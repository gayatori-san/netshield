"""The capture pipeline.

Threads:
* producer — reads from a packet source and pushes records onto a bounded queue
* worker   — owns every detector, scores candidates, persists alerts/packets

The queue is the only hand-off point. Back-pressure is deliberate: if the
worker falls behind, the producer blocks instead of growing memory without
bound, because a flood must not be able to exhaust the monitor's RAM.
"""

from __future__ import annotations

import queue
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from netshield.capture.live import LiveSource
from netshield.capture.pcap import PcapSource
from netshield.capture.synthetic import SyntheticSource
from netshield.config.settings import Settings
from netshield.detectors.port_scan import PortScanDetector
from netshield.detectors.spike import TrafficSpikeDetector
from netshield.detectors.suspicious import SuspiciousConnectionDetector
from netshield.features.aggregation import TrafficAggregator
from netshield.models import CaptureStatus, PacketRecord
from netshield.scoring.scorer import RECURRENCE_WINDOW_SECONDS, AlertScorer
from netshield.storage.db import Database
from netshield.storage.repositories import (
    IncidentRepository,
    PacketRepository,
    TrafficRepository,
)

MAX_PACKETS_PER_RUN = 200_000
FINAL_FLUSH_MARGIN = 1.0


class PipelineBusy(RuntimeError):
    """Raised when a capture is already running."""


class PipelineError(RuntimeError):
    """Raised for configuration problems that prevent a capture from starting."""


class ProcessingPipeline:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        *,
        clock: Callable[[], float] = time.time,
        demo_pace: bool = True,
    ):
        self.settings = settings
        self.db = db
        self.clock = clock
        self._demo_pace = demo_pace
        self.incidents = IncidentRepository(db)
        self.packets = PacketRepository(db)
        self.traffic = TrafficRepository(db)

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._source: Any = None
        self._producer: threading.Thread | None = None
        self._worker: threading.Thread | None = None
        self._queue: queue.Queue | None = None
        self._origin = "real"
        self._status = CaptureStatus()
        self._buffer: list[PacketRecord] = []
        self._recurrence: dict[str, deque[float]] = {}
        self._last_ts = 0.0
        self._last_prune = 0.0
        self._packets_capped = False

        db.init_schema()
        self._reset_runtime()

    # ------------------------------------------------------------------ state
    def _reset_runtime(self) -> None:
        self._aggregator = TrafficAggregator(
            baseline_alpha=self.settings.spike.baseline_alpha,
            rate_window_seconds=max(60, self.settings.spike.baseline_window_seconds),
        )
        self._detectors = [
            PortScanDetector(self.settings.port_scan),
            SuspiciousConnectionDetector(self.settings.suspicious),
            TrafficSpikeDetector(self.settings.spike),
        ]
        self._scorer = AlertScorer(self.settings.scoring, self.settings.dedup)
        self._buffer = []
        self._recurrence.clear()
        self._last_ts = 0.0
        self._packets_capped = False
        self._last_prune = self.clock()

    def _running(self) -> bool:
        return any(
            thread is not None and thread.is_alive()
            for thread in (self._producer, self._worker)
        )

    @property
    def running(self) -> bool:
        return self._running()

    def status(self) -> dict:
        with self._lock:
            return {**self._status.to_dict(), "running": self._running()}

    def snapshot(self) -> dict:
        with self._lock:
            now = self._last_ts or self.clock()
            snap = self._aggregator.snapshot(now)
        return {
            "now": snap.now,
            "total_packets": snap.total_packets,
            "total_bytes": snap.total_bytes,
            "current_pps": snap.current_pps,
            "baseline_pps": snap.baseline_pps,
            "window_packets": snap.window_packets,
            "active_flows": snap.active_flows,
            "protocol_counts": snap.protocol_counts,
            "top_sources": [[ip, count] for ip, count in snap.top_sources],
            "top_destinations": [[ip, count] for ip, count in snap.top_destinations],
        }

    def configure(self, settings: Settings) -> bool:
        """Replace thresholds. Returns True if they take effect immediately."""
        with self._lock:
            self.settings = settings
            if self._running():
                return False
            self._reset_runtime()
            return True

    # ------------------------------------------------------------------ start
    def start(self, mode: str, *, path: str | None = None, iface: str | None = None) -> dict:
        with self._lock:
            if self._running():
                raise PipelineBusy("a capture is already running; stop it first")

            source, origin, target = self._build_source(mode, path, iface)
            self._reset_runtime()
            self._stop.clear()
            try:
                source.start()
            except (ValueError, PermissionError, RuntimeError) as exc:
                raise PipelineError(str(exc)) from exc

            self._source = source
            self._origin = origin
            self._queue = queue.Queue(maxsize=self.settings.capture.queue_maxsize)
            self._status = CaptureStatus(
                state="running",
                mode=mode,
                target=target,
                started_at=self.clock(),
                message="capture running",
            )
            self._producer = threading.Thread(
                target=self._produce, name="netshield-producer", daemon=True
            )
            self._worker = threading.Thread(
                target=self._consume, name="netshield-worker", daemon=True
            )
            self._producer.start()
            self._worker.start()
            return {**self._status.to_dict(), "running": True}

    def _build_source(self, mode: str, path: str | None, iface: str | None):
        if mode == "pcap":
            if not path:
                raise PipelineError("a PCAP file path is required for pcap mode")
            resolved = Path(path).expanduser()
            if not resolved.exists():
                raise PipelineError(f"PCAP file not found: {resolved}")
            if not resolved.is_file():
                raise PipelineError(f"not a file: {resolved}")
            return PcapSource(resolved), "real", str(resolved)
        if mode == "live":
            if not iface:
                raise PipelineError("a network interface is required for live mode")
            return LiveSource(iface), "real", iface
        if mode == "demo":
            return (
                SyntheticSource(duration=self.settings.demo_duration, pace=self._demo_pace),
                "demonstration",
                "labelled synthetic demonstration",
            )
        raise PipelineError(f"unknown capture mode: {mode!r}")

    # --------------------------------------------------------------- producer
    def _produce(self) -> None:
        assert self._queue is not None
        try:
            for record in self._source.packets():
                if self._stop.is_set():
                    break
                while not self._stop.is_set():
                    try:
                        self._queue.put(record, timeout=0.5)
                        break
                    except queue.Full:
                        continue
        except Exception as exc:  # pragma: no cover - source-specific failures
            with self._lock:
                self._status.error = str(exc)
        finally:
            while True:
                try:
                    self._queue.put(None, timeout=0.5)
                    break
                except queue.Full:
                    if self._stop.is_set() and self._worker is not None and not self._worker.is_alive():
                        break

    # ----------------------------------------------------------------- worker
    def _consume(self) -> None:
        try:
            self._consume_impl()
        finally:
            self.db.close_thread()

    def _consume_impl(self) -> None:
        assert self._queue is not None
        interval = max(0.1, float(self.settings.capture.flush_interval_seconds))
        next_logical = None
        last_wall_flush = time.monotonic()
        try:
            while True:
                try:
                    item = self._queue.get(timeout=0.25)
                except queue.Empty:
                    if self._stop.is_set() and not (
                        self._producer is not None and self._producer.is_alive()
                    ):
                        break
                    if time.monotonic() - last_wall_flush >= interval:
                        self._flush(self._flush_now())
                        last_wall_flush = time.monotonic()
                    continue

                if item is None:
                    break

                self._observe(item)
                if next_logical is None:
                    next_logical = item.timestamp + interval
                elif item.timestamp >= next_logical:
                    self._flush(item.timestamp)
                    next_logical = item.timestamp + interval
                    last_wall_flush = time.monotonic()

            self._flush(self._finish_now())
        except Exception as exc:  # pragma: no cover - defensive
            with self._lock:
                self._status.state = "error"
                self._status.error = f"pipeline failed: {exc}"
                self._status.finished_at = self.clock()
            return

        source_status = self._source.status() if self._source is not None else None
        with self._lock:
            if source_status is not None:
                self._status.packets_skipped = source_status.packets_skipped
                if source_status.error and not self._status.error:
                    self._status.error = source_status.error
            if self._status.error:
                self._status.state = "error"
                self._status.message = self._status.error
            elif self._stop.is_set():
                self._status.state = "stopped"
                self._status.message = f"capture stopped ({self._status.packets_processed} packets)"
            else:
                self._status.state = "completed"
                self._status.message = f"capture finished ({self._status.packets_processed} packets)"
            self._status.finished_at = self.clock()

    def _observe(self, record: PacketRecord) -> None:
        with self._lock:
            self._aggregator.observe(record)
            if len(self._buffer) < MAX_PACKETS_PER_RUN:
                self._buffer.append(record)
            elif not self._packets_capped:
                self._packets_capped = True
                self._status.message = (
                    f"packet storage capped at {MAX_PACKETS_PER_RUN} rows for this run"
                )
            self._last_ts = max(self._last_ts, record.timestamp)
            self._status.packets_processed += 1

        for detector in self._detectors:
            detector.update(record)

    def _flush_now(self) -> float:
        # Replayed timelines (pcap and the paced demo) must be judged against
        # their own clock, not the wall clock, or windows used for pruning
        # would sit years away from the traffic being analysed.
        if self._status.mode in ("pcap", "demo"):
            return self._last_ts or self.clock()
        return self.clock()

    def _finish_now(self) -> float:
        if self._status.mode in ("pcap", "demo"):
            return (self._last_ts or self.clock()) + FINAL_FLUSH_MARGIN
        return self.clock()

    def _flush(self, now: float) -> None:
        candidates = []
        for detector in self._detectors:
            candidates.extend(detector.flush(now))

        for candidate in candidates:
            recurrence = self._recurrence_position(candidate.src_ip, now)
            alert = self._scorer.score(
                candidate,
                now,
                recurrence_count=recurrence,
                data_origin=self._origin,
            )
            if not self._scorer.should_emit(alert, now):
                continue
            if not self.incidents.insert(alert):
                continue
            self._record_recurrence(candidate.src_ip, now)
            with self._lock:
                self._status.alerts_raised += 1

        with self._lock:
            buckets = self._aggregator.drain_buckets()
            buffered = self._buffer
            self._buffer = []
        if buckets:
            self.traffic.upsert(
                (bucket["bucket_ts"], bucket["packets"], bucket["bytes"]) for bucket in buckets
            )
        if buffered:
            self.packets.add_many(buffered, self._origin, now=self.clock())

        if self.clock() - self._last_prune >= self.settings.retention.prune_interval_seconds:
            self.packets.prune(self.settings.retention.packet_days, now=self.clock())
            self._last_prune = self.clock()

    def _recurrence_position(self, src_ip: str | None, now: float) -> int:
        if not src_ip:
            return 1
        history = self._recurrence.setdefault(src_ip, deque())
        cutoff = now - RECURRENCE_WINDOW_SECONDS
        while history and history[0] < cutoff:
            history.popleft()
        return len(history) + 1

    def _record_recurrence(self, src_ip: str | None, now: float) -> None:
        if not src_ip:
            return
        self._recurrence.setdefault(src_ip, deque()).append(now)

    # ------------------------------------------------------------------- stop
    def stop(self) -> dict:
        with self._lock:
            if not self._running():
                if self._status.state in ("running", "stopping"):
                    self._status.state = "stopped"
                    self._status.finished_at = self.clock()
                return {**self._status.to_dict(), "running": False}
            self._status.state = "stopping"
            source = self._source
            self._stop.set()

        if source is not None:
            source.stop()

        for thread in (self._producer, self._worker):
            if thread is not None and thread.is_alive():
                thread.join(timeout=10)

        with self._lock:
            if self._status.state == "stopping":
                self._status.state = "stopped"
                self._status.finished_at = self.clock()
                self._status.message = (
                    f"capture stopped ({self._status.packets_processed} packets)"
                )
            return {**self._status.to_dict(), "running": self._running()}
