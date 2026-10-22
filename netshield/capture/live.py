"""Live capture from a network interface.

Live capture is the only part of NetShield that needs elevated privilege,
because reading raw frames requires ``CAP_NET_RAW``. The source fails with an
actionable message instead of a traceback, and it never attempts to escalate
privileges by itself.
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from typing import Iterator

from netshield.capture.sources import normalize_packet
from netshield.models import CaptureStatus, PacketRecord

try:  # pragma: no cover - scapy is a hard dependency at runtime
    from scapy.sendrecv import AsyncSniffer
except Exception:  # pragma: no cover
    AsyncSniffer = None  # type: ignore[assignment]


PERMISSION_HELP = (
    "live capture needs raw-socket permission. Grant it once with: "
    "sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python) "
    "or run NetShield with sudo."
)


class LiveSource:
    def __init__(self, iface: str | None = None, bpf_filter: str = "ip", queue_size: int = 5000):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.queue_size = queue_size
        self.label = f"live:{iface or 'default'}"
        self._stop = False
        self._lock = threading.Lock()
        self._sniffer = None
        self._queue: queue.Queue | None = None
        self._status = CaptureStatus(state="idle", mode="live", target=self.label)

    def start(self) -> None:
        if AsyncSniffer is None:
            raise RuntimeError("scapy is not installed; run: pip install -r requirements.txt")

        if self.iface:
            try:
                socket.if_nametoindex(self.iface)
            except OSError as exc:
                raise ValueError(f"network interface not found: {self.iface}") from exc

        if hasattr(socket, "AF_PACKET"):
            try:
                probe = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            except PermissionError as exc:
                raise PermissionError(PERMISSION_HELP) from exc
            except OSError as exc:
                raise RuntimeError(f"raw packet socket unavailable: {exc}") from exc
            else:
                probe.close()

        self._status = CaptureStatus(
            state="capturing",
            mode="live",
            target=self.label,
            started_at=time.time(),
            message="live capture running",
        )

    def packets(self) -> Iterator[PacketRecord]:
        if self._stop:
            return

        self._queue = queue.Queue(maxsize=self.queue_size)

        def handle(pkt) -> None:
            try:
                self._queue.put_nowait(pkt)
            except queue.Full:
                with self._lock:
                    self._status.packets_skipped += 1

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            store=False,
            prn=handle,
        )
        try:
            self._sniffer.start()
        except Exception as exc:
            self._fail(f"could not start live capture: {exc}")
            return

        try:
            while not self._stop:
                try:
                    raw = self._queue.get(timeout=0.25)
                except queue.Empty:
                    continue
                record = normalize_packet(raw, self.label)
                if record is None:
                    with self._lock:
                        self._status.packets_skipped += 1
                    continue
                yield record
        except Exception as exc:  # pragma: no cover - defensive
            self._fail(f"live capture stopped: {exc}")
            return
        finally:
            try:
                self._sniffer.stop()
            except Exception:  # pragma: no cover
                pass
            with self._lock:
                if self._status.state == "capturing":
                    self._status.state = "completed"
                    self._status.finished_at = time.time()

    def stop(self) -> None:
        self._stop = True

    def status(self) -> CaptureStatus:
        with self._lock:
            return self._status

    def _fail(self, message: str) -> None:
        with self._lock:
            if not self._stop:
                self._status.state = "error"
                self._status.error = message
            self._status.finished_at = time.time()
