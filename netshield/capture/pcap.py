"""PCAP file ingestion.

Uses Scapy's streaming ``PcapReader`` rather than ``rdpcap`` so a large file
does not have to fit in memory. Failure modes are handled explicitly:

* missing file            -> clear error state
* zero-byte file          -> treated as an empty capture (0 packets)
* valid pcap, no records  -> 0 packets, completed
* undecodable file bytes  -> error state, message preserved
* individual bad packets  -> counted as skipped, capture continues
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterator

from netshield.capture.sources import normalize_packet
from netshield.models import CaptureStatus, PacketRecord

try:
    from scapy.utils import PcapReader
except Exception:  # pragma: no cover
    PcapReader = None  # type: ignore[assignment]


class CaptureError(RuntimeError):
    pass


# pcap/pcapng file signatures. Checking these before constructing a Scapy
# reader keeps a malformed file from opening a handle it never gets to close.
_CAPTURE_SIGNATURES = (
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microseconds
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microseconds
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanoseconds
    b"\x0a\x0d\x0d\x0a",  # pcapng
)


class PcapSource:
    def __init__(self, path: str | Path, label: str | None = None):
        self.path = Path(path)
        self.label = label or f"pcap:{self.path.name}"
        self._stop = False
        self._status = CaptureStatus(state="idle", mode="pcap", target=str(self.path))
        self._size = 0

    def start(self) -> None:
        if PcapReader is None:
            raise CaptureError("scapy is not installed; run: pip install -r requirements.txt")
        if not self.path.exists():
            raise CaptureError(f"PCAP file not found: {self.path}")
        if not self.path.is_file():
            raise CaptureError(f"not a file: {self.path}")
        try:
            self._size = self.path.stat().st_size
        except OSError as exc:
            raise CaptureError(f"cannot stat PCAP file: {exc}") from exc

        self._status = CaptureStatus(
            state="reading_pcap",
            mode="pcap",
            target=str(self.path),
            started_at=time.time(),
            message="empty capture file (0 bytes)" if self._size == 0 else "reading PCAP",
        )
        if self._size == 0:
            self._status.state = "completed"
            self._status.finished_at = time.time()
            return

        try:
            with self.path.open("rb") as handle:
                signature = handle.read(4)
        except OSError as exc:
            raise CaptureError(f"cannot read PCAP file: {exc}") from exc
        if signature not in _CAPTURE_SIGNATURES:
            self._fail("not a readable capture file: unrecognised file signature")

    def packets(self) -> Iterator[PacketRecord]:
        if self._size == 0 or self._status.state == "error":
            return

        try:
            reader = PcapReader(str(self.path))
        except Exception as exc:
            self._fail(f"not a readable capture file: {exc}")
            return

        try:
            with reader:
                for pkt in reader:
                    if self._stop:
                        break
                    record = normalize_packet(pkt, self.label)
                    if record is None:
                        self._status.packets_skipped += 1
                        continue
                    yield record
        except Exception as exc:
            self._fail(f"capture ended on a malformed record: {exc}")
            return
        finally:
            if self._status.state == "reading_pcap":
                self._status.state = "completed"
                self._status.finished_at = time.time()

    def stop(self) -> None:
        self._stop = True

    def status(self) -> CaptureStatus:
        return self._status

    def _fail(self, message: str) -> None:
        self._status.state = "error"
        self._status.error = message
        self._status.finished_at = time.time()
