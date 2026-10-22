from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netshield.config.settings import load_settings
from netshield.models import PacketRecord


@pytest.fixture(scope="session")
def settings():
    return load_settings(ROOT / "config" / "thresholds.toml", env_path=ROOT / ".env.nonexistent")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return ROOT / "tests" / "fixtures"


@pytest.fixture
def packet_factory():
    def make(
        src="10.0.0.1",
        dst="10.0.0.2",
        sport=40000,
        dport=80,
        proto="TCP",
        state="SYN",
        flags="S",
        ts=0.0,
        size=60,
        source="test",
    ) -> PacketRecord:
        return PacketRecord(
            timestamp=ts,
            src_ip=src,
            dst_ip=dst,
            src_port=sport,
            dst_port=dport,
            protocol=proto,
            flags=flags,
            tcp_state=state,
            size=size,
            source=source,
        )

    return make


@pytest.fixture
def stub_auth():
    from tests.auth_support import StubAuthBackend

    return StubAuthBackend()


@pytest.fixture
def auth_client(stub_auth):
    def make(app, token="admin-token", use_session_cookie=False):
        client = app.test_client()
        if use_session_cookie:
            client.set_cookie("netshield_session", f"session:{token}")
        else:
            client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return client

    return make


@pytest.fixture
def replay(fixtures_dir):
    """Run one or more detectors over a fixture PCAP and return candidates."""
    from netshield.capture.pcap import PcapSource

    def run(name, detectors, final_offset=1.0):
        source = PcapSource(fixtures_dir / name)
        source.start()
        last_ts = 0.0
        for pkt in source.packets():
            last_ts = pkt.timestamp
            for detector in detectors:
                detector.update(pkt)
        now = last_ts + final_offset
        candidates = []
        for detector in detectors:
            candidates.extend(detector.flush(now))
        return candidates

    return run
