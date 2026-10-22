from __future__ import annotations

import subprocess

import pytest

from netshield import responses
from netshield.config.settings import SafeResponseConfig
from netshield.responses import ResponseError, ResponseRequest, ResponseService
from netshield.storage.db import Database
from netshield.storage.repositories import ResponseRepository

LAB = ("127.0.0.0/8", "10.0.0.0/8")


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "responses.db")
    database.init_schema()
    yield database
    database.close()


def make_settings(settings, *, enabled=True, firewall=False):
    return settings.with_overrides(
        safe_response=SafeResponseConfig(
            enabled=enabled, allow_firewall_changes=firewall, allowed_cidrs=LAB
        )
    )


class FakeRunner:
    def __init__(self, returncode=0, stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


def build(settings, db, *, enabled=True, firewall=False, euid=1, which="/usr/sbin/iptables"):
    runner = FakeRunner()
    service = ResponseService(
        make_settings(settings, enabled=enabled, firewall=firewall),
        ResponseRepository(db),
        euid=lambda: euid,
        runner=runner,
        which=lambda name: which,
    )
    return service, runner


class TestGates:
    def test_disabled_feature(self, settings, db):
        service, _ = build(settings, db, enabled=False)
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="10.0.0.66", action="simulate_block"))
        assert info.value.code == "response_disabled"
        assert info.value.status == 403

    def test_unknown_action(self, settings, db):
        service, _ = build(settings, db)
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="10.0.0.66", action="delete_everything"))
        assert info.value.code == "invalid_parameter"

    def test_invalid_ip(self, settings, db):
        service, _ = build(settings, db)
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="10.0.0.999", action="simulate_block"))
        assert info.value.code == "invalid_parameter"

    def test_target_outside_lab(self, settings, db):
        service, _ = build(settings, db)
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="8.8.8.8", action="simulate_block"))
        assert info.value.code == "target_not_allowed"
        assert info.value.status == 403


class TestSimulated:
    def test_block_and_unblock(self, settings, db):
        service, runner = build(settings, db)
        result = service.apply(
            ResponseRequest(target_ip="10.0.0.66", action="simulate_block", reason="demo")
        )
        assert result["blocked"] is True
        assert result["mode"] == "simulated"
        assert service.blocked_targets() == ["10.0.0.66"]
        assert runner.calls == []

        rows = ResponseRepository(db).list()
        assert rows[0]["applied"] is True
        assert rows[0]["mode"] == "simulated"

        service.apply(ResponseRequest(target_ip="10.0.0.66", action="simulate_unblock"))
        assert service.blocked_targets() == []
        assert len(ResponseRepository(db).list()) == 2

    def test_block_list_is_bounded(self, settings, db, monkeypatch):
        monkeypatch.setattr(responses, "MAX_SIMULATED_BLOCKS", 2)
        service, _ = build(settings, db)
        service.apply(ResponseRequest(target_ip="10.0.0.1", action="simulate_block"))
        service.apply(ResponseRequest(target_ip="10.0.0.2", action="simulate_block"))
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="10.0.0.3", action="simulate_block"))
        assert info.value.code == "response_limit"

    def test_reblocking_an_existing_target_is_allowed(self, settings, db, monkeypatch):
        monkeypatch.setattr(responses, "MAX_SIMULATED_BLOCKS", 1)
        service, _ = build(settings, db)
        service.apply(ResponseRequest(target_ip="10.0.0.1", action="simulate_block"))
        service.apply(ResponseRequest(target_ip="10.0.0.1", action="simulate_block"))
        assert service.blocked_targets() == ["10.0.0.1"]


class TestFirewall:
    def test_requires_the_explicit_flag(self, settings, db):
        service, runner = build(settings, db, firewall=False)
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="10.0.0.66", action="firewall_block"))
        assert info.value.code == "firewall_disabled"
        assert runner.calls == []

    def test_requires_root(self, settings, db):
        service, runner = build(settings, db, firewall=True, euid=1000)
        with pytest.raises(ResponseError) as info:
            service.apply(ResponseRequest(target_ip="10.0.0.66", action="firewall_block"))
        assert info.value.code == "firewall_requires_root"
        assert runner.calls == []

    def test_requires_a_matching_confirmation_token(self, settings, db):
        service, runner = build(settings, db, firewall=True, euid=0)
        with pytest.raises(ResponseError) as info:
            service.apply(
                ResponseRequest(
                    target_ip="10.0.0.66",
                    action="firewall_block",
                    confirm_token="yes please",
                )
            )
        assert info.value.code == "confirm_required"
        assert info.value.status == 400
        assert runner.calls == []

    def test_block_inserts_one_input_rule(self, settings, db):
        service, runner = build(settings, db, firewall=True, euid=0)
        result = service.apply(
            ResponseRequest(
                target_ip="10.0.0.66",
                action="firewall_block",
                confirm_token="BLOCK 10.0.0.66",
            )
        )
        assert result["applied"] is True
        assert result["mode"] == "firewall"

        argv, kwargs = runner.calls[0]
        assert argv == [
            "/usr/sbin/iptables",
            "-I",
            "INPUT",
            "-s",
            "10.0.0.66",
            "-j",
            "DROP",
        ]
        assert kwargs["check"] is False
        assert kwargs["timeout"] == 10

    def test_unblock_deletes_the_rule(self, settings, db):
        service, runner = build(settings, db, firewall=True, euid=0)
        service.apply(
            ResponseRequest(
                target_ip="10.0.0.66",
                action="firewall_unblock",
                confirm_token="UNBLOCK 10.0.0.66",
            )
        )
        assert runner.calls[0][0][1] == "-D"

    def test_iptables_failure_is_reported(self, settings, db):
        runner = FakeRunner(returncode=1, stderr="Permission denied")
        service = ResponseService(
            make_settings(settings, firewall=True),
            ResponseRepository(db),
            euid=lambda: 0,
            runner=runner,
            which=lambda name: "/usr/sbin/iptables",
        )
        with pytest.raises(ResponseError) as info:
            service.apply(
                ResponseRequest(
                    target_ip="10.0.0.66",
                    action="firewall_block",
                    confirm_token="BLOCK 10.0.0.66",
                )
            )
        assert info.value.code == "firewall_failed"
        assert info.value.status == 502
        assert ResponseRepository(db).list() == []

    def test_missing_iptables_is_reported(self, settings, db):
        service, _ = build(settings, db, firewall=True, euid=0, which=None)
        with pytest.raises(ResponseError) as info:
            service.apply(
                ResponseRequest(
                    target_ip="10.0.0.66",
                    action="firewall_block",
                    confirm_token="BLOCK 10.0.0.66",
                )
            )
        assert info.value.code == "firewall_unavailable"

    def test_ipv6_lab_target_is_handled(self, settings, db):
        service, runner = build(settings, db, firewall=True, euid=0)
        service.apply(
            ResponseRequest(
                target_ip="127.0.0.1",
                action="firewall_block",
                confirm_token="BLOCK 127.0.0.1",
            )
        )
        assert runner.calls[0][0][4] == "127.0.0.1"
