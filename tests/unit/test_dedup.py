from __future__ import annotations

from netshield.detectors.dedup import AlertDeduplicator


class TestFingerprints:
    def test_same_observation_has_stable_fingerprint(self):
        dedup = AlertDeduplicator(300)
        a = dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.1", "10.0.0.2", 100.0)
        b = dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.1", "10.0.0.2", 200.0)
        assert a == b

    def test_different_bucket_changes_fingerprint(self):
        dedup = AlertDeduplicator(300)
        a = dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.1", "10.0.0.2", 100.0)
        b = dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.1", "10.0.0.2", 400.0)
        assert a != b

    def test_different_rule_or_address_changes_fingerprint(self):
        dedup = AlertDeduplicator(300)
        base = dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.1", "10.0.0.2", 100.0)
        assert base != dedup.fingerprint("PORT_SCAN_HOSTS", "10.0.0.1", "10.0.0.2", 100.0)
        assert base != dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.9", "10.0.0.2", 100.0)
        assert base != dedup.fingerprint("PORT_SCAN_PORTS", "10.0.0.1", None, 100.0)

    def test_fingerprint_is_hex_and_bounded(self):
        dedup = AlertDeduplicator(300)
        fp = dedup.fingerprint("X", None, None, 0.0)
        assert len(fp) == 32
        int(fp, 16)


class TestSuppression:
    def test_duplicate_is_suppressed_within_window(self):
        dedup = AlertDeduplicator(300)
        fp = dedup.fingerprint("R", "a", "b", 100.0)
        assert dedup.should_emit(fp, 100.0) is True
        assert dedup.should_emit(fp, 200.0) is False
        assert dedup.should_emit(fp, 399.0) is False
        assert dedup.should_emit(fp, 401.0) is True

    def test_distinct_fingerprints_both_emit(self):
        dedup = AlertDeduplicator(300)
        assert dedup.should_emit("a" * 32, 1.0) is True
        assert dedup.should_emit("b" * 32, 1.0) is True

    def test_reset_allows_reemission(self):
        dedup = AlertDeduplicator(300)
        assert dedup.should_emit("c" * 32, 1.0) is True
        dedup.reset()
        assert dedup.should_emit("c" * 32, 1.0) is True

    def test_old_state_is_pruned(self):
        dedup = AlertDeduplicator(10)
        dedup.should_emit("d" * 32, 0.0)
        dedup.should_emit("e" * 32, 100.0)
        assert len(dedup._seen) <= 1

    def test_invalid_window_rejected(self):
        try:
            AlertDeduplicator(0)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")
