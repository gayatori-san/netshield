from __future__ import annotations

from netshield.config.settings import DedupConfig, ScoringConfig
from netshield.models import AlertCandidate
from netshield.scoring.scorer import AlertScorer
from netshield.scoring.severity import apply_evidence_gate, severity_for


def make_scorer() -> AlertScorer:
    return AlertScorer(ScoringConfig(), DedupConfig())


def candidate(**facts):
    base_facts = {
        "metric": "distinct destination ports",
        "observed": 60,
        "required": 15,
        "window_seconds": 60,
        "evidence_sufficient": True,
        "volume_scale": True,
    }
    base_facts.update(facts)
    return AlertCandidate(
        rule_id="PORT_SCAN_PORTS",
        src_ip="203.0.113.50",
        dst_ip="10.0.0.10",
        window_start=100.0,
        window_end=160.0,
        evidence={"distinct_destination_ports": base_facts["observed"]},
        facts=base_facts,
    )


class TestSeverityBands:
    def test_band_boundaries(self):
        cfg = ScoringConfig(low_max=34, medium_max=67)
        assert severity_for(0, cfg) == "low"
        assert severity_for(33, cfg) == "low"
        assert severity_for(34, cfg) == "medium"
        assert severity_for(66, cfg) == "medium"
        assert severity_for(67, cfg) == "high"
        assert severity_for(100, cfg) == "high"

    def test_evidence_gate_caps_high_at_medium(self):
        assert apply_evidence_gate("high", False) == "medium"
        assert apply_evidence_gate("medium", False) == "medium"
        assert apply_evidence_gate("low", False) == "low"
        assert apply_evidence_gate("high", True) == "high"


class TestScoringMath:
    def test_port_scan_scores_high(self):
        alert = make_scorer().score(candidate(), now=160.0)
        assert alert.score == 70
        assert alert.severity == "high"
        assert alert.facts["base"] == 40
        assert alert.facts["volume_bonus"] == 30

    def test_volume_bonus_is_capped(self):
        alert = make_scorer().score(candidate(observed=100000, required=15), now=160.0)
        assert alert.facts["volume_bonus"] == 30
        assert alert.score == 70

    def test_score_is_clamped_to_100(self):
        alert = make_scorer().score(candidate(), now=160.0, recurrence_count=50)
        assert alert.score <= 100

    def test_frequency_bonus_from_recurrence(self):
        alert = make_scorer().score(candidate(), now=160.0, recurrence_count=3)
        assert alert.facts["frequency_bonus"] == 10
        assert alert.score == 80

    def test_evidence_gate_downgrades_high_to_medium(self):
        alert = make_scorer().score(candidate(evidence_sufficient=False), now=160.0)
        assert alert.score >= 67
        assert alert.severity == "medium"
        assert any("insufficient" in r.lower() for r in alert.reasons)

    def test_low_severity_single_sensitive_port(self):
        cand = AlertCandidate(
            rule_id="SENSITIVE_PORT",
            src_ip="10.0.0.40",
            dst_ip=None,
            window_start=100.0,
            window_end=160.0,
            evidence={"destination_port": 22},
            facts={
                "metric": "connection attempts to a sensitive port",
                "observed": 1,
                "required": 1,
                "volume_observed": 1,
                "volume_required": 5,
                "window_seconds": 60,
                "evidence_sufficient": False,
                "volume_scale": True,
            },
        )
        alert = make_scorer().score(cand, now=160.0)
        assert alert.severity == "low"
        assert alert.score == 31

    def test_reasons_are_generated_from_facts(self):
        alert = make_scorer().score(candidate(), now=160.0)
        joined = " ".join(alert.reasons)
        assert "60" in joined and "15" in joined
        assert "60s" in joined
        assert any("+30" in r for r in alert.reasons)

    def test_fingerprint_is_stable(self):
        scorer = make_scorer()
        a = scorer.score(candidate(), now=160.0)
        b = scorer.score(candidate(), now=161.0)
        assert a.fingerprint == b.fingerprint

    def test_data_origin_is_preserved(self):
        alert = make_scorer().score(candidate(), now=160.0, data_origin="demonstration")
        assert alert.data_origin == "demonstration"

    def test_no_confidence_percentage_is_invented(self):
        alert = make_scorer().score(candidate(), now=160.0)
        for value in alert.reasons:
            assert "%" not in value

    def test_duplicate_suppression_via_scorer(self):
        scorer = make_scorer()
        first = scorer.score(candidate(), now=160.0)
        second = scorer.score(candidate(), now=161.0)
        assert scorer.should_emit(first, now=160.0) is True
        assert scorer.should_emit(second, now=161.0) is False

    def test_title_comes_from_rule_catalogue(self):
        alert = make_scorer().score(candidate(), now=160.0)
        assert alert.title.startswith("Possible port scan")
