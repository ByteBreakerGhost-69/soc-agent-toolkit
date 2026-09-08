"""Tests for triage.py — covers item #9 from the review (windowed + fuzzy dedup)."""

from soc_agent_toolkit import triage


def _alert(id_, sig, ts, src="1.2.3.4", dst="5.6.7.8", severity=5):
    return {"id": id_, "signature": sig, "timestamp": ts, "src_ip": src, "dst_ip": dst,
            "dest_ip": dst, "severity": severity, "message": sig}


class TestDedupAlerts:
    def test_exact_duplicates_within_window_are_merged(self):
        alerts = [
            _alert("a1", "SSH Brute Force", "2026-01-01T10:00:00"),
            _alert("a2", "SSH Brute Force", "2026-01-01T10:05:00"),
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60)
        assert len(result) == 1
        assert result[0]["occurrence_count"] == 2

    def test_same_fingerprint_outside_window_is_not_merged(self):
        alerts = [
            _alert("a1", "SSH Brute Force", "2026-01-01T10:00:00"),
            _alert("a2", "SSH Brute Force", "2026-02-15T10:00:00"),  # weeks later
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60)
        assert len(result) == 2
        assert all(a["occurrence_count"] == 1 for a in result)

    def test_fuzzy_signature_match_within_window_merges(self):
        alerts = [
            _alert("a1", "SSH Brute Force Attempt", "2026-01-01T10:00:00"),
            _alert("a2", "SSH Brute-Force Attempt", "2026-01-01T10:02:00"),
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60, fuzzy_threshold=0.85)
        assert len(result) == 1
        assert result[0]["occurrence_count"] == 2

    def test_dissimilar_signatures_not_merged_even_in_window(self):
        alerts = [
            _alert("a1", "SSH Brute Force", "2026-01-01T10:00:00"),
            _alert("a2", "Port Scan Detected", "2026-01-01T10:01:00"),
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60)
        assert len(result) == 2

    def test_both_missing_timestamps_are_merged(self):
        # Common case: SIEM export with no timestamp field at all -> treat as same batch.
        alerts = [
            _alert("a1", "SSH Brute Force", None),
            _alert("a2", "SSH Brute Force", None),
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60)
        assert len(result) == 1
        assert result[0]["occurrence_count"] == 2

    def test_one_missing_one_present_timestamp_not_merged(self):
        # Ambiguous case: be conservative and keep them separate.
        alerts = [
            _alert("a1", "SSH Brute Force", None),
            _alert("a2", "SSH Brute Force", "2026-01-01T10:00:00"),
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60)
        assert len(result) == 2

    def test_different_src_dst_not_merged(self):
        alerts = [
            _alert("a1", "SSH Brute Force", "2026-01-01T10:00:00", src="1.1.1.1"),
            _alert("a2", "SSH Brute Force", "2026-01-01T10:01:00", src="2.2.2.2"),
        ]
        result = triage.dedup_alerts(alerts, time_window_minutes=60)
        assert len(result) == 2


class TestScoreAlert:
    def test_base_severity_scaling(self):
        alert = {"severity": 10, "occurrence_count": 1, "enrichment": {}, "mitre": []}
        assert triage.score_alert(alert) == 60  # 10 * SEVERITY_WEIGHT(6)

    def test_asset_criticality_adds_weight(self):
        alert = {"severity": 5, "occurrence_count": 1, "enrichment": {}, "mitre": [], "src_ip": "10.0.0.5"}
        base = triage.score_alert(alert)
        boosted = triage.score_alert(alert, asset_criticality={"10.0.0.5": 15})
        assert boosted == base + 15

    def test_score_capped_at_100(self):
        alert = {
            "severity": 10, "occurrence_count": 20,
            "enrichment": {"src_ip": {"verdict": "malicious"}, "dest_ip": {"verdict": "malicious"}},
            "mitre": [{"technique_id": "T1110"}], "src_ip": "1.1.1.1",
        }
        assert triage.score_alert(alert, asset_criticality={"1.1.1.1": 50}) == 100


def test_score_alert_counts_nested_threat_intelligence():
    from soc_agent_toolkit import triage

    base = {
        "severity": 5,
        "occurrence_count": 1,
        "mitre": [],
        "src_ip": None,
        "dest_ip": None,
        "enrichment": {},
    }

    clean_score = triage.score_alert(base)

    malicious_ti = dict(base)
    malicious_ti["enrichment"] = {
        "domains": {
            "evil-example.com": {
                "ioc": "evil-example.com",
                "verdict": "malicious",
            }
        },
        "hashes": {
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
                "ioc": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "verdict": "malicious",
            }
        },
    }

    malicious_score = triage.score_alert(malicious_ti)

    assert malicious_score > clean_score
    expected_score = (
        clean_score
        + (4 * triage.config.ENRICHMENT_BOOST_MULTIPLIER * 2)
        + triage.CONFIDENCE_BONUS["strong"]
    )

    assert malicious_score == expected_score

def test_enrichment_confidence_strong_consensus():
    from soc_agent_toolkit import triage

    enrichment = {
        "src_ip": {
            "verdict": "malicious",
            "score": 90,
            "abuseipdb": {"abuse_confidence_score": 95},
        },
        "domains": {
            "evil-example.com": {
                "verdict": "malicious",
                "score": 80,
                "virustotal": {"malicious": 4},
            }
        },
        "hashes": {
            "abc": {
                "verdict": "suspicious",
                "score": 25,
                "virustotal": {"stats": {"malicious": 1}},
            }
        },
    }

    result = triage.enrichment_confidence(enrichment)

    assert result["provider_count"] == 3
    assert result["malicious_count"] == 2
    assert result["suspicious_count"] == 1
    assert result["consensus"] == "strong"
    assert 0 <= result["confidence"] <= 1


def test_enrichment_confidence_unknown_when_no_results():
    from soc_agent_toolkit import triage

    result = triage.enrichment_confidence({})

    assert result["provider_count"] == 0
    assert result["malicious_count"] == 0
    assert result["suspicious_count"] == 0
    assert result["consensus"] == "unknown"
    assert result["confidence"] == 0.0

def test_score_alert_uses_enrichment_confidence_bonus():
    from soc_agent_toolkit import triage

    alert = {
        "severity": 5,
        "enrichment": {
            "src_ip": {
                "verdict": "malicious",
                "score": 90,
            },
            "domains": {
                "evil-example.com": {
                    "verdict": "malicious",
                    "score": 80,
                },
            },
        },
    }

    verdict_only_score = (
        5 * triage.config.SEVERITY_WEIGHT
        + (4 * triage.config.ENRICHMENT_BOOST_MULTIPLIER * 2)
    )

    score = triage.score_alert(alert)

    assert score > verdict_only_score
