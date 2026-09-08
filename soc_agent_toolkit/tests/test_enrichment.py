
from soc_agent_toolkit.enrichment import extract_iocs


def test_extract_iocs_finds_domain_and_hash():
    text = (
        "Connection to evil-example.com detected. "
        "SHA256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )

    result = extract_iocs(text)

    assert "evil-example.com" in result["domains"]
    assert (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        in result["hashes"]
    )


def test_extract_iocs_ignores_private_ip_as_external_ioc():
    text = "src=192.168.1.10 contacting example.com"

    result = extract_iocs(text)

    assert result["ips"] == ["192.168.1.10"]
    assert result["domains"] == ["example.com"]


def test_enrich_alert_orchestrates_ip_domain_and_hash(monkeypatch):
    from soc_agent_toolkit import enrichment

    calls = []

    def fake_ip(value):
        calls.append(("ip", value))
        return {"ioc": value, "verdict": "clean"}

    def fake_domain(value):
        calls.append(("domain", value))
        return {"ioc": value, "verdict": "suspicious"}

    def fake_hash(value):
        calls.append(("hash", value))
        return {"ioc": value, "verdict": "malicious"}

    monkeypatch.setattr(enrichment, "enrich_ip", fake_ip)
    monkeypatch.setattr(enrichment, "enrich_domain", fake_domain)
    monkeypatch.setattr(enrichment, "enrich_hash", fake_hash)

    file_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

    alert = {
        "message": (
            "src=203.0.113.10 connected to evil-example.com "
            f"and dropped SHA256 {file_hash}"
        ),
        "raw": "",
        "src_ip": "203.0.113.10",
        "dest_ip": None,
    }

    result = enrichment.enrich_alert(alert)

    assert "src_ip" in result["enrichment"]
    assert "domains" in result["enrichment"]
    assert "evil-example.com" in result["enrichment"]["domains"]
    assert "hashes" in result["enrichment"]
    assert file_hash in result["enrichment"]["hashes"]
    assert ("ip", "203.0.113.10") in calls
    assert ("domain", "evil-example.com") in calls
    assert ("hash", file_hash) in calls
    assert "ioc_extraction" in result

def test_enrichment_to_triage_produces_confidence_and_priority(monkeypatch):
    from soc_agent_toolkit import enrichment, triage

    file_hash = (
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )

    def fake_ip(value):
        return {
            "ioc": value,
            "type": "ip",
            "providers_used": ["abuseipdb", "virustotal"],
            "verdict": "malicious",
            "score": 90,
        }

    def fake_domain(value):
        return {
            "ioc": value,
            "type": "domain",
            "providers_used": ["virustotal", "otx"],
            "verdict": "malicious",
            "score": 85,
        }

    def fake_hash(value):
        return {
            "ioc": value,
            "type": "hash:sha256",
            "providers_used": ["virustotal"],
            "verdict": "malicious",
            "score": 95,
        }

    monkeypatch.setattr(enrichment, "enrich_ip", fake_ip)
    monkeypatch.setattr(enrichment, "enrich_domain", fake_domain)
    monkeypatch.setattr(enrichment, "enrich_hash", fake_hash)

    alert = {
        "id": "alert-001",
        "timestamp": "2025-01-01T10:00:00Z",
        "source": "test-siem",
        "signature": "Malicious Activity Detected",
        "severity": 8,
        "src_ip": "203.0.113.10",
        "dest_ip": None,
        "message": (
            "Connection to evil-example.com "
            f"with SHA256 {file_hash}"
        ),
        "raw": "",
    }

    enriched = enrichment.enrich_alert(alert)

    result = triage.triage_alerts(
        [enriched],
        dedup=False,
    )[0]

    assert result["enrichment_confidence"]["provider_count"] == 3
    assert result["enrichment_confidence"]["malicious_count"] == 3
    assert result["enrichment_confidence"]["suspicious_count"] == 0
    assert result["enrichment_confidence"]["consensus"] == "strong"
    assert result["enrichment_confidence"]["confidence"] == 1.0

    assert result["priority_score"] > 8 * triage.config.SEVERITY_WEIGHT
    assert result["priority_tier"] in {"P1", "P2", "P3"}

def test_enrichment_preserves_provider_provenance(monkeypatch):
    from soc_agent_toolkit import enrichment

    def fake_ip(value):
        return {
            "ioc": value,
            "type": "ip",
            "providers_used": ["abuseipdb", "virustotal"],
            "verdict": "malicious",
            "score": 90,
            "abuseipdb": {
                "abuse_confidence_score": 95,
                "total_reports": 12,
            },
            "virustotal": {
                "malicious": 8,
                "suspicious": 1,
            },
        }

    monkeypatch.setattr(enrichment, "enrich_ip", fake_ip)

    alert = {
        "message": "Connection from 203.0.113.10",
        "raw": "",
        "src_ip": "203.0.113.10",
        "dest_ip": None,
    }

    result = enrichment.enrich_alert(alert)
    ip_result = result["enrichment"]["src_ip"]

    assert ip_result["ioc"] == "203.0.113.10"
    assert ip_result["type"] == "ip"
    assert ip_result["providers_used"] == ["abuseipdb", "virustotal"]
    assert ip_result["verdict"] == "malicious"

    assert "abuseipdb" in ip_result
    assert ip_result["abuseipdb"]["abuse_confidence_score"] == 95

    assert "virustotal" in ip_result
    assert ip_result["virustotal"]["malicious"] == 8

def test_async_enrichment_handles_ip_domain_and_hash(monkeypatch):
    import asyncio
    from soc_agent_toolkit import enrichment_async

    calls = []

    async def fake_ip(client, value, sem):
        calls.append(("ip", value))
        return {
            "ioc": value,
            "type": "ip",
            "providers_used": ["virustotal"],
            "verdict": "malicious",
            "score": 90,
        }

    async def fake_domain(client, value, sem):
        calls.append(("domain", value))
        return {
            "ioc": value,
            "type": "domain",
            "providers_used": ["virustotal"],
            "verdict": "malicious",
            "score": 85,
        }

    async def fake_hash(client, value, sem):
        calls.append(("hash", value))
        return {
            "ioc": value,
            "type": "hash:sha256",
            "providers_used": ["virustotal"],
            "verdict": "malicious",
            "score": 95,
        }

    monkeypatch.setattr(enrichment_async, "enrich_ip_async", fake_ip)
    monkeypatch.setattr(enrichment_async, "enrich_domain_async", fake_domain)
    monkeypatch.setattr(enrichment_async, "enrich_hash_async", fake_hash)

    file_hash = (
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )

    alerts = [
        {
            "id": "async-001",
            "src_ip": "203.0.113.10",
            "dest_ip": None,
            "message": (
                "Connection to evil-example.com "
                f"with SHA256 {file_hash}"
            ),
            "raw": "",
        }
    ]

    result = asyncio.run(
        enrichment_async.enrich_alerts_batch_async(alerts)
    )

    enrichment = result[0]["enrichment"]

    assert "src_ip" in enrichment
    assert "domains" in enrichment
    assert "evil-example.com" in enrichment["domains"]
    assert "hashes" in enrichment
    assert file_hash in enrichment["hashes"]

    assert ("ip", "203.0.113.10") in calls
    assert ("domain", "evil-example.com") in calls
    assert ("hash", file_hash) in calls
