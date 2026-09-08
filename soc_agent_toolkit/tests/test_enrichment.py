
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
