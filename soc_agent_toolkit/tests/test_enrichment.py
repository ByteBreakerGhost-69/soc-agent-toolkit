
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
