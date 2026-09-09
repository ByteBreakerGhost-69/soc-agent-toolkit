import json

from soc_agent_toolkit import config, mitre


def test_download_stix_bundle_rejects_non_https(monkeypatch):
    monkeypatch.setattr(
        config,
        "MITRE_STIX_URL",
        "http://example.com/enterprise-attack.json",
    )

    def fail_request(*args, **kwargs):
        raise AssertionError("HTTP request should not be made for non-HTTPS URL")

    monkeypatch.setattr(mitre.requests, "get", fail_request)

    result = mitre._download_stix_bundle()

    assert result is None


def test_download_stix_bundle_creates_cache_directory(monkeypatch, tmp_path):
    cache_path = tmp_path / "nested" / "cache" / "mitre.json"

    monkeypatch.setattr(
        config,
        "MITRE_STIX_URL",
        "https://example.com/enterprise-attack.json",
    )
    monkeypatch.setattr(
        config,
        "MITRE_CACHE_PATH",
        str(cache_path),
    )

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "type": "bundle",
                "objects": [],
            }

    monkeypatch.setattr(
        mitre.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    result = mitre._download_stix_bundle()

    assert result == {
        "type": "bundle",
        "objects": [],
    }
    assert cache_path.exists()

    cached = json.loads(cache_path.read_text(encoding="utf-8"))
    assert cached["bundle"] == result
    assert "fetched_at" in cached
