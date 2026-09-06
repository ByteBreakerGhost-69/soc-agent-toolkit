"""
enrichment.py — IOC reputation enrichment for IPs, domains, and file hashes.

Providers supported (via API key in env vars — never hardcode keys):
  - AbuseIPDB   (ABUSEIPDB_API_KEY)   -> IP reputation
  - VirusTotal  (VIRUSTOTAL_API_KEY)          -> IP / domain / hash reputation
  - AlienVault OTX (OTX_API_KEY)      -> IP / domain pulses

If no key is set for a provider, that provider is skipped (not faked) and
`enrich_ip` / `enrich_domain` / `enrich_hash` return whatever providers ARE
configured, plus a `providers_used` list so the agent/analyst knows what
was actually checked.

Scoring: every provider is normalized to a 0-100 "malice score" then
averaged. The weights used to do that (e.g. "each VT vendor flag = 20
points") live in config.py with the rationale documented there, instead of
being unexplained magic numbers here — see config.VT_MALICIOUS_VOTE_WEIGHT
and config.OTX_PULSE_WEIGHT.

Caching: every successful lookup is cached (see cache.py) for
config.ENRICHMENT_CACHE_TTL_SECONDS to avoid re-hitting rate-limited APIs
for the same IOC within a run. Error responses are not cached, so a
transient outage doesn't get "stuck" for the full TTL.

Network calls are isolated behind `_get_json` so tests can mock it.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from . import config
from .cache import get_cache
from .logging_setup import get_logger

logger = get_logger(__name__)

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
OTX_KEY = os.environ.get("OTX_API_KEY")

_HASH_RE = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def _get_json(url: str, headers: dict | None = None, params: dict | None = None, timeout: int | None = None) -> dict | None:
    if requests is None:
        logger.warning("`requests` not installed — enrichment lookups are disabled")
        return None
    timeout = timeout or config.HTTP_TIMEOUT_SECONDS
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Enrichment lookup got HTTP %s from %s", resp.status_code, url)
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text[:300]}
    except Exception as exc:  # noqa: BLE001 - surface any transport error to caller
        logger.warning("Enrichment lookup failed for %s: %s", url, exc)
        return {"error": str(exc)}


def is_private_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)

        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )

        return any(
            address in network
            for network in private_networks
        )

    except ValueError:
        return False

def detect_hash_type(value: str) -> str | None:
    for htype, pattern in _HASH_RE.items():
        if pattern.match(value.strip()):
            return htype
    return None


def _verdict_from_score(score: float) -> str:
    if score >= config.VERDICT_MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= config.VERDICT_SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def _cached_or_fetch(cache_key: str, fetch_fn) -> dict[str, Any]:
    """Shared cache-check-then-fetch-then-store wrapper for the three enrich_* functions."""
    cache = get_cache()
    hit = cache.get(cache_key)
    if hit is not None:
        logger.debug("Cache hit for %s", cache_key)
        result = dict(hit)
        result["cached"] = True
        return result

    result = fetch_fn()
    # Don't cache outright transport errors — a transient outage shouldn't
    # "poison" the cache for the full TTL; only cache results where at least
    # one provider actually responded (or the IOC is private/unsupported,
    # which is a stable fact worth caching).
    has_provider_error_only = result.get("providers_used") and not any(
        k in result for k in ("abuseipdb", "virustotal", "otx")
    )
    if not has_provider_error_only:
        cache.set(cache_key, result, ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS)
    return result


def enrich_ip(ip: str) -> dict[str, Any]:
    """Look up an IP across configured reputation providers (cached, see module docstring)."""
    def _fetch() -> dict[str, Any]:
        result: dict[str, Any] = {"ioc": ip, "type": "ip", "providers_used": [], "verdict": "unknown"}

        if is_private_ip(ip):
            result["verdict"] = "private/internal"
            result["note"] = "RFC1918/private address — skip external lookups"
            return result

        scores = []

        if ABUSEIPDB_KEY:
            data = _get_json(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            result["providers_used"].append("abuseipdb")
            if data and "data" in data:
                d = data["data"]
                result["abuseipdb"] = {
                    "abuse_confidence_score": d.get("abuseConfidenceScore"),
                    "total_reports": d.get("totalReports"),
                    "country": d.get("countryCode"),
                    "is_tor": d.get("isTor"),
                }
                scores.append(d.get("abuseConfidenceScore", 0))  # already 0-100
            else:
                result["abuseipdb"] = data or {"error": "no response"}

        if VT_KEY:
            data = _get_json(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_KEY},
            )
            result["providers_used"].append("virustotal")
            if data and "data" in data:
                stats = data["data"].get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                result["virustotal"] = stats
                scores.append(min(100, malicious * config.VT_MALICIOUS_VOTE_WEIGHT))
            else:
                result["virustotal"] = data or {"error": "no response"}

        if OTX_KEY:
            data = _get_json(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
            )
            result["providers_used"].append("otx")
            if data:
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                result["otx"] = {"pulse_count": pulse_count}
                scores.append(min(100, pulse_count * config.OTX_PULSE_WEIGHT))

        if not result["providers_used"]:
            result["note"] = "No reputation API keys configured (ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY / OTX_API_KEY)"
        elif scores:
            avg = sum(scores) / len(scores)
            result["verdict"] = _verdict_from_score(avg)
            result["score"] = round(avg, 1)

        return result

    return _cached_or_fetch(f"ip:{ip}", _fetch)


def enrich_domain(domain: str) -> dict[str, Any]:
    """Look up a domain across configured reputation providers (cached, see module docstring)."""
    def _fetch() -> dict[str, Any]:
        result: dict[str, Any] = {"ioc": domain, "type": "domain", "providers_used": [], "verdict": "unknown"}
        scores = []

        if VT_KEY:
            data = _get_json(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_KEY},
            )
            result["providers_used"].append("virustotal")
            if data and "data" in data:
                stats = data["data"].get("attributes", {}).get("last_analysis_stats", {})
                result["virustotal"] = stats
                scores.append(min(100, stats.get("malicious", 0) * config.VT_MALICIOUS_VOTE_WEIGHT))
            else:
                result["virustotal"] = data or {"error": "no response"}

        if OTX_KEY:
            data = _get_json(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
            )
            result["providers_used"].append("otx")
            if data:
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                result["otx"] = {"pulse_count": pulse_count}
                scores.append(min(100, pulse_count * config.OTX_PULSE_WEIGHT))

        if not result["providers_used"]:
            result["note"] = "No reputation API keys configured (VIRUSTOTAL_API_KEY / OTX_API_KEY)"
        elif scores:
            avg = sum(scores) / len(scores)
            result["verdict"] = _verdict_from_score(avg)
            result["score"] = round(avg, 1)

        return result

    return _cached_or_fetch(f"domain:{domain}", _fetch)


def enrich_hash(file_hash: str) -> dict[str, Any]:
    """Look up a file hash (md5/sha1/sha256) via VirusTotal (cached, see module docstring)."""
    htype = detect_hash_type(file_hash)
    if not htype:
        return {
            "ioc": file_hash, "type": "hash:unknown", "providers_used": [], "verdict": "unknown",
            "note": "Value does not match md5/sha1/sha256 format",
        }

    def _fetch() -> dict[str, Any]:
        result: dict[str, Any] = {
            "ioc": file_hash, "type": f"hash:{htype}",
            "providers_used": [], "verdict": "unknown",
        }

        if VT_KEY:
            data = _get_json(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VT_KEY},
            )
            result["providers_used"].append("virustotal")
            if data and "data" in data:
                attrs = data["data"].get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["virustotal"] = {
                    "stats": stats,
                    "names": attrs.get("names", [])[:5],
                    "type_description": attrs.get("type_description"),
                }
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                result["score"] = round(100 * malicious / total, 1)
                result["verdict"] = (
                    "malicious" if malicious >= config.HASH_MALICIOUS_VENDOR_COUNT
                    else "suspicious" if malicious >= config.HASH_SUSPICIOUS_VENDOR_COUNT
                    else "clean"
                )
            else:
                result["virustotal"] = data or {"error": "no response"}
        else:
            result["note"] = "No reputation API key configured (VIRUSTOTAL_API_KEY)"

        return result

    return _cached_or_fetch(f"hash:{file_hash}", _fetch)


def enrich_alert(alert: dict) -> dict:
    """Enrich a normalized alert's src_ip/dest_ip fields in place (returns a copy)."""
    alert = dict(alert)
    enrichments = {}
    for field_name in ("src_ip", "dest_ip"):
        ip = alert.get(field_name)
        if ip:
            enrichments[field_name] = enrich_ip(ip)
    alert["enrichment"] = enrichments
    return alert
