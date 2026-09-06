"""
enrichment_async.py — Concurrent variant of enrichment.py for large alert
batches. The sync `enrichment.py` does one blocking `requests.get()` per
IOC, which is fine for a handful of alerts but slow once you're enriching
hundreds (e.g. a bulk SIEM export): N IOCs x M providers x network latency,
all serialized.

This module re-implements the same provider calls with `httpx.AsyncClient`
and runs them concurrently (bounded by config.ASYNC_ENRICHMENT_CONCURRENCY
via a semaphore, so we don't blow through provider rate limits). It shares
the same cache (cache.py) and scoring config (config.py) as the sync path,
so results are consistent whichever one you use.

Usage:
    import asyncio
    from soc_agent_toolkit.enrichment_async import enrich_alerts_batch_async

    enriched = asyncio.run(enrich_alerts_batch_async(alerts))
"""

from __future__ import annotations

import asyncio
from typing import Any

from . import config
from .cache import get_cache
from .enrichment import (
    ABUSEIPDB_KEY,
    OTX_KEY,
    VT_KEY,
    _verdict_from_score,
    is_private_ip,
)
from .logging_setup import get_logger

logger = get_logger(__name__)

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


async def _get_json_async(client: "httpx.AsyncClient", url: str, headers: dict | None = None,
                           params: dict | None = None) -> dict | None:
    try:
        resp = await client.get(url, headers=headers, params=params, timeout=config.HTTP_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Async enrichment lookup got HTTP %s from %s", resp.status_code, url)
        return {"error": f"HTTP {resp.status_code}", "detail": resp.text[:300]}
    except Exception as exc:  # noqa: BLE001
        logger.warning("Async enrichment lookup failed for %s: %s", url, exc)
        return {"error": str(exc)}


async def enrich_ip_async(client: "httpx.AsyncClient", ip: str, sem: asyncio.Semaphore) -> dict[str, Any]:
    cache = get_cache()
    cache_key = f"ip:{ip}"
    hit = cache.get(cache_key)
    if hit is not None:
        result = dict(hit)
        result["cached"] = True
        return result

    result: dict[str, Any] = {"ioc": ip, "type": "ip", "providers_used": [], "verdict": "unknown"}
    if is_private_ip(ip):
        result["verdict"] = "private/internal"
        result["note"] = "RFC1918/private address — skip external lookups"
        cache.set(cache_key, result, ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS)
        return result

    async with sem:
        scores = []
        calls = []
        if ABUSEIPDB_KEY:
            calls.append(("abuseipdb", _get_json_async(
                client, "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )))
        if VT_KEY:
            calls.append(("virustotal", _get_json_async(
                client, f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_KEY},
            )))
        if OTX_KEY:
            calls.append(("otx", _get_json_async(
                client, f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
            )))

        responses = await asyncio.gather(*(c[1] for c in calls))

    for (provider, _), data in zip(calls, responses):
        result["providers_used"].append(provider)
        if provider == "abuseipdb" and data and "data" in data:
            d = data["data"]
            result["abuseipdb"] = {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
                "country": d.get("countryCode"),
                "is_tor": d.get("isTor"),
            }
            scores.append(d.get("abuseConfidenceScore", 0))
        elif provider == "virustotal" and data and "data" in data:
            stats = data["data"].get("attributes", {}).get("last_analysis_stats", {})
            result["virustotal"] = stats
            scores.append(min(100, stats.get("malicious", 0) * config.VT_MALICIOUS_VOTE_WEIGHT))
        elif provider == "otx" and data:
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            result["otx"] = {"pulse_count": pulse_count}
            scores.append(min(100, pulse_count * config.OTX_PULSE_WEIGHT))
        elif data:
            result[provider] = data  # error payload, still recorded for visibility

    if not result["providers_used"]:
        result["note"] = "No reputation API keys configured (ABUSEIPDB_API_KEY / VIRUSTOTAL_API_KEY / OTX_API_KEY)"
    elif scores:
        avg = sum(scores) / len(scores)
        result["verdict"] = _verdict_from_score(avg)
        result["score"] = round(avg, 1)

    if scores or not result["providers_used"]:
        cache.set(cache_key, result, ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS)
    return result


async def enrich_alerts_batch_async(
    alerts: list[dict[str, Any]],
    concurrency: int | None = None,
) -> list[dict[str, Any]]:
    """
    Enrich every alert's src_ip/dest_ip concurrently. Semantically equivalent
    to calling enrichment.enrich_alert() on each alert in a loop, but runs
    all the IOC lookups for the whole batch concurrently (bounded by
    `concurrency`, default config.ASYNC_ENRICHMENT_CONCURRENCY).
    """
    if httpx is None:
        raise RuntimeError(
            "enrich_alerts_batch_async() requires the `httpx` package "
            "(pip install httpx). Use enrichment.enrich_alert() for the "
            "synchronous, requests-based path instead."
        )

    concurrency = concurrency or config.ASYNC_ENRICHMENT_CONCURRENCY
    sem = asyncio.Semaphore(concurrency)
    logger.info("Enriching %d alert(s) concurrently (max %d in flight)", len(alerts), concurrency)

    async with httpx.AsyncClient() as client:
        # Collect unique IOCs first so the same IP shared across many alerts
        # (e.g. a noisy attacker source) is only looked up once, not once per alert.
        unique_ips = {ip for a in alerts for ip in (a.get("src_ip"), a.get("dest_ip")) if ip}
        results = await asyncio.gather(*(enrich_ip_async(client, ip, sem) for ip in unique_ips))
        ip_lookup = dict(zip(unique_ips, results))

    enriched = []
    for alert in alerts:
        alert = dict(alert)
        enrichments = {}
        for field_name in ("src_ip", "dest_ip"):
            ip = alert.get(field_name)
            if ip:
                enrichments[field_name] = ip_lookup[ip]
        alert["enrichment"] = enrichments
        enriched.append(alert)
    return enriched
