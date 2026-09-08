"""
enrichment_async.py — Concurrent threat-intelligence enrichment.

Provides an asynchronous enrichment path for large alert batches using
httpx.AsyncClient. Supports:

- IP enrichment
- Domain enrichment
- File-hash enrichment
- Shared cache
- Bounded concurrency
- Batch-wide IOC deduplication

The async path mirrors the normalized result structure of enrichment.py.
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
    detect_hash_type,
    extract_iocs,
    is_private_ip,
)
from .logging_setup import get_logger

logger = get_logger(__name__)

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


async def _get_json_async(
    client: "httpx.AsyncClient",
    url: str,
    headers: dict | None = None,
    params: dict | None = None,
) -> dict | None:
    """Perform an async GET request and return parsed JSON."""
    try:
        response = await client.get(
            url,
            headers=headers,
            params=params,
            timeout=config.HTTP_TIMEOUT_SECONDS,
        )

        if response.status_code == 200:
            return response.json()

        logger.warning(
            "Async enrichment lookup got HTTP %s from %s",
            response.status_code,
            url,
        )

        return {
            "error": f"HTTP {response.status_code}",
            "detail": response.text[:300],
        }

    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Async enrichment lookup failed for %s: %s",
            url,
            exc,
        )
        return {"error": str(exc)}


async def enrich_ip_async(
    client: "httpx.AsyncClient",
    ip: str,
    sem: asyncio.Semaphore,
) -> dict[str, Any]:
    """Enrich an IP across configured reputation providers."""
    cache = get_cache()
    cache_key = f"ip:{ip}"

    hit = cache.get(cache_key)

    if hit is not None:
        result = dict(hit)
        result["cached"] = True
        return result

    result: dict[str, Any] = {
        "ioc": ip,
        "type": "ip",
        "providers_used": [],
        "verdict": "unknown",
    }

    if is_private_ip(ip):
        result["verdict"] = "private/internal"
        result["note"] = (
            "RFC1918/private address — skip external lookups"
        )

        cache.set(
            cache_key,
            result,
            ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS,
        )

        return result

    async with sem:
        scores: list[float] = []
        calls = []

        if ABUSEIPDB_KEY:
            calls.append(
                (
                    "abuseipdb",
                    _get_json_async(
                        client,
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={
                            "Key": ABUSEIPDB_KEY,
                            "Accept": "application/json",
                        },
                        params={
                            "ipAddress": ip,
                            "maxAgeInDays": 90,
                        },
                    ),
                )
            )

        if VT_KEY:
            calls.append(
                (
                    "virustotal",
                    _get_json_async(
                        client,
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": VT_KEY},
                    ),
                )
            )

        if OTX_KEY:
            calls.append(
                (
                    "otx",
                    _get_json_async(
                        client,
                        (
                            "https://otx.alienvault.com/api/v1/"
                            f"indicators/IPv4/{ip}/general"
                        ),
                        headers={"X-OTX-API-KEY": OTX_KEY},
                    ),
                )
            )

        responses = await asyncio.gather(
            *(call[1] for call in calls)
        )

    for (provider, _), data in zip(calls, responses):
        result["providers_used"].append(provider)

        if (
            provider == "abuseipdb"
            and data
            and "data" in data
        ):
            data_block = data["data"]

            result["abuseipdb"] = {
                "abuse_confidence_score": data_block.get(
                    "abuseConfidenceScore"
                ),
                "total_reports": data_block.get(
                    "totalReports"
                ),
                "country": data_block.get("countryCode"),
                "is_tor": data_block.get("isTor"),
            }

            scores.append(
                data_block.get("abuseConfidenceScore", 0)
            )

        elif (
            provider == "virustotal"
            and data
            and "data" in data
        ):
            stats = (
                data["data"]
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            result["virustotal"] = stats

            malicious = stats.get("malicious", 0)

            scores.append(
                min(
                    100,
                    malicious
                    * config.VT_MALICIOUS_VOTE_WEIGHT,
                )
            )

        elif provider == "otx" and data:
            pulse_count = data.get(
                "pulse_info", {}
            ).get("count", 0)

            result["otx"] = {
                "pulse_count": pulse_count,
            }

            scores.append(
                min(
                    100,
                    pulse_count
                    * config.OTX_PULSE_WEIGHT,
                )
            )

        elif data:
            result[provider] = data

    if not result["providers_used"]:
        result["note"] = (
            "No reputation API keys configured "
            "(ABUSEIPDB_API_KEY / "
            "VIRUSTOTAL_API_KEY / OTX_API_KEY)"
        )

    elif scores:
        average_score = sum(scores) / len(scores)

        result["verdict"] = _verdict_from_score(
            average_score
        )
        result["score"] = round(
            average_score,
            1,
        )

    if scores or not result["providers_used"]:
        cache.set(
            cache_key,
            result,
            ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS,
        )

    return result


async def enrich_domain_async(
    client: "httpx.AsyncClient",
    domain: str,
    sem: asyncio.Semaphore,
) -> dict[str, Any]:
    """Enrich a domain across configured reputation providers."""
    cache = get_cache()
    cache_key = f"domain:{domain}"

    hit = cache.get(cache_key)

    if hit is not None:
        result = dict(hit)
        result["cached"] = True
        return result

    result: dict[str, Any] = {
        "ioc": domain,
        "type": "domain",
        "providers_used": [],
        "verdict": "unknown",
    }

    async with sem:
        calls = []

        if VT_KEY:
            calls.append(
                (
                    "virustotal",
                    _get_json_async(
                        client,
                        (
                            "https://www.virustotal.com/api/v3/"
                            f"domains/{domain}"
                        ),
                        headers={
                            "x-apikey": VT_KEY,
                        },
                    ),
                )
            )

        if OTX_KEY:
            calls.append(
                (
                    "otx",
                    _get_json_async(
                        client,
                        (
                            "https://otx.alienvault.com/api/v1/"
                            f"indicators/domain/{domain}/general"
                        ),
                        headers={
                            "X-OTX-API-KEY": OTX_KEY,
                        },
                    ),
                )
            )

        responses = await asyncio.gather(
            *(call[1] for call in calls)
        )

    scores: list[float] = []

    for (provider, _), data in zip(calls, responses):
        result["providers_used"].append(provider)

        if (
            provider == "virustotal"
            and data
            and "data" in data
        ):
            stats = (
                data["data"]
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            result["virustotal"] = stats

            scores.append(
                min(
                    100,
                    stats.get("malicious", 0)
                    * config.VT_MALICIOUS_VOTE_WEIGHT,
                )
            )

        elif provider == "otx" and data:
            pulse_count = data.get(
                "pulse_info", {}
            ).get("count", 0)

            result["otx"] = {
                "pulse_count": pulse_count,
            }

            scores.append(
                min(
                    100,
                    pulse_count
                    * config.OTX_PULSE_WEIGHT,
                )
            )

        elif data:
            result[provider] = data

    if not result["providers_used"]:
        result["note"] = (
            "No reputation API keys configured "
            "(VIRUSTOTAL_API_KEY / OTX_API_KEY)"
        )

    elif scores:
        average_score = sum(scores) / len(scores)

        result["verdict"] = _verdict_from_score(
            average_score
        )
        result["score"] = round(
            average_score,
            1,
        )

    if scores or not result["providers_used"]:
        cache.set(
            cache_key,
            result,
            ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS,
        )

    return result


async def enrich_hash_async(
    client: "httpx.AsyncClient",
    file_hash: str,
    sem: asyncio.Semaphore,
) -> dict[str, Any]:
    """Enrich an MD5/SHA1/SHA256 hash via VirusTotal."""
    hash_type = detect_hash_type(file_hash)

    if not hash_type:
        return {
            "ioc": file_hash,
            "type": "hash:unknown",
            "providers_used": [],
            "verdict": "unknown",
            "note": (
                "Value does not match "
                "md5/sha1/sha256 format"
            ),
        }

    cache = get_cache()
    cache_key = f"hash:{file_hash}"

    hit = cache.get(cache_key)

    if hit is not None:
        result = dict(hit)
        result["cached"] = True
        return result

    result: dict[str, Any] = {
        "ioc": file_hash,
        "type": f"hash:{hash_type}",
        "providers_used": [],
        "verdict": "unknown",
    }

    async with sem:
        if VT_KEY:
            data = await _get_json_async(
                client,
                (
                    "https://www.virustotal.com/api/v3/"
                    f"files/{file_hash}"
                ),
                headers={
                    "x-apikey": VT_KEY,
                },
            )
        else:
            data = None

    if VT_KEY:
        result["providers_used"].append(
            "virustotal"
        )

        if data and "data" in data:
            attributes = data["data"].get(
                "attributes",
                {},
            )

            stats = attributes.get(
                "last_analysis_stats",
                {},
            )

            result["virustotal"] = {
                "stats": stats,
                "names": attributes.get(
                    "names",
                    [],
                )[:5],
                "type_description": attributes.get(
                    "type_description"
                ),
            }

            malicious = stats.get(
                "malicious",
                0,
            )

            total = sum(stats.values()) or 1

            result["score"] = round(
                100 * malicious / total,
                1,
            )

            result["verdict"] = (
                "malicious"
                if malicious
                >= config.HASH_MALICIOUS_VENDOR_COUNT
                else (
                    "suspicious"
                    if malicious
                    >= config.HASH_SUSPICIOUS_VENDOR_COUNT
                    else "clean"
                )
            )

        else:
            result["virustotal"] = (
                data or {"error": "no response"}
            )

    else:
        result["note"] = (
            "No reputation API key configured "
            "(VIRUSTOTAL_API_KEY)"
        )

    if result["providers_used"]:
        cache.set(
            cache_key,
            result,
            ttl_seconds=config.ENRICHMENT_CACHE_TTL_SECONDS,
        )

    return result


async def enrich_alerts_batch_async(
    alerts: list[dict[str, Any]],
    concurrency: int | None = None,
) -> list[dict[str, Any]]:
    """
    Enrich every alert's IPs, domains, and hashes concurrently.

    Unique IOCs are collected across the entire batch, meaning the same IOC
    appearing in multiple alerts is looked up only once.
    """
    if httpx is None:
        raise RuntimeError(
            "enrich_alerts_batch_async() requires the `httpx` package "
            "(pip install httpx). Use enrichment.enrich_alert() "
            "for the synchronous, requests-based path instead."
        )

    concurrency = (
        concurrency
        if concurrency is not None
        else config.ASYNC_ENRICHMENT_CONCURRENCY
    )

    sem = asyncio.Semaphore(concurrency)

    logger.info(
        "Enriching %d alert(s) concurrently "
        "(max %d in flight)",
        len(alerts),
        concurrency,
    )

    unique_ips: set[str] = set()
    unique_domains: set[str] = set()
    unique_hashes: set[str] = set()

    alert_iocs: list[dict[str, list[str]]] = []

    for alert in alerts:
        text = " ".join(
            str(value)
            for value in (
                alert.get("message", ""),
                alert.get("raw", ""),
            )
            if value
        )

        iocs = extract_iocs(text)

        # Explicit IP fields must always be enriched.
        for field_name in (
            "src_ip",
            "dest_ip",
        ):
            value = alert.get(field_name)

            if value:
                unique_ips.add(value)

        unique_ips.update(iocs["ips"])
        unique_domains.update(iocs["domains"])
        unique_hashes.update(iocs["hashes"])

        alert_iocs.append(iocs)

    async with httpx.AsyncClient() as client:
        ip_results = await asyncio.gather(
            *(
                enrich_ip_async(
                    client,
                    ip,
                    sem,
                )
                for ip in unique_ips
            )
        )

        domain_results = await asyncio.gather(
            *(
                enrich_domain_async(
                    client,
                    domain,
                    sem,
                )
                for domain in unique_domains
            )
        )

        hash_results = await asyncio.gather(
            *(
                enrich_hash_async(
                    client,
                    file_hash,
                    sem,
                )
                for file_hash in unique_hashes
            )
        )

    ip_lookup = dict(
        zip(
            unique_ips,
            ip_results,
        )
    )

    domain_lookup = dict(
        zip(
            unique_domains,
            domain_results,
        )
    )

    hash_lookup = dict(
        zip(
            unique_hashes,
            hash_results,
        )
    )

    enriched: list[dict[str, Any]] = []

    for alert, iocs in zip(
        alerts,
        alert_iocs,
    ):
        enriched_alert = dict(alert)
        enrichments: dict[str, Any] = {}

        for field_name in (
            "src_ip",
            "dest_ip",
        ):
            ip = enriched_alert.get(
                field_name
            )

            if ip:
                enrichments[field_name] = (
                    ip_lookup[ip]
                )

        explicit_ips = {
            enriched_alert.get("src_ip"),
            enriched_alert.get("dest_ip"),
        }

        additional_ips = {
            ip
            for ip in iocs["ips"]
            if ip not in explicit_ips
        }

        if additional_ips:
            enrichments["ips"] = {
                ip: ip_lookup[ip]
                for ip in additional_ips
            }

        if iocs["domains"]:
            enrichments["domains"] = {
                domain: domain_lookup[domain]
                for domain in iocs["domains"]
            }

        if iocs["hashes"]:
            enrichments["hashes"] = {
                file_hash: hash_lookup[file_hash]
                for file_hash in iocs["hashes"]
            }

        enriched_alert["ioc_extraction"] = iocs
        enriched_alert["enrichment"] = enrichments

        enriched.append(enriched_alert)

    return enriched
