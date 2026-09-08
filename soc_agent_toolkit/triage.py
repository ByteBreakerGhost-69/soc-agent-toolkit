"""
triage.py — Deduplicate, score, and prioritize normalized alerts.

Dedup (item #9 from the review): the original version grouped alerts purely
by an exact (signature, src_ip, dest_ip) fingerprint, which has two gaps:
  1. Two alerts with the same fingerprint but weeks apart get silently
     merged into one "occurrence_count=2" alert, hiding that it's actually a
     fresh, unrelated incident.
  2. Two alerts that are obviously the same kind of event but have slightly
     different signature text (e.g. "SSH Brute Force" vs
     "SSH Brute-Force Attempt" from two different sensors) are treated as
     completely separate alerts.

dedup_alerts() groups by (src_ip, dest_ip) + fuzzy-matched signature and
requires timestamps to fall within config.DEDUP_TIME_WINDOW_MINUTES of the
group's most recent member.

Alerts with unparseable timestamps are conservatively treated as outside the
window unless both timestamps are unavailable.

Scoring weights live in config.py. Threat-intelligence verdicts and enrichment
confidence contribute to the final priority score.
"""

from __future__ import annotations

import difflib
from datetime import datetime
from typing import Any

from . import config
from .logging_setup import get_logger

logger = get_logger(__name__)

VERDICT_BOOST = {
    "malicious": 4,
    "suspicious": 2,
    "clean": 0,
    "unknown": 0,
    "private/internal": 0,
}

CONFIDENCE_BONUS = {
    "strong": 6,
    "mixed": 3,
    "weak": 1,
    "unknown": 0,
}

_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S",
    "%b %d, %Y @ %H:%M:%S.%f",
)


def _try_parse_timestamp(value: str | None) -> datetime | None:
    """Best-effort timestamp parsing across common alert timestamp formats."""
    if not value:
        return None

    try:
        from dateutil import parser as dateutil_parser

        return dateutil_parser.parse(value)
    except ImportError:
        pass
    except (ValueError, OverflowError):
        return None

    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    return None


def _signatures_match(sig_a: str, sig_b: str) -> bool:
    """Return True when signatures are identical or sufficiently similar."""
    if sig_a == sig_b:
        return True

    ratio = difflib.SequenceMatcher(
        None,
        sig_a.lower(),
        sig_b.lower(),
    ).ratio()

    return ratio >= config.DEDUP_FUZZY_SIGNATURE_THRESHOLD


def _within_window(
    ts_a: datetime | None,
    ts_b: datetime | None,
    window_minutes: int,
) -> bool:
    """
    Determine whether two timestamps are close enough for deduplication.

    Both timestamps missing:
        Assume same batch and allow merge.

    Only one timestamp missing:
        Do not merge conservatively.

    Timezone-aware vs naive:
        Do not merge because subtraction is ambiguous.
    """
    if ts_a is None and ts_b is None:
        return True

    if ts_a is None or ts_b is None:
        return False

    try:
        delta = abs((ts_a - ts_b).total_seconds())
    except TypeError:
        return False

    return delta <= window_minutes * 60


def dedup_alerts(
    alerts: list[dict],
    time_window_minutes: int | None = None,
    fuzzy_threshold: float | None = None,
) -> list[dict]:
    """
    Group alerts by (src_ip, dest_ip) + fuzzy-matched signature.

    Matching alerts are merged only when timestamps fall within the configured
    time window.

    Returns representative alerts with:
        occurrence_count
        first_seen
        last_seen
        related_ids
    """
    time_window_minutes = (
        time_window_minutes
        if time_window_minutes is not None
        else config.DEDUP_TIME_WINDOW_MINUTES
    )

    fuzzy_threshold = (
        fuzzy_threshold
        if fuzzy_threshold is not None
        else config.DEDUP_FUZZY_SIGNATURE_THRESHOLD
    )

    buckets: dict[tuple, list[dict[str, Any]]] = {}

    for alert in alerts:
        key = (
            alert.get("src_ip"),
            alert.get("dest_ip"),
        )

        ts = _try_parse_timestamp(alert.get("timestamp"))
        sig = alert.get("signature", "")

        bucket = buckets.setdefault(key, [])
        placed = False

        for group in bucket:
            if (
                _signatures_match(group["signature"], sig)
                and _within_window(
                    group["last_ts"],
                    ts,
                    time_window_minutes,
                )
            ):
                group["members"].append(alert)

                if ts is not None and (
                    group["last_ts"] is None
                    or ts > group["last_ts"]
                ):
                    group["last_ts"] = ts

                placed = True
                break

        if not placed:
            bucket.append(
                {
                    "signature": sig,
                    "last_ts": ts,
                    "members": [alert],
                }
            )

    deduped = []

    for bucket in buckets.values():
        for group in bucket:
            members = group["members"]
            rep = dict(members[0])

            timestamps = [
                m.get("timestamp")
                for m in members
                if m.get("timestamp")
            ]

            rep["occurrence_count"] = len(members)
            rep["first_seen"] = min(timestamps) if timestamps else None
            rep["last_seen"] = max(timestamps) if timestamps else None
            rep["related_ids"] = [
                m["id"]
                for m in members
                if m.get("id") is not None
            ]

            deduped.append(rep)

    logger.info(
        "dedup_alerts: %d raw -> %d deduped "
        "(window=%dm, fuzzy>=%.2f)",
        len(alerts),
        len(deduped),
        time_window_minutes,
        fuzzy_threshold,
    )

    return deduped


def _iter_enrichment_results(value: object):
    """Yield normalized enrichment result dictionaries from nested structures."""
    if isinstance(value, dict):
        if "verdict" in value:
            yield value
            return

        for nested in value.values():
            yield from _iter_enrichment_results(nested)

    elif isinstance(value, list):
        for nested in value:
            yield from _iter_enrichment_results(nested)


def enrichment_confidence(enrichment: dict) -> dict:
    """
    Estimate confidence from normalized threat-intelligence verdicts.

    Returns:
        result_count: Number of normalized enrichment results found.
        malicious_count: Number of malicious results.
        suspicious_count: Number of suspicious results.
        consensus: Overall consensus strength.
        confidence: Confidence score from 0.0 to 1.0.
    """
    results = list(_iter_enrichment_results(enrichment))

    result_count = len(results)

    providers = sorted(
        {
            provider
            for result in results
            for provider in result.get("providers_used", [])
        }
    )

    provider_count = len(providers)

    malicious_count = sum(
        1
        for result in results
        if result.get("verdict") == "malicious"
    )

    suspicious_count = sum(
        1
        for result in results
        if result.get("verdict") == "suspicious"
    )

    if result_count == 0:
        return {
            "result_count": 0,
            "provider_count": 0,
            "providers": [],
            "malicious_count": 0,
            "suspicious_count": 0,
            "consensus": "unknown",
            "confidence": 0.0,
        }

    positive_count = malicious_count + suspicious_count
    confidence = positive_count / result_count

    if malicious_count == 0 and suspicious_count == 0:
        consensus = "unknown"
    elif malicious_count == result_count:
        consensus = "strong"
    elif malicious_count >= 2 and malicious_count > suspicious_count:
        consensus = "strong"
    else:
        consensus = "mixed"

    return {
        "result_count": result_count,
        "provider_count": provider_count,
        "providers": providers,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "consensus": consensus,
        "confidence": round(confidence, 3),
    }

def score_alert(
    alert: dict,
    asset_criticality: dict[str, int] | None = None,
) -> int:
    """
    Compute a 0-100 priority score for a single deduped alert.

    Score components:
      - alert severity
      - repeated occurrences
      - threat-intelligence verdicts
      - enrichment confidence/consensus
      - MITRE ATT&CK match
      - asset criticality
    """
    asset_criticality = asset_criticality or {}

    score = alert.get("severity", 5) * config.SEVERITY_WEIGHT

    occurrences = alert.get("occurrence_count", 1)

    if occurrences > 1:
        score += min(
            config.REPEAT_OCCURRENCE_CAP,
            (occurrences - 1) * config.REPEAT_OCCURRENCE_POINTS,
        )

    enrichment = alert.get("enrichment", {})

    for field_data in _iter_enrichment_results(enrichment):
        verdict = field_data.get("verdict", "unknown")

        score += (
            VERDICT_BOOST.get(verdict, 0)
            * config.ENRICHMENT_BOOST_MULTIPLIER
        )

    confidence = enrichment_confidence(enrichment)

    score += CONFIDENCE_BONUS.get(
        confidence["consensus"],
        0,
    )

    if alert.get("mitre"):
        score += config.MITRE_MATCH_BONUS

    for field_name in ("src_ip", "dest_ip", "source"):
        val = alert.get(field_name)

        if val and val in asset_criticality:
            score += asset_criticality[val]

    return max(0, min(100, score))


def triage_alerts(
    alerts: list[dict],
    asset_criticality: dict[str, int] | None = None,
    dedup: bool = True,
) -> list[dict[str, Any]]:
    """
    Full triage pass: dedup -> score -> confidence -> sort.

    Adds:
        priority_score
        priority_tier
        enrichment_confidence
    """
    working = (
        dedup_alerts(alerts)
        if dedup
        else [dict(a) for a in alerts]
    )

    for a in working:
        s = score_alert(
            a,
            asset_criticality,
        )

        a["priority_score"] = s

        a["priority_tier"] = (
            "P1"
            if s >= config.TIER_P1_THRESHOLD
            else "P2"
            if s >= config.TIER_P2_THRESHOLD
            else "P3"
            if s >= config.TIER_P3_THRESHOLD
            else "P4"
        )

        a["enrichment_confidence"] = enrichment_confidence(
            a.get("enrichment", {})
        )

        confidence = a["enrichment_confidence"]

        a["threat_intelligence"] = {
            "verdict": (
                "malicious"
                if confidence["malicious_count"] > 0
                else "suspicious"
                if confidence["suspicious_count"] > 0
                else "unknown"
            ),
            "confidence": confidence["confidence"],
            "consensus": confidence["consensus"],
            "result_count": confidence["result_count"],
            "provider_count": confidence["provider_count"],
            "providers": confidence["providers"],
        }

    working.sort(
        key=lambda a: a["priority_score"],
        reverse=True,
    )

    return working
