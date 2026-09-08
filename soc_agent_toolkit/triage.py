"""
triage.py — Deduplicate, score, and prioritize normalized alerts.

Dedup (item #9 from the review): the original version grouped alerts purely
by an exact (signature, src_ip, dest_ip) fingerprint, which has two gaps:
  1. Two alerts with the same fingerprint but weeks apart get silently
     merged into one "occurrence_count=2" alert, hiding that it's actually a
     fresh, unrelated incident.
  2. Two alerts that are obviously the same *kind* of event but have
     slightly different signature text (e.g. "SSH Brute Force" vs "SSH
     Brute-Force Attempt" from two different sensors) are treated as
     completely separate alerts.

`dedup_alerts()` now groups by (fuzzy-matched signature, src_ip, dest_ip)
AND requires the timestamps to fall within config.DEDUP_TIME_WINDOW_MINUTES
of each other. Alerts with unparseable timestamps are conservatively treated
as "outside the window" (i.e. NOT merged) rather than guessed at, since a
false merge hides an incident and a false split just costs a duplicate line
in the summary.

Scoring weights (base severity multiplier, repeat-occurrence bonus,
enrichment boost, MITRE-match bonus, tier cutoffs) all live in config.py
now instead of being inline magic numbers — see config.py for the
per-weight rationale.
"""

from __future__ import annotations

import difflib
from datetime import datetime
from typing import Any

from . import config
from .logging_setup import get_logger

logger = get_logger(__name__)

VERDICT_BOOST = {"malicious": 4, "suspicious": 2, "clean": 0, "unknown": 0, "private/internal": 0}

_TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
    "%b %d %H:%M:%S", "%b %d, %Y @ %H:%M:%S.%f",
)


def _try_parse_timestamp(value: str | None) -> datetime | None:
    """Best-effort timestamp parsing across the handful of formats we're likely to see.
    Returns None (not "now") on failure — callers must treat that as "unknown time",
    not "recent", to avoid accidentally collapsing unrelated alerts into one group."""
    if not value:
        return None
    try:
        from dateutil import parser as dateutil_parser  # optional dependency
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
    if sig_a == sig_b:
        return True
    ratio = difflib.SequenceMatcher(None, sig_a.lower(), sig_b.lower()).ratio()
    return ratio >= config.DEDUP_FUZZY_SIGNATURE_THRESHOLD


def _within_window(ts_a: datetime | None, ts_b: datetime | None, window_minutes: int) -> bool:
    """
    If BOTH timestamps are missing/unparseable, assume same batch (merge) —
    this is the common case for SIEM exports that don't carry a timestamp
    field, and matches the pre-review behavior for that case. If only ONE
    side has a timestamp, or the timestamps are tz-aware vs naive and can't
    be compared, be conservative and do NOT merge — that ambiguity is exactly
    the case where silently merging could hide a genuinely separate incident.
    """
    if ts_a is None and ts_b is None:
        return True
    if ts_a is None or ts_b is None:
        return False
    try:
        delta = abs((ts_a - ts_b).total_seconds())
    except TypeError:
        # tz-aware vs naive datetimes can't be subtracted; be conservative.
        return False
    return delta <= window_minutes * 60


def dedup_alerts(
    alerts: list[dict],
    time_window_minutes: int | None = None,
    fuzzy_threshold: float | None = None,
) -> list[dict]:
    """
    Group alerts by (src_ip, dest_ip) + fuzzy-matched signature, only merging
    alerts whose timestamps fall within `time_window_minutes` of the group's
    most recent member. Returns one representative alert per group with
    `occurrence_count`, `first_seen`/`last_seen`, and `related_ids` added.

    Alert dictionaries do not require an ``id`` field. When an alert has no
    ID, it is omitted from ``related_ids`` rather than causing triage to fail.
    """
    time_window_minutes = time_window_minutes if time_window_minutes is not None else config.DEDUP_TIME_WINDOW_MINUTES
    fuzzy_threshold = fuzzy_threshold if fuzzy_threshold is not None else config.DEDUP_FUZZY_SIGNATURE_THRESHOLD

    # Groups keyed by (src_ip, dest_ip); each bucket holds a list of open
    # groups (dicts with "members", "signature", "last_ts") since more than
    # one *kind* of alert can share the same src/dest pair.
    buckets: dict[tuple, list[dict[str, Any]]] = {}

    for alert in alerts:
        key = (alert.get("src_ip"), alert.get("dest_ip"))
        ts = _try_parse_timestamp(alert.get("timestamp"))
        sig = alert.get("signature", "")

        bucket = buckets.setdefault(key, [])
        placed = False
        for group in bucket:
            if _signatures_match(group["signature"], sig) and _within_window(group["last_ts"], ts, time_window_minutes):
                group["members"].append(alert)
                if ts is not None and (group["last_ts"] is None or ts > group["last_ts"]):
                    group["last_ts"] = ts
                placed = True
                break
        if not placed:
            bucket.append({"signature": sig, "last_ts": ts, "members": [alert]})

    deduped = []
    for bucket in buckets.values():
        for group in bucket:
            members = group["members"]
            rep = dict(members[0])
            timestamps = [m.get("timestamp") for m in members if m.get("timestamp")]
            rep["occurrence_count"] = len(members)
            rep["first_seen"] = min(timestamps) if timestamps else None
            rep["last_seen"] = max(timestamps) if timestamps else None
            rep["related_ids"] = [m["id"] for m in members if m.get("id") is not None]
            deduped.append(rep)

    logger.info("dedup_alerts: %d raw -> %d deduped (window=%dm, fuzzy>=%.2f)",
                len(alerts), len(deduped), time_window_minutes, fuzzy_threshold)
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


def score_alert(alert: dict, asset_criticality: dict[str, int] | None = None) -> int:
    """Compute a 0-100 priority score for a single (deduped) alert. See config.py
    for the rationale behind each weight used here."""
    asset_criticality = asset_criticality or {}
    score = alert.get("severity", 5) * config.SEVERITY_WEIGHT

    occurrences = alert.get("occurrence_count", 1)
    if occurrences > 1:
        score += min(config.REPEAT_OCCURRENCE_CAP, (occurrences - 1) * config.REPEAT_OCCURRENCE_POINTS)

    enrichment = alert.get("enrichment", {})
    for field_data in _iter_enrichment_results(enrichment):
        verdict = field_data.get("verdict", "unknown")
        score += (
            VERDICT_BOOST.get(verdict, 0)
            * config.ENRICHMENT_BOOST_MULTIPLIER
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
    Full triage pass: dedup (optional) -> score -> sort descending by score.
    Adds `priority_score` and `priority_tier` ("P1".."P4") to each alert.
    """
    working = dedup_alerts(alerts) if dedup else [dict(a) for a in alerts]

    for a in working:
        s = score_alert(a, asset_criticality)
        a["priority_score"] = s
        a["priority_tier"] = (
            "P1" if s >= config.TIER_P1_THRESHOLD
            else "P2" if s >= config.TIER_P2_THRESHOLD
            else "P3" if s >= config.TIER_P3_THRESHOLD
            else "P4"
        )

    working.sort(key=lambda a: a["priority_score"], reverse=True)
    return working
