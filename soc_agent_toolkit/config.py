"""
config.py — Single place for tunables that used to be hardcoded scattered
across the toolkit: model name, enrichment scoring weights, cache TTLs, and
the MITRE dataset source. Everything here can be overridden via environment
variables so ops can retune without touching source code.
"""

from __future__ import annotations

import os


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


# --- Claude model -----------------------------------------------------------
# Was hardcoded as MODEL = "claude-sonnet-4-6" in both agent.py and
# summarizer.py. Now one source of truth, overridable per-environment
# (e.g. pin a specific dated snapshot in prod without a code change).
ANTHROPIC_MODEL = os.environ.get("SOC_TOOLKIT_MODEL", "claude-sonnet-4-6")

# --- Enrichment scoring weights ---------------------------------------------
# Rationale: reputation providers report on different scales, so we normalize
# every provider to a 0-100 "malice score" before averaging them:
#   - AbuseIPDB already reports 0-100 (abuseConfidenceScore) -> used as-is.
#   - VirusTotal reports a raw vendor count (e.g. "12 vendors flagged this").
#     VT_MALICIOUS_VOTE_WEIGHT (default 20) says "each flagging vendor is
#     worth 20 points toward the 0-100 scale", i.e. 5 vendors flagging
#     something = 100 (max malice). This is a deliberately conservative
#     default: VT has 70+ vendors, so 5 independent flags is already a solid
#     signal, but it's tunable per your false-positive tolerance.
#   - OTX only reports how many threat-intel "pulses" reference the IOC, not
#     a malice score. OTX_PULSE_WEIGHT (default 10) says "each pulse is worth
#     10 points", capped at 100.
VT_MALICIOUS_VOTE_WEIGHT = _env_int("SOC_VT_VOTE_WEIGHT", 20)
OTX_PULSE_WEIGHT = _env_int("SOC_OTX_PULSE_WEIGHT", 10)

# Verdict thresholds applied to the averaged 0-100 score.
VERDICT_MALICIOUS_THRESHOLD = _env_int("SOC_VERDICT_MALICIOUS_THRESHOLD", 50)
VERDICT_SUSPICIOUS_THRESHOLD = _env_int("SOC_VERDICT_SUSPICIOUS_THRESHOLD", 20)

# File-hash verdicts use raw vendor counts directly (VT gives an exact
# malicious-vendor count for files, unlike the vote-weighted IP/domain score).
HASH_MALICIOUS_VENDOR_COUNT = _env_int("SOC_HASH_MALICIOUS_VENDORS", 3)
HASH_SUSPICIOUS_VENDOR_COUNT = _env_int("SOC_HASH_SUSPICIOUS_VENDORS", 1)

# --- Triage scoring weights ---------------------------------------------
# Base severity (0-10) is scaled to a 0-60 contribution -> SEVERITY_WEIGHT=6.
SEVERITY_WEIGHT = _env_int("SOC_SEVERITY_WEIGHT", 6)
# Each repeat occurrence beyond the first adds this many points, capped.
REPEAT_OCCURRENCE_POINTS = _env_int("SOC_REPEAT_OCCURRENCE_POINTS", 3)
REPEAT_OCCURRENCE_CAP = _env_int("SOC_REPEAT_OCCURRENCE_CAP", 20)
# Each malicious/suspicious enriched IOC on the alert adds this many points
# per point of VERDICT_BOOST (see triage.VERDICT_BOOST).
ENRICHMENT_BOOST_MULTIPLIER = _env_int("SOC_ENRICHMENT_BOOST_MULTIPLIER", 2)
# Flat bonus for matching a known ATT&CK technique (signal it's not noise).
MITRE_MATCH_BONUS = _env_int("SOC_MITRE_MATCH_BONUS", 5)

# Priority tier cutoffs on the final 0-100 score.
TIER_P1_THRESHOLD = _env_int("SOC_TIER_P1", 80)
TIER_P2_THRESHOLD = _env_int("SOC_TIER_P2", 55)
TIER_P3_THRESHOLD = _env_int("SOC_TIER_P3", 30)

# --- Caching -----------------------------------------------------------
# In-memory TTL cache for enrichment lookups, to avoid re-hitting rate-limited
# reputation APIs for the same IOC within a run/session.
ENRICHMENT_CACHE_TTL_SECONDS = _env_int("SOC_ENRICHMENT_CACHE_TTL", 3600)
REDIS_URL = os.environ.get("SOC_REDIS_URL")  # optional; falls back to in-memory if unset

# --- Deduplication -----------------------------------------------------
# Alerts with the same (signature, src_ip, dest_ip) fingerprint are only
# grouped together if they fall within this time window; otherwise they're
# treated as separate incidents (e.g. brute force today vs. same pairing a
# month ago shouldn't be silently merged).
DEDUP_TIME_WINDOW_MINUTES = _env_int("SOC_DEDUP_WINDOW_MINUTES", 60)
# Fuzzy-match threshold (0-1, difflib ratio) for treating two differently
# worded signatures as "the same alert type" during dedup.
DEDUP_FUZZY_SIGNATURE_THRESHOLD = _env_float("SOC_DEDUP_FUZZY_THRESHOLD", 0.90)

# --- MITRE ATT&CK dataset ------------------------------------------------
MITRE_STIX_URL = os.environ.get(
    "SOC_MITRE_STIX_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
)
MITRE_CACHE_PATH = os.environ.get(
    "SOC_MITRE_CACHE_PATH",
    os.path.expanduser("~/.cache/soc-agent-toolkit/mitre.json"),
)
MITRE_CACHE_TTL_SECONDS = _env_int("SOC_MITRE_CACHE_TTL", 7 * 24 * 3600)  # 1 week

# --- Async enrichment -----------------------------------------------------
ASYNC_ENRICHMENT_CONCURRENCY = _env_int("SOC_ASYNC_CONCURRENCY", 10)
HTTP_TIMEOUT_SECONDS = _env_int("SOC_HTTP_TIMEOUT", 10)
