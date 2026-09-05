"""
mitre.py — MITRE ATT&CK technique mapping, two ways:

1. Heuristic keyword mapper (`map_technique`) — fast, offline, zero
   dependencies. Good default and always available, but coarse: it will
   miss techniques with no matching keyword and can occasionally over-match
   generic terms. This is the known limitation flagged in the code review —
   treat it as a first-pass triage tag, not ground truth.

2. Optional STIX-backed mapper (`map_technique_stix`) — downloads the real
   MITRE ATT&CK Enterprise STIX bundle (cached to disk, see config.py for
   TTL/path) and matches alert text against every technique's actual name
   and aliases. Far more accurate coverage, at the cost of a one-time
   network fetch (~40MB) and a slower first call. Falls back to the
   heuristic mapper automatically if the dataset can't be loaded (offline,
   blocked network, etc.) — call sites don't need to know which path ran.

`enrich_alert_with_mitre(alert, use_stix=False)` is the main entry point
used by the pipeline; pass use_stix=True to prefer the STIX-backed mapper
when available.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from typing import Any

from . import config
from .logging_setup import get_logger

logger = get_logger(__name__)

# (keywords to match in signature/message, case-insensitive) -> (technique_id, technique_name, tactic)
SIGNATURE_KEYWORDS: list[tuple[list[str], str, str, str]] = [
    (["brute force", "bruteforce", "password spray", "credential stuffing"],
     "T1110", "Brute Force", "Credential Access"),
    (["mimikatz", "lsass dump", "credential dump"],
     "T1003", "OS Credential Dumping", "Credential Access"),
    (["powershell -enc", "powershell encoded", "encodedcommand"],
     "T1059.001", "PowerShell", "Execution"),
    (["scheduled task", "schtasks", "cron job added"],
     "T1053", "Scheduled Task/Job", "Persistence"),
    (["new admin account", "account created", "user added to administrators"],
     "T1136", "Create Account", "Persistence"),
    (["disable defender", "disable antivirus", "amsi bypass", "edr kill"],
     "T1562.001", "Disable or Modify Tools", "Defense Evasion"),
    (["beacon", "c2", "command and control", "callback"],
     "T1071", "Application Layer Protocol", "Command and Control"),
    (["dns tunneling", "dns exfiltration"],
     "T1071.004", "DNS", "Command and Control"),
    (["port scan", "nmap", "network scan"],
     "T1046", "Network Service Discovery", "Discovery"),
    (["phishing", "malicious attachment", "suspicious email link"],
     "T1566", "Phishing", "Initial Access"),
    (["exploit public-facing", "cve-", "rce attempt", "sqli", "sql injection"],
     "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (["lateral movement", "psexec", "wmiexec", "remote service creation"],
     "T1021", "Remote Services", "Lateral Movement"),
    (["data staged", "archive collected", "rar of exfil"],
     "T1074", "Data Staged", "Collection"),
    (["exfiltration", "data transfer to external", "large outbound upload"],
     "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    (["ransomware", "file encrypted", "ransom note"],
     "T1486", "Data Encrypted for Impact", "Impact"),
    (["impossible travel", "geo anomaly login"],
     "T1078", "Valid Accounts", "Defense Evasion"),
    (["malware detected", "trojan", "backdoor"],
     "T1204", "User Execution", "Execution"),
]


def map_technique(text: str) -> list[dict[str, str]]:
    """Return all ATT&CK techniques whose keywords appear in `text` (offline heuristic)."""
    text_l = (text or "").lower()
    matches = []
    for keywords, tid, tname, tactic in SIGNATURE_KEYWORDS:
        if any(kw in text_l for kw in keywords):
            matches.append({"technique_id": tid, "technique": tname, "tactic": tactic})
    return matches


# --- STIX-backed mapper -------------------------------------------------

_STIX_INDEX_CACHE: dict[str, list[dict[str, str]]] | None = None  # word -> [technique matches], built once per process


def _download_stix_bundle() -> dict[str, Any] | None:
    logger.info("Downloading MITRE ATT&CK STIX bundle from %s (one-time, cached to %s)",
                config.MITRE_STIX_URL, config.MITRE_CACHE_PATH)
    try:
        with urllib.request.urlopen(config.MITRE_STIX_URL, timeout=30) as resp:
            data = json.loads(resp.read())
        with open(config.MITRE_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": time.time(), "bundle": data}, f)
        return data
    except Exception:
        logger.exception("Failed to download MITRE ATT&CK STIX bundle")
        return None


def _load_stix_bundle(force_refresh: bool = False) -> dict[str, Any] | None:
    if not force_refresh and os.path.exists(config.MITRE_CACHE_PATH):
        try:
            with open(config.MITRE_CACHE_PATH, encoding="utf-8") as f:
                cached = json.load(f)
            age = time.time() - cached.get("fetched_at", 0)
            if age < config.MITRE_CACHE_TTL_SECONDS:
                return cached["bundle"]
            logger.info("MITRE STIX cache expired (age=%.0fs), refreshing", age)
        except Exception:
            logger.warning("MITRE STIX cache file unreadable, refetching", exc_info=True)
    return _download_stix_bundle()


def _build_stix_index(bundle: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    """
    Build a simple word -> technique-matches index from the STIX bundle so
    lookups stay O(1)-ish instead of rescanning every technique per alert.
    Indexes on the technique name and any x_mitre_aliases, tokenized to
    lowercase words of 4+ chars (skips short/common words).
    """
    index: dict[str, list[dict[str, str]]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = next(
            (ref["external_id"] for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack" and "external_id" in ref),
            None,
        )
        if not tid:
            continue
        tactics = [phase["phase_name"].replace("-", " ").title()
                   for phase in obj.get("kill_chain_phases", [])
                   if phase.get("kill_chain_name") == "mitre-attack"]
        entry = {"technique_id": tid, "technique": obj.get("name", tid),
                 "tactic": tactics[0] if tactics else "Unknown"}

        names_to_index = [obj.get("name", "")] + obj.get("x_mitre_aliases", [])
        for name in names_to_index:
            for word in re.findall(r"[a-z0-9]{4,}", name.lower()):
                index.setdefault(word, [])
                if entry not in index[word]:
                    index[word].append(entry)
    return index


def _get_stix_index(force_refresh: bool = False) -> dict[str, list[dict[str, str]]] | None:
    global _STIX_INDEX_CACHE
    if _STIX_INDEX_CACHE is not None and not force_refresh:
        return _STIX_INDEX_CACHE
    bundle = _load_stix_bundle(force_refresh=force_refresh)
    if bundle is None:
        return None
    _STIX_INDEX_CACHE = _build_stix_index(bundle)
    logger.info("Built MITRE STIX keyword index with %d indexed word(s)", len(_STIX_INDEX_CACHE))
    return _STIX_INDEX_CACHE


def map_technique_stix(text: str, force_refresh: bool = False) -> list[dict[str, str]] | None:
    """
    Match `text` against real ATT&CK technique names/aliases from the STIX
    bundle. Returns None (not []) if the dataset couldn't be loaded, so
    callers can distinguish "no matches" from "dataset unavailable, fell
    back to heuristic".
    """
    index = _get_stix_index(force_refresh=force_refresh)
    if index is None:
        return None

    text_l = (text or "").lower()
    words = set(re.findall(r"[a-z0-9]{4,}", text_l))
    seen_ids = set()
    matches = []
    for word in words:
        for entry in index.get(word, []):
            if entry["technique_id"] not in seen_ids:
                seen_ids.add(entry["technique_id"])
                matches.append(entry)
    return matches


def enrich_alert_with_mitre(alert: dict, use_stix: bool = False) -> dict:
    """
    Add a `mitre` field (list of technique matches) to a normalized alert.

    use_stix=True tries the real ATT&CK dataset first and transparently
    falls back to the keyword heuristic if the dataset isn't available
    (offline, blocked egress, first-run download failure, etc.).
    """
    haystack = f"{alert.get('signature', '')} {alert.get('message', '')}"
    alert = dict(alert)

    if use_stix:
        stix_matches = map_technique_stix(haystack)
        if stix_matches is not None:
            alert["mitre"] = stix_matches
            alert["mitre_source"] = "stix"
            return alert
        logger.info("STIX-backed MITRE mapping unavailable, falling back to keyword heuristic")

    alert["mitre"] = map_technique(haystack)
    alert["mitre_source"] = "heuristic"
    return alert
