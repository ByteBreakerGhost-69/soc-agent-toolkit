"""Configuration command."""

from __future__ import annotations

import json
import os
from argparse import Namespace

from rich import box
from rich.console import Console
from rich.table import Table

from .. import config

console = Console()
EXIT_OK = 0

def cmd_config(args: Namespace) -> int:
    """Show toolkit configuration."""
    table = Table(
        title="SOC AGENT CONFIG",
        box=box.ROUNDED,
        expand=True,
    )

    table.add_column("Setting", style="bold")
    table.add_column("Value")

    rows = [
        ("AI Model", config.ANTHROPIC_MODEL),
        ("VT Vote Weight", str(config.VT_MALICIOUS_VOTE_WEIGHT)),
        ("OTX Pulse Weight", str(config.OTX_PULSE_WEIGHT)),
        (
            "Malicious Threshold",
            str(config.VERDICT_MALICIOUS_THRESHOLD),
        ),
        (
            "Suspicious Threshold",
            str(config.VERDICT_SUSPICIOUS_THRESHOLD),
        ),
        (
            "Hash Malicious Vendors",
            str(config.HASH_MALICIOUS_VENDOR_COUNT),
        ),
        (
            "Hash Suspicious Vendors",
            str(config.HASH_SUSPICIOUS_VENDOR_COUNT),
        ),
        ("Severity Weight", str(config.SEVERITY_WEIGHT)),
        (
            "Repeat Occurrence Points",
            str(config.REPEAT_OCCURRENCE_POINTS),
        ),
        ("Repeat Occurrence Cap", str(config.REPEAT_OCCURRENCE_CAP)),
        (
            "Enrichment Boost Multiplier",
            str(config.ENRICHMENT_BOOST_MULTIPLIER),
        ),
        ("MITRE Match Bonus", str(config.MITRE_MATCH_BONUS)),
        ("P1 Threshold", str(config.TIER_P1_THRESHOLD)),
        ("P2 Threshold", str(config.TIER_P2_THRESHOLD)),
        ("P3 Threshold", str(config.TIER_P3_THRESHOLD)),
        (
            "Enrichment Cache TTL",
            f"{config.ENRICHMENT_CACHE_TTL_SECONDS}s",
        ),
        (
            "Dedup Window",
            f"{config.DEDUP_TIME_WINDOW_MINUTES} min",
        ),
        (
            "Dedup Fuzzy Threshold",
            str(config.DEDUP_FUZZY_SIGNATURE_THRESHOLD),
        ),
        (
            "Async Concurrency",
            str(config.ASYNC_ENRICHMENT_CONCURRENCY),
        ),
        (
            "HTTP Timeout",
            f"{config.HTTP_TIMEOUT_SECONDS}s",
        ),
        ("Log Level", os.getenv("SOC_TOOLKIT_LOG_LEVEL", "WARNING")),
    ]

    for name, value in rows:
        table.add_row(name, value)

    if args.json:
        result = {
            "configuration": {
                "ai_model": config.ANTHROPIC_MODEL,
                "vt_vote_weight": config.VT_MALICIOUS_VOTE_WEIGHT,
                "otx_pulse_weight": config.OTX_PULSE_WEIGHT,
                "malicious_threshold": config.VERDICT_MALICIOUS_THRESHOLD,
                "suspicious_threshold": config.VERDICT_SUSPICIOUS_THRESHOLD,
                "hash_malicious_vendors": config.HASH_MALICIOUS_VENDOR_COUNT,
                "hash_suspicious_vendors": config.HASH_SUSPICIOUS_VENDOR_COUNT,
                "severity_weight": config.SEVERITY_WEIGHT,
                "repeat_occurrence_points": config.REPEAT_OCCURRENCE_POINTS,
                "repeat_occurrence_cap": config.REPEAT_OCCURRENCE_CAP,
                "enrichment_boost_multiplier": config.ENRICHMENT_BOOST_MULTIPLIER,
                "mitre_match_bonus": config.MITRE_MATCH_BONUS,
                "tier_p1_threshold": config.TIER_P1_THRESHOLD,
                "tier_p2_threshold": config.TIER_P2_THRESHOLD,
                "tier_p3_threshold": config.TIER_P3_THRESHOLD,
                "enrichment_cache_ttl_seconds": config.ENRICHMENT_CACHE_TTL_SECONDS,
                "dedup_time_window_minutes": config.DEDUP_TIME_WINDOW_MINUTES,
                "dedup_fuzzy_signature_threshold": config.DEDUP_FUZZY_SIGNATURE_THRESHOLD,
                "async_enrichment_concurrency": config.ASYNC_ENRICHMENT_CONCURRENCY,
                "http_timeout_seconds": config.HTTP_TIMEOUT_SECONDS,
                "log_level": os.getenv("SOC_TOOLKIT_LOG_LEVEL", "WARNING"),
            },
            "integrations": {
                "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
                "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
                "otx": bool(os.getenv("OTX_API_KEY")),
                "claude": bool(os.getenv("ANTHROPIC_API_KEY")),
            },
        }

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            )
        )
        return EXIT_OK

    console.print(table)

    console.print()

    api_table = Table(
        title="INTEGRATIONS",
        box=box.SIMPLE,
        expand=True,
    )

    api_table.add_column("Provider", style="bold")
    api_table.add_column("Status")

    providers = [
        ("VirusTotal", "VIRUSTOTAL_API_KEY"),
        ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
        ("AlienVault OTX", "OTX_API_KEY"),
        ("Claude AI", "ANTHROPIC_API_KEY"),
    ]

    for provider, env_name in providers:
        configured = bool(os.getenv(env_name))
        api_table.add_row(
            provider,
            "[green]SET[/green]"
            if configured
            else "[yellow]NOT SET[/yellow]",
        )

    console.print(api_table)
    return EXIT_OK
