"""Status command."""

from __future__ import annotations

import json
import os
import platform
from argparse import Namespace

from rich import box
from rich.console import Console
from rich.table import Table

from .. import config

console = Console()

EXIT_OK = 0
VERSION = "0.1.0"


def cmd_status(args: Namespace) -> int:
    """Show toolkit and integration status."""
    table = Table(
        title="SOC AGENT STATUS",
        box=box.ROUNDED,
        expand=True,
    )

    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row(
        "Toolkit",
        "[green]READY[/green]",
        f"v{VERSION}",
    )

    table.add_row(
        "Python",
        "[green]READY[/green]",
        platform.python_version(),
    )

    table.add_row(
        "Platform",
        "[green]READY[/green]",
        platform.system(),
    )

    table.add_row(
        "AI Model",
        "[green]CONFIGURED[/green]",
        config.ANTHROPIC_MODEL,
    )

    table.add_row(
        "MITRE Dataset",
        "[green]CONFIGURED[/green]",
        "Remote STIX source",
    )

    table.add_row(
        "Enrichment Cache",
        "[green]READY[/green]",
        f"TTL {config.ENRICHMENT_CACHE_TTL_SECONDS}s",
    )

    table.add_row(
        "VirusTotal",
        "[green]CONFIGURED[/green]"
        if os.getenv("VIRUSTOTAL_API_KEY")
        else "[yellow]NOT CONFIGURED[/yellow]",
        "API key detected"
        if os.getenv("VIRUSTOTAL_API_KEY")
        else "Set VIRUSTOTAL_API_KEY to enable",
    )

    table.add_row(
        "AbuseIPDB",
        "[green]CONFIGURED[/green]"
        if os.getenv("ABUSEIPDB_API_KEY")
        else "[yellow]NOT CONFIGURED[/yellow]",
        "API key detected"
        if os.getenv("ABUSEIPDB_API_KEY")
        else "Set ABUSEIPDB_API_KEY to enable",
    )

    table.add_row(
        "AlienVault OTX",
        "[green]CONFIGURED[/green]"
        if os.getenv("OTX_API_KEY")
        else "[yellow]NOT CONFIGURED[/yellow]",
        "API key detected"
        if os.getenv("OTX_API_KEY")
        else "Set OTX_API_KEY to enable",
    )

    table.add_row(
        "Claude AI",
        "[green]CONFIGURED[/green]"
        if os.getenv("ANTHROPIC_API_KEY")
        else "[yellow]OFFLINE FALLBACK[/yellow]",
        "API key detected"
        if os.getenv("ANTHROPIC_API_KEY")
        else "Deterministic offline mode",
    )

    if args.json:
        result = {
            "toolkit": {
                "version": VERSION,
            },
            "runtime": {
                "python": platform.python_version(),
                "platform": platform.system(),
            },
            "configuration": {
                "model": config.ANTHROPIC_MODEL,
                "mitre_dataset": bool(config.MITRE_STIX_URL),
                "enrichment_cache_ttl": config.ENRICHMENT_CACHE_TTL_SECONDS,
            },
            "integrations": {
                "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
                "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
                "otx": bool(os.getenv("OTX_API_KEY")),
                "claude": bool(os.getenv("ANTHROPIC_API_KEY")),
            },
        }

        print(json.dumps(result, ensure_ascii=False, indent=2))
        return EXIT_OK

    console.print(table)
    return EXIT_OK
