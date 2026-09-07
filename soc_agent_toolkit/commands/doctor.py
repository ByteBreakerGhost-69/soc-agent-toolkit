"""Doctor command."""

from __future__ import annotations

import json
import os
import platform
import sys
from argparse import Namespace

import requests
from rich import box
from rich.console import Console
from rich.table import Table

from .. import config

console = Console()

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 3

def cmd_doctor(args: Namespace) -> int:
    """Run basic toolkit health checks."""
    checks = []

    def add_check(name: str, ok: bool, details: str) -> None:
        checks.append((name, ok, details))

    # Python runtime
    add_check(
        "Python",
        sys.version_info >= (3, 10),
        platform.python_version(),
    )

    # Core dependencies
    dependency_checks = [
        ("requests", "requests"),
        ("httpx", "httpx"),
        ("rich", "rich"),
        ("anthropic", "anthropic"),
    ]

    for display_name, module_name in dependency_checks:
        try:
            __import__(module_name)
            add_check(display_name, True, "available")
        except ImportError:
            add_check(display_name, False, "missing")

    # Configuration source
    add_check(
        "Configuration",
        bool(config.ANTHROPIC_MODEL),
        f"model={config.ANTHROPIC_MODEL}",
    )

    # MITRE source
    add_check(
        "MITRE dataset",
        bool(config.MITRE_STIX_URL),
        "STIX source configured"
        if config.MITRE_STIX_URL
        else "STIX source missing",
    )

    if args.network:
        # Basic outbound HTTPS connectivity.
        # No API key is sent and no reputation lookup is performed.
        network_targets = {
            "VirusTotal": "https://www.virustotal.com",
            "AbuseIPDB": "https://api.abuseipdb.com",
            "AlienVault OTX": "https://otx.alienvault.com",
        }

        for provider, url in network_targets.items():
            try:
                response = requests.get(
                    url,
                    timeout=config.HTTP_TIMEOUT_SECONDS,
                )
                add_check(
                    f"{provider} network",
                    True,
                    f"HTTPS reachable (HTTP {response.status_code})",
                )
            except Exception as exc:
                add_check(
                    f"{provider} network",
                    False,
                    f"unreachable ({type(exc).__name__})",
                )

    # Enrichment providers
    providers = [
        ("VirusTotal", "VIRUSTOTAL_API_KEY"),
        ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
        ("AlienVault OTX", "OTX_API_KEY"),
        ("Claude AI", "ANTHROPIC_API_KEY"),
    ]

    configured_count = sum(
        1 for _, env_name in providers if os.getenv(env_name)
    )

    add_check(
        "Integrations",
        True,
        f"{configured_count}/{len(providers)} providers configured",
    )

    if args.json:
        result = {
            "checks": [
                {
                    "name": name,
                    "status": "pass" if ok else "fail",
                    "details": details,
                }
                for name, ok, details in checks
            ],
            "failed": sum(1 for _, ok, _ in checks if not ok),
        }

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
            )
        )

        return (
            EXIT_RUNTIME_ERROR
            if result["failed"]
            else EXIT_OK
        )

    table = Table(
        title="SOC AGENT DOCTOR",
        box=box.ROUNDED,
        expand=True,
    )

    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    for name, ok, details in checks:
        table.add_row(
            name,
            "[green]PASS[/green]" if ok else "[red]FAIL[/red]",
            details,
        )

    console.print(table)

    failed = sum(1 for _, ok, _ in checks if not ok)

    console.print()

    if failed:
        console.print(
            f"[red]Doctor found {failed} problem(s).[/red]"
        )
        return EXIT_RUNTIME_ERROR

    console.print("[green]All diagnostic checks passed.[/green]")
    return EXIT_OK
