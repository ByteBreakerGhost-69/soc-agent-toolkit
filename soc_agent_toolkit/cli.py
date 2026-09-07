"""
cli.py — Command-line interface for SOC Agent Toolkit.

Usage:
    soc-agent analyze alerts.json
    soc-agent analyze alerts.json --json
    cat alerts.json | soc-agent analyze -
    soc-agent mitre "SSH brute force login attempt"
    soc-agent version
"""

from __future__ import annotations

import argparse
import json
import sys
import os
import platform
import requests

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TextColumn
from rich.table import Table

from . import config, enrichment, mitre, triage
from .agent import run_pipeline
from .logging_setup import configure_logging, get_logger

logger = get_logger(__name__)
console = Console()

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_RUNTIME_ERROR = 3

VERSION = "0.1.0"


def _read_input(path: str) -> str:
    """Read alerts from a file path or stdin when path is '-'."""
    if path == "-":
        return sys.stdin.read()

    with open(path, encoding="utf-8") as f:
        return f.read()


def _read_asset_criticality(path: str) -> dict[str, int]:
    """Read asset criticality mapping from JSON."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected a JSON object of {{ip_or_host: weight}}, "
            f"got {type(data).__name__}"
        )

    return data


def cmd_analyze(args: argparse.Namespace) -> int:
    """Run the SOC analysis pipeline."""
    configure_logging(args.log_level or "WARNING")

    try:
        raw_input = _read_input(args.input)
    except FileNotFoundError:
        print(
            f"Error: input file not found: {args.input}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR
    except PermissionError:
        print(
            f"Error: permission denied reading: {args.input}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR
    except IsADirectoryError:
        print(
            f"Error: expected a file but got a directory: {args.input}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR
    except UnicodeDecodeError:
        print(
            f"Error: could not decode {args.input} as UTF-8 text.",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    if not raw_input.strip():
        print(
            f"Error: {args.input} is empty — nothing to triage.",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    asset_criticality = None

    if args.assets:
        try:
            asset_criticality = _read_asset_criticality(args.assets)
        except FileNotFoundError:
            print(
                f"Error: assets file not found: {args.assets}",
                file=sys.stderr,
            )
            return EXIT_INPUT_ERROR
        except json.JSONDecodeError as exc:
            print(
                f"Error: {args.assets} is not valid JSON ({exc})",
                file=sys.stderr,
            )
            return EXIT_INPUT_ERROR
        except ValueError as exc:
            print(
                f"Error: {exc}",
                file=sys.stderr,
            )
            return EXIT_INPUT_ERROR

    # Run the actual SOC pipeline.
    try:
        with Progress(
            TextColumn("{task.description}"),
            transient=False,
            console=Console(stderr=True),
        ) as progress:

            current_task: int | None = None

            def update_progress(message: str) -> None:
                nonlocal current_task

                # Complete the previous stage.
                if current_task is not None:
                    previous_description = progress.tasks[
                        current_task
                    ].description

                    previous_description = (
                        previous_description
                        .replace("[cyan]⠋[/cyan] ", "")
                        .replace("[green]✓[/green] ", "")
                    )

                    progress.update(
                        current_task,
                        description=(
                            f"[green]✓[/green] "
                            f"{previous_description}"
                        ),
                        completed=1,
                    )

                # Start the new stage.
                current_task = progress.add_task(
                    f"[cyan]⠋[/cyan] {message}",
                    total=1,
                    completed=0,
                )

            result = run_pipeline(
                raw_input,
                asset_criticality=asset_criticality,
                progress_callback=update_progress,
            )

            # Complete the final stage.
            if current_task is not None:
                final_description = progress.tasks[
                    current_task
                ].description

                final_description = (
                    final_description
                    .replace("[cyan]⠋[/cyan] ", "")
                    .replace("[green]✓[/green] ", "")
                )

                progress.update(
                    current_task,
                    description=(
                        f"[green]✓[/green] "
                        f"{final_description}"
                    ),
                    completed=1,
                )

    except Exception:
        logger.exception("Pipeline failed")

        print(
            "Error: the triage pipeline failed unexpectedly.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR

    # JSON mode stays machine-readable.
    if args.json:
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )
        return EXIT_OK

    alerts = result.get("alerts", [])

    p1 = sum(
        1
        for alert in alerts
        if alert.get("priority_tier") == "P1"
    )

    p2 = sum(
        1
        for alert in alerts
        if alert.get("priority_tier") == "P2"
    )

    p3 = sum(
        1
        for alert in alerts
        if alert.get("priority_tier") == "P3"
    )

    p4 = sum(
        1
        for alert in alerts
        if alert.get("priority_tier") == "P4"
    )

    status = Table(
        box=box.SIMPLE,
        expand=True,
    )

    status.add_column("Metric", style="bold")
    status.add_column("Value")

    status.add_row("Alerts analyzed", str(len(alerts)))
    status.add_row("P1 Critical", str(p1))
    status.add_row("P2 High", str(p2))
    status.add_row("P3 Medium", str(p3))
    status.add_row("P4 Low", str(p4))

    console.print(
        Panel(
            status,
            title="ANALYSIS COMPLETE",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    if alerts:
        top = alerts[0]

        incident = Table(
            box=box.SIMPLE,
            expand=True,
        )

        incident.add_column(
            "Field",
            style="bold",
            width=18,
        )
        incident.add_column("Value")

        incident.add_row(
            "Signature",
            str(top.get("signature", "Unknown")),
        )
        incident.add_row(
            "Priority",
            str(top.get("priority_tier", "Unknown")),
        )
        incident.add_row(
            "Score",
            str(top.get("priority_score", "Unknown")),
        )
        incident.add_row(
            "Source",
            str(top.get("src_ip", "Unknown")),
        )
        incident.add_row(
            "Target",
            str(top.get("dest_ip", "Unknown")),
        )

        mitre_matches = top.get("mitre", [])

        if mitre_matches:
            mitre_text = ", ".join(
                f"{item.get('technique_id')} — "
                f"{item.get('technique')}"
                for item in mitre_matches
            )
        else:
            mitre_text = "No MITRE technique matched"

        incident.add_row(
            "MITRE ATT&CK",
            mitre_text,
        )

        console.print(
            Panel(
                incident,
                title="TOP INCIDENT",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    console.print(
        Panel(
            result.get(
                "summary",
                "No incident summary available.",
            ),
            title="INCIDENT SUMMARY",
            border_style="blue",
            box=box.ROUNDED,
        )
    )

    console.print(
        f"[dim]{len(alerts)} deduped alerts — "
        "use --json for machine-readable output[/dim]"
    )

    return EXIT_OK

def cmd_triage(args: argparse.Namespace) -> int:
    """Run alert deduplication and priority scoring."""
    configure_logging(args.log_level or "WARNING")

    try:
        raw_input = _read_input(args.input)

        if not raw_input.strip():
            print(
                f"Error: {args.input} is empty — nothing to triage.",
                file=sys.stderr,
            )
            return EXIT_INPUT_ERROR

        data = json.loads(raw_input)

        if not isinstance(data, list):
            print(
                "Error: triage input must be a JSON array of alerts.",
                file=sys.stderr,
            )
            return EXIT_INPUT_ERROR

        asset_criticality = None

        if args.assets:
            asset_criticality = _read_asset_criticality(args.assets)

        triaged = triage.triage_alerts(
            data,
            asset_criticality=asset_criticality,
        )

        if args.json:
            print(
                json.dumps(
                    triaged,
                    ensure_ascii=False,
                    indent=2,
                    default=str,
                )
            )
            return EXIT_OK

        table = Table(
            title="SOC TRIAGE RESULTS",
            box=box.ROUNDED,
            expand=True,
        )

        table.add_column("Priority", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Signature")
        table.add_column("Source")
        table.add_column("Target")

        for alert in triaged:
            table.add_row(
                str(alert.get("priority_tier", "P4")),
                str(alert.get("priority_score", 0)),
                str(alert.get("signature", "Unknown")),
                str(alert.get("src_ip", "Unknown")),
                str(alert.get("dest_ip", "Unknown")),
            )

        console.print(table)

        console.print(
            f"[dim]{len(triaged)} alerts triaged and sorted by priority[/dim]"
        )

        return EXIT_OK

    except FileNotFoundError:
        print(
            f"Error: input file not found: {args.input}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    except PermissionError:
        print(
            f"Error: permission denied reading: {args.input}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    except json.JSONDecodeError as exc:
        print(
            f"Error: {args.input} is not valid JSON ({exc})",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    except Exception:
        logger.exception("Triage failed")

        print(
            "Error: triage failed unexpectedly.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR

def cmd_mitre(args: argparse.Namespace) -> int:
    """Map text to MITRE ATT&CK techniques."""
    try:
        results = mitre.map_technique(args.text)

        if not results:
            print("No MITRE ATT&CK technique matched.")
            return EXIT_OK

        print("MITRE ATT&CK Matches")
        print("====================")

        for item in results:
            print(
                f"{item['technique_id']} — "
                f"{item['technique']}"
            )
            print(f"Tactic: {item['tactic']}")
            print()

        return EXIT_OK

    except Exception:
        logger.exception("MITRE mapping failed")

        print(
            "Error: MITRE ATT&CK mapping failed.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR


def cmd_enrich_ip(args: argparse.Namespace) -> int:
    """Check IP reputation."""
    try:
        result = enrichment.enrich_ip(args.ip)

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )

        return EXIT_OK

    except Exception:
        logger.exception("IP enrichment failed")

        print(
            "Error: IP enrichment failed.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR


def cmd_enrich_domain(args: argparse.Namespace) -> int:
    """Check domain reputation."""
    try:
        result = enrichment.enrich_domain(args.domain)

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )

        return EXIT_OK

    except Exception:
        logger.exception("Domain enrichment failed")

        print(
            "Error: domain enrichment failed.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR

def cmd_enrich_hash(args: argparse.Namespace) -> int:
    """Check file hash reputation."""
    try:
        result = enrichment.enrich_hash(args.hash)

        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )

        return EXIT_OK

    except Exception:
        logger.exception("Hash enrichment failed")

        print(
            "Error: hash enrichment failed.",
            file=sys.stderr,
        )

        return EXIT_RUNTIME_ERROR

def cmd_status(args: argparse.Namespace) -> int:
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


def cmd_doctor(args: argparse.Namespace) -> int:
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


def cmd_config(args: argparse.Namespace) -> int:
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



def cmd_version(_: argparse.Namespace) -> int:
    """Print the CLI version."""
    print(f"SOC Agent Toolkit v{VERSION}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="soc-agent",
        description=(
            "SOC Agent Toolkit — "
            "AI-assisted SOC alert triage and incident analysis"
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{analyze,triage,mitre,enrich,status,config,doctor,version}",
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze and triage security alerts",
    )

    analyze_parser.add_argument(
        "input",
        help="Path to alert/log file, or '-' to read from stdin",
    )

    analyze_parser.add_argument(
        "--assets",
        help=(
            "Optional JSON file mapping IP/hostname "
            "to criticality weight"
        ),
    )

    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete analysis result as JSON",
    )

    analyze_parser.add_argument(
        "--log-level",
        default=None,
        help=(
            "DEBUG, INFO, WARNING, ERROR "
            "(default: INFO or $SOC_TOOLKIT_LOG_LEVEL)"
        ),
    )

    analyze_parser.set_defaults(func=cmd_analyze)

    triage_parser = subparsers.add_parser(
        "triage",
        help="Deduplicate and prioritize security alerts",
    )

    triage_parser.add_argument(
        "input",
        help="Path to JSON alert file, or '-' to read from stdin",
    )

    triage_parser.add_argument(
        "--assets",
        help="Optional JSON file mapping IP/hostname to criticality weight",
    )

    triage_parser.add_argument(
        "--json",
        action="store_true",
        help="Print triaged alerts as JSON",
    )

    triage_parser.add_argument(
        "--log-level",
        default=None,
        help="DEBUG, INFO, WARNING, ERROR",
    )

    triage_parser.set_defaults(func=cmd_triage)

    mitre_parser = subparsers.add_parser(
        "mitre",
        help="Map text to MITRE ATT&CK techniques",
    )

    mitre_parser.add_argument(
        "text",
        help="Security alert text to map",
    )

    mitre_parser.set_defaults(func=cmd_mitre)

    # Grouped enrichment commands
    enrich_parser = subparsers.add_parser(
        "enrich",
        help="Enrich IPs, domains, and file hashes",
    )

    enrich_subparsers = enrich_parser.add_subparsers(
        dest="enrich_type",
        required=True,
    )

    enrich_ip_group_parser = enrich_subparsers.add_parser(
        "ip",
        help="Check IP reputation",
    )
    enrich_ip_group_parser.add_argument(
        "ip",
        help="IPv4 or IPv6 address to investigate",
    )
    enrich_ip_group_parser.set_defaults(func=cmd_enrich_ip)

    enrich_domain_group_parser = enrich_subparsers.add_parser(
        "domain",
        help="Check domain reputation",
    )
    enrich_domain_group_parser.add_argument(
        "domain",
        help="Domain to investigate",
    )
    enrich_domain_group_parser.set_defaults(func=cmd_enrich_domain)

    enrich_hash_group_parser = enrich_subparsers.add_parser(
        "hash",
        help="Check file hash reputation",
    )
    enrich_hash_group_parser.add_argument(
        "hash",
        help="MD5, SHA1, or SHA256 file hash to investigate",
    )
    enrich_hash_group_parser.set_defaults(func=cmd_enrich_hash)

    enrich_ip_parser = subparsers.add_parser(
        "enrich-ip",
        help=argparse.SUPPRESS,
    )

    enrich_ip_parser.add_argument(
        "ip",
        help="IPv4 or IPv6 address to investigate",
    )

    enrich_ip_parser.set_defaults(func=cmd_enrich_ip)

    enrich_domain_parser = subparsers.add_parser(
        "enrich-domain",
        help=argparse.SUPPRESS,
    )

    enrich_domain_parser.add_argument(
        "domain",
        help="Domain to investigate",
    )

    enrich_domain_parser.set_defaults(func=cmd_enrich_domain)

    enrich_hash_parser = subparsers.add_parser(
        "enrich-hash",
        help=argparse.SUPPRESS,
    )

    enrich_hash_parser.add_argument(
        "hash",
        help="MD5, SHA1, or SHA256 file hash to investigate",
    )

    enrich_hash_parser.set_defaults(func=cmd_enrich_hash)

    status_parser = subparsers.add_parser(
        "status",
        help="Show toolkit and integration status",
    )

    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Print status as JSON",
    )

    status_parser.set_defaults(func=cmd_status)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Run toolkit health checks",
    )

    doctor_parser.add_argument(
        "--network",
        action="store_true",
        help="Also check outbound HTTPS connectivity",
    )

    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Print diagnostic results as JSON",
    )

    doctor_parser.set_defaults(func=cmd_doctor)

    config_parser = subparsers.add_parser(
        "config",
        help="Show toolkit configuration status",
    )

    config_parser.add_argument(
        "--json",
        action="store_true",
        help="Print configuration as JSON",
    )

    config_parser.set_defaults(func=cmd_config)

    version_parser = subparsers.add_parser(
        "version",
        help="Show SOC Agent Toolkit version",
    )

    version_parser.set_defaults(func=cmd_version)

    hidden_commands = {"enrich-ip", "enrich-domain", "enrich-hash"}
    subparsers._choices_actions = [
        action
        for action in subparsers._choices_actions
        if action.dest not in hidden_commands
    ]

    return parser


def main() -> int:
    """CLI entrypoint."""
    if len(sys.argv) == 1:
        from .tui import run_interactive

        run_interactive()
        return EXIT_OK

    parser = build_parser()
    args = parser.parse_args()

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
