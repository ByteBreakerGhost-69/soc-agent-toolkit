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
from .commands.version import VERSION, cmd_version
from .commands.status import cmd_status
from .commands.config import cmd_config
from .commands.doctor import cmd_doctor
from .agent import run_pipeline
from .logging_setup import configure_logging, get_logger

logger = get_logger(__name__)
console = Console()

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_RUNTIME_ERROR = 3



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
