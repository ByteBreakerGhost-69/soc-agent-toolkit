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
from .commands.mitre import cmd_mitre
from .commands.enrich import cmd_enrich_ip, cmd_enrich_domain, cmd_enrich_hash
from .commands.triage import make_cmd_triage
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


cmd_triage = make_cmd_triage(
    read_input=_read_input,
    read_asset_criticality=_read_asset_criticality,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    from .cli_parser import build_parser as _build_parser

    return _build_parser(
        cmd_analyze=cmd_analyze,
        cmd_triage=cmd_triage,
        cmd_mitre=cmd_mitre,
        cmd_enrich_ip=cmd_enrich_ip,
        cmd_enrich_domain=cmd_enrich_domain,
        cmd_enrich_hash=cmd_enrich_hash,
        cmd_status=cmd_status,
        cmd_doctor=cmd_doctor,
        cmd_config=cmd_config,
        cmd_version=cmd_version,
    )



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
