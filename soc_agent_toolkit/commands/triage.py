"""Alert triage command."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich import box
from rich.console import Console
from rich.table import Table

from .. import triage
from ..logging_setup import configure_logging, get_logger

logger = get_logger(__name__)
console = Console()

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_RUNTIME_ERROR = 3

def cmd_triage(
    args: Namespace,
    *,
    read_input,
    read_asset_criticality,
) -> int:
    """Run alert deduplication and priority scoring."""
    configure_logging(args.log_level or "WARNING")

    try:
        raw_input = read_input(args.input)

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
            asset_criticality = read_asset_criticality(args.assets)

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


def make_cmd_triage(*, read_input, read_asset_criticality):
    """Create the parser-compatible triage command handler."""
    def _cmd(args: Namespace) -> int:
        return cmd_triage(
            args,
            read_input=read_input,
            read_asset_criticality=read_asset_criticality,
        )

    return _cmd
