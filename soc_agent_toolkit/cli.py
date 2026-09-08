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
from .commands.analyze import make_cmd_analyze
from .commands.analyze_render import render_analysis_result
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




cmd_analyze = make_cmd_analyze(
    read_input=_read_input,
    read_asset_criticality=_read_asset_criticality,
    pipeline_runner=run_pipeline,
    analysis_renderer=render_analysis_result,
)


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
