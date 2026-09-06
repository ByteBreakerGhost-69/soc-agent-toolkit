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

from . import enrichment, mitre
from .agent import run_pipeline
from .logging_setup import configure_logging, get_logger

logger = get_logger(__name__)

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
    configure_logging(args.log_level)

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

    try:
        result = run_pipeline(
            raw_input,
            asset_criticality=asset_criticality,
        )

    except Exception:
        logger.exception("Pipeline failed")

        print(
            "Error: the triage pipeline failed unexpectedly — "
            "see logs above for details.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR

    if args.json:
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )
    else:
        print(result["summary"])
        print(
            f"\n({len(result['alerts'])} deduped alerts — "
            "run with --json for full detail)"
        )

    return EXIT_OK


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

        print(json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            default=str,
        ))

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
    )

    # -------------------------------------------------
    # analyze
    # -------------------------------------------------
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

    # -------------------------------------------------
    # mitre
    # -------------------------------------------------
    mitre_parser = subparsers.add_parser(
        "mitre",
        help="Map text to MITRE ATT&CK techniques",
    )

    mitre_parser.add_argument(
        "text",
        help="Security alert text to map",
    )

    mitre_parser.set_defaults(func=cmd_mitre)

    # -------------------------------------------------
    # enrich-ip
    # -------------------------------------------------
    enrich_ip_parser = subparsers.add_parser(
        "enrich-ip",
        help="Check IP reputation",
    )

    enrich_ip_parser.add_argument(
        "ip",
        help="IPv4 or IPv6 address to investigate",
    )

    enrich_ip_parser.set_defaults(func=cmd_enrich_ip)

    # -------------------------------------------------
    # enrich-domain
    # -------------------------------------------------
    enrich_domain_parser = subparsers.add_parser(
        "enrich-domain",
        help="Check domain reputation",
    )

    enrich_domain_parser.add_argument(
        "domain",
        help="Domain to investigate",
    )

    enrich_domain_parser.set_defaults(func=cmd_enrich_domain)

    # -------------------------------------------------
    # version
    # -------------------------------------------------
    version_parser = subparsers.add_parser(
        "version",
        help="Show SOC Agent Toolkit version",
    )

    version_parser.set_defaults(func=cmd_version)

    return parser


def main() -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
