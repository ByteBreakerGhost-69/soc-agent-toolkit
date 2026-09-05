"""
cli.py — Command-line entrypoint.

Usage:
    python -m soc_agent_toolkit.cli path/to/alerts.log
    cat alerts.json | python -m soc_agent_toolkit.cli -
    python -m soc_agent_toolkit.cli path/to/alerts.log --assets assets.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .agent import run_pipeline
from .logging_setup import configure_logging, get_logger

logger = get_logger(__name__)

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_RUNTIME_ERROR = 3


def _read_input(path: str) -> str:
    """Read the alert input from a file path or stdin ('-'). Raises FileNotFoundError,
    PermissionError, IsADirectoryError, or UnicodeDecodeError on bad input — callers
    should catch these and print a friendly message rather than letting them crash."""
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as f:
        return f.read()


def _read_asset_criticality(path: str) -> dict[str, int]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object of {{ip_or_host: weight}}, got {type(data).__name__}")
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description="SOC Analyst Agent toolkit — end-to-end triage pipeline")
    ap.add_argument("input", help="Path to a log/alert file, or '-' to read from stdin")
    ap.add_argument("--assets", help="Optional JSON file mapping IP/hostname -> criticality weight (int)")
    ap.add_argument("--json", action="store_true", help="Print full JSON result instead of just the summary")
    ap.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ERROR (default: INFO or $SOC_TOOLKIT_LOG_LEVEL)")
    args = ap.parse_args()

    configure_logging(args.log_level)

    try:
        raw_input = _read_input(args.input)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except PermissionError:
        print(f"Error: permission denied reading: {args.input}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except IsADirectoryError:
        print(f"Error: expected a file but got a directory: {args.input}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except UnicodeDecodeError:
        print(f"Error: could not decode {args.input} as UTF-8 text — is this a binary file?", file=sys.stderr)
        return EXIT_INPUT_ERROR

    if not raw_input.strip():
        print(f"Error: {args.input} is empty — nothing to triage.", file=sys.stderr)
        return EXIT_INPUT_ERROR

    asset_criticality = None
    if args.assets:
        try:
            asset_criticality = _read_asset_criticality(args.assets)
        except FileNotFoundError:
            print(f"Error: assets file not found: {args.assets}", file=sys.stderr)
            return EXIT_INPUT_ERROR
        except json.JSONDecodeError as exc:
            print(f"Error: {args.assets} is not valid JSON ({exc})", file=sys.stderr)
            return EXIT_INPUT_ERROR
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_INPUT_ERROR

    try:
        result = run_pipeline(raw_input, asset_criticality=asset_criticality)
    except Exception:
        logger.exception("Pipeline failed")
        print("Error: the triage pipeline failed unexpectedly — see logs above for details.", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(result["summary"])
        print(f"\n({len(result['alerts'])} deduped alerts — run with --json for full detail)")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
