"""MITRE ATT&CK command."""

from __future__ import annotations

import sys
from argparse import Namespace

from .. import mitre
from ..logging_setup import get_logger

logger = get_logger(__name__)

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 3

def cmd_mitre(args: Namespace) -> int:
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
