"""IOC enrichment commands."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from .. import enrichment
from ..logging_setup import get_logger

logger = get_logger(__name__)

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 3

def cmd_enrich_ip(args: Namespace) -> int:
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


def cmd_enrich_domain(args: Namespace) -> int:
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

def cmd_enrich_hash(args: Namespace) -> int:
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
