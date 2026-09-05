"""
logging_setup.py — One place to configure structured logging for the whole
toolkit. Every module does `logger = logging.getLogger(__name__)` and relies
on the caller (CLI, agent runner, or the host application) to have called
`configure_logging()` once at startup — libraries shouldn't call
`basicConfig()` themselves, or they'll clobber the host app's logging config.
"""

from __future__ import annotations

import logging
import os
import sys

_CONFIGURED = False


def configure_logging(level: str | None = None) -> None:
    """
    Configure root logging once. Safe to call multiple times (no-op after
    the first). Level can come from SOC_TOOLKIT_LOG_LEVEL env var, an
    explicit argument, or defaults to INFO.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = level or os.environ.get("SOC_TOOLKIT_LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, level_name.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper — ensures logging is configured before handing back a logger."""
    configure_logging()
    return logging.getLogger(name)
