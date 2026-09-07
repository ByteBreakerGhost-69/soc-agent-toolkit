"""Version command."""

from argparse import Namespace

from rich.console import Console

console = Console()

VERSION = "0.1.0"


def cmd_version(_: Namespace) -> int:
    """Print the CLI version."""
    console.print(f"SOC Agent Toolkit v{VERSION}")
    return 0
