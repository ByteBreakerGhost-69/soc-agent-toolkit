"""Version command."""

from argparse import Namespace
from importlib.metadata import PackageNotFoundError, version as package_version

from rich.console import Console

console = Console()

try:
    VERSION = package_version("soc-agent-toolkit")
except PackageNotFoundError:
    VERSION = "unknown"


def cmd_version(_: Namespace) -> int:
    """Print the CLI version."""
    console.print(f"SOC Agent Toolkit v{VERSION}")
    return 0
