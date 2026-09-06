"""
tui.py — Interactive terminal UI for SOC Agent Toolkit.
"""

from __future__ import annotations

import shlex
import shutil
import time

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from .cli import build_parser

console = Console()


ASCII_LOGO = r"""
   ███████╗ ██████╗  ██████╗
   ██╔════╝██╔═══██╗██╔════╝
   ███████╗██║   ██║██║
   ╚════██║██║   ██║██║
   ███████║╚██████╔╝╚██████╗
   ╚══════╝ ╚═════╝  ╚═════╝
"""


AUTHOR = "by: ByteBreakerGhost / Maulana Yasyfa'u Al Azhiim Yudho Leksono"


def _status_table() -> Table:
    """Create the component status table."""
    table = Table(
        box=box.SIMPLE,
        expand=True,
        show_header=True,
        padding=(0, 1),
    )

    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Description")

    table.add_row(
        "SOC Engine",
        "[green]● ONLINE[/green]",
        "Core analysis pipeline",
    )

    table.add_row(
        "MITRE ATT&CK",
        "[green]● READY[/green]",
        "Technique mapping",
    )

    table.add_row(
        "IOC Enrichment",
        "[green]● READY[/green]",
        "IP / domain / hash reputation",
    )

    table.add_row(
        "AI",
        "[yellow]● CONFIGURE[/yellow]",
        "Anthropic API key required",
    )

    return table


def _commands_text() -> Text:
    """Create command help text."""
    text = Text()

    commands = [
        ("analyze <file>", "Analyze security alerts"),
        ('mitre "<text>"', "Map text to MITRE ATT&CK"),
        ("enrich-ip <ip>", "Check IP reputation"),
        ("enrich-domain <domain>", "Check domain reputation"),
        ("enrich-hash <hash>", "Check file hash reputation"),
        ("version", "Show version"),
        ("help", "Show commands"),
        ("exit", "Exit"),
    ]

    for command, description in commands:
        text.append(f"  {command:<28}", style="bold green")
        text.append(f"{description}\n")

    return text

def _footer() -> Text:
    """Create the small bottom-right author footer."""
    footer = Text(
        AUTHOR,
        style="dim",
        justify="right",
    )
    return footer

def startup_animation() -> None:
    """Display startup animation before showing the main interface."""
    console.clear()

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            "Initializing SOC Engine...",
            total=None,
        )
        time.sleep(0.4)

        progress.update(
            task,
            description="Loading MITRE ATT&CK..."
        )
        time.sleep(0.4)

        progress.update(
            task,
            description="Checking IOC Enrichment..."
        )
        time.sleep(0.4)

        progress.update(
            task,
            description="Checking AI configuration..."
        )
        time.sleep(0.4)

        progress.update(
            task,
            description="[green]SOC Agent ready[/green]"
        )
        time.sleep(0.5)

def show_banner() -> None:
    """Display the main SOC Agent Toolkit interface."""
    console.clear()

    terminal_width = shutil.get_terminal_size((100, 30)).columns
    panel_width = max(70, min(terminal_width - 2, 120))

    logo = Text(ASCII_LOGO)
    logo.justify = "center"

    title = Text()
    title.append("SOC AGENT TOOLKIT\n", style="bold cyan")
    title.append(
        "AI-Assisted Security Operations",
        style="dim",
    )
    title.justify = "center"

    status_title = Text("SYSTEM STATUS", style="bold cyan")
    status_title.justify = "left"

    commands_title = Text("AVAILABLE COMMANDS", style="bold cyan")
    commands_title.justify = "left"

    content = Group(
        title,
        Text(""),
        logo,
        Text(""),
        status_title,
        _status_table(),
        Text(""),
        commands_title,
        _commands_text(),
        Text(""),
        _footer(),
    )

    console.print(
        Panel(
            content,
            border_style="cyan",
            box=box.ROUNDED,
            width=panel_width,
            padding=(1, 2),
        )
    )


def run_interactive() -> None:
    """Run the interactive SOC Agent terminal."""
    startup_animation()
    show_banner()

    parser = build_parser()

    while True:
        try:
            command = console.input(
                "\n[bold cyan]soc-agent[/bold cyan] > "
            ).strip()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]Goodbye.[/cyan]")
            break

        if not command:
            continue

        if command in {"exit", "quit"}:
            console.print("[cyan]Goodbye.[/cyan]")
            break

        if command == "help":
            show_banner()
            continue

        if command == "clear":
            show_banner()
            continue

        try:
            argv = shlex.split(command)
        except ValueError as exc:
            console.print(
                f"[red]Input error:[/red] {exc}"
            )
            continue

        try:
            args = parser.parse_args(argv)
            result = args.func(args)

            if result != 0:
                console.print(
                    f"[red]Command exited with code {result}[/red]"
                )

        except SystemExit:
            # argparse uses SystemExit for --help and argument errors.
            continue

        except Exception as exc:
            console.print(
                f"[red]Command failed:[/red] {exc}"
            )

if __name__ == "__main__":
    run_interactive()
