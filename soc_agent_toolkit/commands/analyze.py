"""Analyze command."""

from __future__ import annotations

import json
import sys
from argparse import Namespace

from rich.console import Console
from rich.progress import Progress, TextColumn

from ..logging_setup import configure_logging, get_logger

logger = get_logger(__name__)
console = Console()

EXIT_OK = 0
EXIT_INPUT_ERROR = 2
EXIT_RUNTIME_ERROR = 3

def cmd_analyze(
    args: Namespace,
    *,
    read_input,
    read_asset_criticality,
    pipeline_runner,
    analysis_renderer,
) -> int:
    """Run the SOC analysis pipeline."""
    configure_logging(args.log_level or "WARNING")

    try:
        raw_input = read_input(args.input)
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
            asset_criticality = read_asset_criticality(args.assets)
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

    # Run the actual SOC pipeline.
    try:
        with Progress(
            TextColumn("{task.description}"),
            transient=False,
            console=Console(stderr=True),
        ) as progress:

            current_task: int | None = None

            def update_progress(message: str) -> None:
                nonlocal current_task

                # Complete the previous stage.
                if current_task is not None:
                    previous_description = progress.tasks[
                        current_task
                    ].description

                    previous_description = (
                        previous_description
                        .replace("[cyan]⠋[/cyan] ", "")
                        .replace("[green]✓[/green] ", "")
                    )

                    progress.update(
                        current_task,
                        description=(
                            f"[green]✓[/green] "
                            f"{previous_description}"
                        ),
                        completed=1,
                    )

                # Start the new stage.
                current_task = progress.add_task(
                    f"[cyan]⠋[/cyan] {message}",
                    total=1,
                    completed=0,
                )

            result = pipeline_runner(
                raw_input,
                asset_criticality=asset_criticality,
                progress_callback=update_progress,
            )

            # Complete the final stage.
            if current_task is not None:
                final_description = progress.tasks[
                    current_task
                ].description

                final_description = (
                    final_description
                    .replace("[cyan]⠋[/cyan] ", "")
                    .replace("[green]✓[/green] ", "")
                )

                progress.update(
                    current_task,
                    description=(
                        f"[green]✓[/green] "
                        f"{final_description}"
                    ),
                    completed=1,
                )

    except Exception:
        logger.exception("Pipeline failed")

        print(
            "Error: the triage pipeline failed unexpectedly.",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR

    # JSON mode stays machine-readable.
    if args.json:
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                default=str,
            )
        )
        return EXIT_OK

    return analysis_renderer(result)


def make_cmd_analyze(
    *,
    read_input,
    read_asset_criticality,
    pipeline_runner,
    analysis_renderer,
):
    """Create the parser-compatible analyze command handler."""
    def _cmd(args: Namespace) -> int:
        return cmd_analyze(
            args,
            read_input=read_input,
            read_asset_criticality=read_asset_criticality,
            pipeline_runner=pipeline_runner,
            analysis_renderer=analysis_renderer,
        )

    return _cmd
