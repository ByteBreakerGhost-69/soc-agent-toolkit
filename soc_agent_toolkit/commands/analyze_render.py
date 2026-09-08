"""Human-readable rendering for analysis results."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def render_analysis_result(result: dict) -> int:
    """Render a completed analysis result."""
    alerts = result.get("alerts", [])

    counts = {
        tier: sum(
            1
            for alert in alerts
            if alert.get("priority_tier") == tier
        )
        for tier in ("P1", "P2", "P3", "P4")
    }

    status = Table(
        box=box.SIMPLE,
        expand=True,
    )

    status.add_column("Metric", style="bold")
    status.add_column("Value")

    status.add_row("Alerts analyzed", str(len(alerts)))
    status.add_row("P1 Critical", str(counts["P1"]))
    status.add_row("P2 High", str(counts["P2"]))
    status.add_row("P3 Medium", str(counts["P3"]))
    status.add_row("P4 Low", str(counts["P4"]))

    console.print(
        Panel(
            status,
            title="ANALYSIS COMPLETE",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    if alerts:
        top = alerts[0]

        incident = Table(
            box=box.SIMPLE,
            expand=True,
        )

        incident.add_column(
            "Field",
            style="bold",
            width=18,
        )
        incident.add_column("Value")

        incident.add_row(
            "Signature",
            str(top.get("signature", "Unknown")),
        )
        incident.add_row(
            "Priority",
            str(top.get("priority_tier", "Unknown")),
        )
        incident.add_row(
            "Score",
            str(top.get("priority_score", "Unknown")),
        )
        incident.add_row(
            "Source",
            str(top.get("src_ip", "Unknown")),
        )
        incident.add_row(
            "Target",
            str(top.get("dest_ip", "Unknown")),
        )

        mitre_matches = top.get("mitre", [])

        if mitre_matches:
            mitre_text = ", ".join(
                f"{item.get('technique_id')} — "
                f"{item.get('technique')}"
                for item in mitre_matches
            )
        else:
            mitre_text = "No MITRE technique matched"

        incident.add_row(
            "MITRE ATT&CK",
            mitre_text,
        )

        console.print(
            Panel(
                incident,
                title="TOP INCIDENT",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )

    console.print(
        Panel(
            result.get(
                "summary",
                "No incident summary available.",
            ),
            title="INCIDENT SUMMARY",
            border_style="blue",
            box=box.ROUNDED,
        )
    )

    console.print(
        f"[dim]{len(alerts)} deduped alerts — "
        "use --json for machine-readable output[/dim]"
    )

    return 0
