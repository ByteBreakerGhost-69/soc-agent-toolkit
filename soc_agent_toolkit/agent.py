"""
agent.py — Example SOC Analyst Agent loop.

Two ways to use this toolkit:

1. DIRECT PIPELINE (no LLM tool-calling, fastest/cheapest — see `run_pipeline`):
   parse -> mitre-tag -> enrich -> triage -> summarize (Claude only used for
   the final natural-language summary).

2. AGENTIC LOOP (`run_agent`): hands the raw alert text + a task prompt to
   Claude with the full TOOLS list and lets the model decide which tools to
   call and in what order.

Set ANTHROPIC_API_KEY in the environment before using run_agent() or the
AI-generated summary in run_pipeline().
"""

from __future__ import annotations

import json
import os
from typing import Any

from . import config, enrichment, mitre, parser, summarizer, triage
from .logging_setup import get_logger
from .schemas import TOOLS, dispatch_tool_json

logger = get_logger(__name__)

try:
    import anthropic
except ImportError:  # pragma: no cover
    anthropic = None


def run_pipeline(
    raw_input: str,
    asset_criticality: dict[str, int] | None = None,
    use_stix_mitre: bool = False,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    """Deterministic end-to-end run:
    parse -> MITRE tag -> enrich -> triage -> summarize.
    """

    def report_progress(message: str) -> None:
        if progress_callback is not None:
            progress_callback(message)

    logger.info("Starting SOC pipeline run")

    report_progress("Parsing alerts...")
    alerts = parser.parse_alerts(raw_input)

    report_progress("Mapping MITRE ATT&CK...")
    alerts = [
        mitre.enrich_alert_with_mitre(
            alert,
            use_stix=use_stix_mitre,
        )
        for alert in alerts
    ]

    report_progress("Enriching IOCs...")
    alerts = [
        enrichment.enrich_alert(alert)
        for alert in alerts
    ]

    report_progress("Running triage...")
    triaged = triage.triage_alerts(
        alerts,
        asset_criticality,
    )

    report_progress("Generating incident summary...")
    summary = summarizer.summarize_incident(triaged)

    report_progress("Analysis complete")

    logger.info(
        "Pipeline run complete: %d alert(s) triaged",
        len(triaged),
    )

    return {
        "alerts": triaged,
        "summary": summary,
    }


def run_agent(user_task: str, max_turns: int = 6) -> str:
    """
    Let Claude drive the tool-calling loop itself.

    Example:
        "Here are today's alerts: <raw text>. Triage them, enrich any IOCs,
        and give me a summary with next actions."
    """

    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key or anthropic is None:
        raise RuntimeError(
            "run_agent() requires ANTHROPIC_API_KEY and the `anthropic` package. "
            "Use run_pipeline() for the offline-friendly, deterministic path instead."
        )

    client = anthropic.Anthropic(api_key=api_key)

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": user_task,
        }
    ]

    for turn in range(max_turns):
        logger.debug(
            "Agent turn %d/%d",
            turn + 1,
            max_turns,
        )

        response = client.messages.create(
            model=config.ANTHROPIC_MODEL,
            max_tokens=2000,
            tools=TOOLS,
            messages=messages,
        )

        messages.append(
            {
                "role": "assistant",
                "content": response.content,
            }
        )

        if response.stop_reason != "tool_use":
            return "\n".join(
                block.text
                for block in response.content
                if getattr(block, "type", None) == "text"
            )

        tool_results = []

        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                logger.info(
                    "Agent calling tool: %s(%s)",
                    block.name,
                    block.input,
                )

                try:
                    result_json = dispatch_tool_json(
                        block.name,
                        block.input,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "Tool %s failed",
                        block.name,
                    )
                    result_json = json.dumps(
                        {
                            "error": str(exc),
                        }
                    )

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result_json,
                    }
                )

        messages.append(
            {
                "role": "user",
                "content": tool_results,
            }
        )

    logger.warning(
        "Agent reached max_turns=%d without a final answer",
        max_turns,
    )

    return (
        "Reached max_turns without a final answer — "
        "inspect `messages` for partial progress."
    )


if __name__ == "__main__":
    sample_alerts = """
    CEF:0|PaloAlto|NGFW|10.1|1001|Brute Force Login Attempt|8|src=203.0.113.5 dst=10.0.0.12 duser=admin msg=Multiple failed SSH logins
    CEF:0|PaloAlto|NGFW|10.1|1002|Possible C2 Beacon|7|src=10.0.0.12 dst=198.51.100.9 msg=Periodic beacon to external host
    """.strip()

    result = run_pipeline(
        sample_alerts,
        asset_criticality={"10.0.0.12": 15},
    )

    print(result["summary"])
