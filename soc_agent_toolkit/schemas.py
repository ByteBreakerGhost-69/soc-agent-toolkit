"""
schemas.py — Anthropic tool-use definitions for the SOC toolkit, plus a
dispatcher so a Claude agent loop (see agent.py) can call them by name.

Each entry in TOOLS follows the Claude API `tools` parameter shape:
https://docs.claude.com/en/docs/build-with-claude/tool-use
"""

from __future__ import annotations

import json
from typing import Any

from . import enrichment, mitre, parser, triage, summarizer
from .logging_setup import get_logger

logger = get_logger(__name__)

TOOLS: list[dict[str, Any]] = [
    {
        "name": "parse_alerts",
        "description": (
            "Parse raw security alerts/logs (JSON, CEF, or syslog text) into a "
            "normalized alert schema. Use this first on any raw SIEM export or "
            "log dump before triage or enrichment."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "raw_input": {
                    "type": "string",
                    "description": "Raw alert text: a JSON blob, or newline-delimited CEF/syslog lines.",
                }
            },
            "required": ["raw_input"],
        },
    },
    {
        "name": "enrich_ip",
        "description": "Look up an IP address's reputation (AbuseIPDB/VirusTotal/OTX, whichever are configured).",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "IPv4 or IPv6 address to look up."}},
            "required": ["ip"],
        },
    },
    {
        "name": "enrich_domain",
        "description": "Look up a domain's reputation (VirusTotal/OTX, whichever are configured).",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Fully qualified domain name."}},
            "required": ["domain"],
        },
    },
    {
        "name": "enrich_hash",
        "description": "Look up a file hash (md5/sha1/sha256) reputation via VirusTotal.",
        "input_schema": {
            "type": "object",
            "properties": {"file_hash": {"type": "string", "description": "md5, sha1, or sha256 hash string."}},
            "required": ["file_hash"],
        },
    },
    {
        "name": "map_mitre_technique",
        "description": "Heuristically map free-text (alert signature/message) to MITRE ATT&CK technique(s).",
        "input_schema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Alert signature and/or message text."}},
            "required": ["text"],
        },
    },
    {
        "name": "triage_alerts",
        "description": (
            "Deduplicate and score a list of normalized alerts (as produced by parse_alerts, "
            "ideally already run through mitre/enrichment). Returns alerts sorted by priority "
            "with a P1-P4 tier on each."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "alerts": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of normalized alert objects.",
                },
                "asset_criticality": {
                    "type": "object",
                    "description": "Optional map of IP/hostname -> extra priority weight (e.g. {'10.0.0.5': 15}).",
                },
            },
            "required": ["alerts"],
        },
    },
    {
        "name": "summarize_incident",
        "description": (
            "Generate a human-readable incident summary (headline, top priority items, "
            "recommended next actions) from a triaged, enriched alert list. Call this last."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "triaged_alerts": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Output of triage_alerts.",
                }
            },
            "required": ["triaged_alerts"],
        },
    },
]


def dispatch_tool(name: str, tool_input: dict[str, Any]) -> Any:
    """Route a Claude tool_use block to the matching Python function."""
    logger.debug("Dispatching tool call: %s", name)
    if name == "parse_alerts":
        return parser.parse_alerts(tool_input["raw_input"])
    if name == "enrich_ip":
        return enrichment.enrich_ip(tool_input["ip"])
    if name == "enrich_domain":
        return enrichment.enrich_domain(tool_input["domain"])
    if name == "enrich_hash":
        return enrichment.enrich_hash(tool_input["file_hash"])
    if name == "map_mitre_technique":
        return mitre.map_technique(tool_input["text"])
    if name == "triage_alerts":
        return triage.triage_alerts(
            tool_input["alerts"], tool_input.get("asset_criticality")
        )
    if name == "summarize_incident":
        return summarizer.summarize_incident(tool_input["triaged_alerts"])
    raise ValueError(f"Unknown tool: {name}")


def dispatch_tool_json(name: str, tool_input: dict[str, Any]) -> str:
    """Same as dispatch_tool but always returns a JSON string (what tool_result content expects)."""
    result = dispatch_tool(name, tool_input)
    if isinstance(result, str):
        return result
    return json.dumps(result, ensure_ascii=False, default=str)
