"""
soc_agent_toolkit
==================

A modular Python toolkit of callable functions ("tools") for a SOC Analyst
AI Agent. Each module exposes plain Python functions that can be:

  1. Called directly from Python / a CLI (see cli.py), or
  2. Exposed as Claude tool-use functions (see schemas.py + agent.py)

Pipeline covered (end-to-end):
    raw alerts/logs -> parse -> dedup & prioritize (triage)
                     -> enrich IOCs (reputation + MITRE ATT&CK)
                     -> AI-generated incident summary
"""

from . import parser, triage, enrichment, mitre, summarizer, schemas

__all__ = ["parser", "triage", "enrichment", "mitre", "summarizer", "schemas"]
