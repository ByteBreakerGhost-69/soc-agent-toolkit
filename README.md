# SOC Agent Toolkit

A modular Python toolkit for SOC (Security Operations Center) analyst workflows — parse raw alerts, tag them with MITRE ATT&CK techniques, enrich indicators of compromise (IOCs), deduplicate and prioritize, and generate analyst-ready incident summaries. Usable directly in Python, via CLI, or wired in as Claude tool-use functions for a fully agentic triage loop.

## Pipeline

```
raw alerts/logs (JSON / CEF / syslog)
        │  parser.parse_alerts()
        ▼
normalized alerts
        │  mitre.enrich_alert_with_mitre()   → tags ATT&CK technique(s)
        ▼
        │  enrichment.enrich_alert()          → IP/domain/hash reputation
        ▼
        │  triage.triage_alerts()             → dedup + score + P1–P4 tier
        ▼
        │  summarizer.summarize_incident()    → Claude-written incident writeup
        ▼
   analyst-ready summary
```

## Features

- **Multi-format parsing** — JSON, CEF, and syslog alerts normalized into a single schema
- **MITRE ATT&CK mapping** — offline keyword heuristic, or optional real-STIX-dataset matching
- **IOC enrichment** — IP/domain/hash reputation via AbuseIPDB, VirusTotal, and AlienVault OTX (cached, config-driven scoring)
- **Smart deduplication** — time-windowed + fuzzy signature matching, not just exact-string fingerprints
- **Priority scoring** — 0–100 score mapped to P1–P4 tiers, with per-asset criticality weighting
- **AI incident summaries** — Claude-generated writeups, with a deterministic offline fallback when no API key is set
- **Defensive only** — no auto-blocking or auto-isolation; wire the output into your own SOAR/ticketing system

## Requirements

- Python 3.10+
- See `soc_agent_toolkit/requirements.txt` for dependencies

## Installation

```bash
git clone https://github.com/ByteBreakerGhost-69/soc-agent-toolkit.git
cd soc-agent-toolkit
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r soc_agent_toolkit/requirements.txt
```

## Configuration (all optional)

Every module degrades gracefully without these — set only what you have:

```bash
export ANTHROPIC_API_KEY=...   # AI-written incident summaries + agentic loop
export ABUSEIPDB_API_KEY=...   # IP reputation
export VT_API_KEY=...          # IP / domain / hash reputation (VirusTotal)
export OTX_API_KEY=...         # IP / domain pulses (AlienVault OTX)
```

Without any keys: `parser`, `mitre`, and `triage` run fully offline; `enrichment` reports no reputation data instead of guessing; `summarizer` falls back to a deterministic template summary.

## Usage

**CLI:**
```bash
python -m soc_agent_toolkit.cli alerts.json --json
```

**Python:**
```python
from soc_agent_toolkit.agent import run_pipeline

result = run_pipeline(raw_json_or_cef_text, asset_criticality={"10.0.0.12": 15})
print(result["summary"])
```

**As Claude tools (agentic loop):**
```python
from soc_agent_toolkit.schemas import TOOLS, dispatch_tool_json
# Pass TOOLS as the `tools=` param in a client.messages.create() call, and
# route any resulting tool_use blocks through dispatch_tool_json(name, input).
```

## Project structure

| Module | Purpose |
|---|---|
| `parser.py` | Normalize JSON / CEF / syslog input into one alert schema |
| `mitre.py` | MITRE ATT&CK mapping (heuristic or STIX-dataset matching) |
| `enrichment.py` | IP/domain/hash reputation lookups, cached and config-driven |
| `enrichment_async.py` | Concurrent enrichment for large alert batches |
| `triage.py` | Windowed + fuzzy dedup, priority scoring, P1–P4 tiering |
| `summarizer.py` | Claude-generated incident summary with offline fallback |
| `schemas.py` | Claude `tools=[...]` schemas + dispatcher |
| `agent.py` | Deterministic pipeline and full agentic loop |
| `cli.py` | Command-line entry point |
| `config.py` | All tunables, env-var overridable |
| `models.py` | `Alert` dataclass with validation |
| `tests/` | pytest unit tests |

## Testing

```bash
pip install pytest
python -m pytest soc_agent_toolkit/tests/ -v
```

## License

Add a license of your choice (MIT recommended for portfolio/open-source projects).
