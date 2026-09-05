# soc_agent_toolkit

A modular Python toolkit of callable functions ("tools") for a **SOC Analyst
AI Agent**. Same shape as `recon-ai`: plain Python functions, no framework
lock-in, usable directly, via CLI, or exposed as Claude tool-use functions.

## Pipeline

```
raw alerts/logs (JSON / CEF / syslog)
        │  parser.parse_alerts()
        ▼
normalized alerts
        │  mitre.enrich_alert_with_mitre()   -> tags ATT&CK technique(s)
        ▼
        │  enrichment.enrich_alert()          -> IP/domain/hash reputation
        ▼
        │  triage.triage_alerts()             -> dedup + score + P1-P4 tier
        ▼
        │  summarizer.summarize_incident()    -> Claude-written incident writeup
        ▼
   analyst-ready summary
```

## Modules

| Module | Purpose |
|---|---|
| `parser.py` | Normalize JSON / CEF / syslog input into one alert schema (robust CEF extension parser — handles escaped `=`, `\`, spaces in values) |
| `mitre.py` | MITRE ATT&CK mapping: fast offline keyword heuristic, or optional real-STIX-dataset matching |
| `enrichment.py` | IP/domain/hash reputation via AbuseIPDB, VirusTotal, OTX — cached, config-driven scoring |
| `enrichment_async.py` | Same enrichment, concurrent (httpx) for large alert batches |
| `triage.py` | Windowed + fuzzy dedup, priority scoring (0-100), P1-P4 tiering |
| `summarizer.py` | Claude-generated incident summary (with offline fallback) |
| `schemas.py` | Claude `tools=[...]` JSON schemas + dispatcher for each function |
| `agent.py` | `run_pipeline()` (deterministic) and `run_agent()` (full agentic loop) |
| `cli.py` | `python -m soc_agent_toolkit.cli alerts.log` — friendly errors, exit codes |
| `config.py` | Every tunable (model name, scoring weights, cache TTL, dedup window) in one place, env-var overridable |
| `cache.py` | In-memory TTL cache for enrichment lookups (optional Redis backend via `SOC_REDIS_URL`) |
| `models.py` | `Alert` dataclass — validates severity range, IP format, required fields before triage/enrichment |
| `logging_setup.py` | Structured logging (`SOC_TOOLKIT_LOG_LEVEL` env var) used across every module |
| `tests/` | pytest unit tests — CEF edge cases, dedup logic, alert validation |

## Changelog — code review fixes

| # | Area | What changed |
|---|---|---|
| 1 | MITRE mapping | `mitre.map_technique_stix()` optionally downloads and matches against the real ATT&CK Enterprise STIX bundle (cached to disk); `enrich_alert_with_mitre(alert, use_stix=True)` uses it and falls back to the keyword heuristic automatically if unavailable. |
| 2 | CEF parsing | Rewrote extension parsing as `parse_cef_extension()` — a marker-based parser instead of a single greedy regex, correctly handling escaped `\=`/`\\`/`\n` and bare `=` inside values. 12 unit tests in `tests/test_parser.py` cover the edge cases. |
| 3 | Enrichment scoring | All weights (VT vote weight, OTX pulse weight, verdict thresholds) moved to `config.py` with the rationale documented next to each constant, and made env-var tunable. |
| 4 | Caching | `cache.py` — TTL cache (in-memory by default, Redis if `SOC_REDIS_URL` is set) wraps every `enrich_ip`/`enrich_domain`/`enrich_hash` call. Error responses aren't cached, so outages don't "stick". |
| 5 | Logging | `logging_setup.py` + `logger = get_logger(__name__)` in every module; replaces ad-hoc prints and JSON-string errors with real structured log records. |
| 6 | CLI error handling | `cli.py` wraps file I/O in try/except (missing file, permission denied, directory, bad encoding, invalid JSON) with friendly messages and distinct exit codes instead of a raw traceback. |
| 7 | Model name hardcoded | Single `config.ANTHROPIC_MODEL` (env var `SOC_TOOLKIT_MODEL`) used by both `agent.py` and `summarizer.py`. |
| 8 | Input validation | `models.py` — `Alert` dataclass validates severity range, required fields, and IP format; `parser.parse_alerts()` runs every alert through it and drops (with a logged warning) anything malformed. |
| 9 | Deduplication | `triage.dedup_alerts()` now requires alerts to be within `config.DEDUP_TIME_WINDOW_MINUTES` of each other AND fuzzy-matches signatures (`difflib`, threshold in config) instead of an exact-string/no-time-limit fingerprint. |
| 10 | No async I/O | `enrichment_async.py` — `httpx`-based concurrent enrichment (`enrich_alerts_batch_async`), bounded by `config.ASYNC_ENRICHMENT_CONCURRENCY`, dedupes shared IOCs across a batch before looking them up. |

## Setup

```bash
pip install -r requirements.txt

# Set whichever of these you have — every module degrades gracefully without them:
export ANTHROPIC_API_KEY=...      # for AI-written summaries / the agentic loop
export ABUSEIPDB_API_KEY=...      # IP reputation
export VT_API_KEY=...             # IP / domain / hash reputation (VirusTotal)
export OTX_API_KEY=...            # IP / domain pulses (AlienVault OTX)
```

Without any keys, `parser`, `mitre`, and `triage` still run fully offline;
`enrichment` returns `"note": "No reputation API keys configured"` instead of
guessing; `summarizer` falls back to a deterministic template summary.

## Quick start

```bash
# Deterministic pipeline from the CLI
python -m soc_agent_toolkit.cli sample_alerts.cef --json

# Or from Python
from soc_agent_toolkit.agent import run_pipeline
result = run_pipeline(raw_cef_or_json_text, asset_criticality={"10.0.0.12": 15})
print(result["summary"])
```

## Wiring into a Claude agent

```python
from soc_agent_toolkit.schemas import TOOLS, dispatch_tool_json
# Pass TOOLS as the `tools=` param in a client.messages.create() call, and
# route any resulting tool_use blocks through dispatch_tool_json(name, input).
# See agent.run_agent() for a full working loop.
```

## Running tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Extending

- Add more ATT&CK keyword rules in `mitre.SIGNATURE_KEYWORDS`, or swap in the
  real MITRE STIX/ATT&CK Navigator dataset for exact coverage.
- Add another enrichment provider by following the pattern in
  `enrichment.enrich_ip` (env var key -> `_get_json` call -> merge into `scores`).
- Tune `triage.score_alert()` weights to match your environment's noise profile.
- `asset_criticality` lets you weight your crown-jewel hosts/IPs higher without
  touching the scoring logic.

## Notes

- This toolkit is defensive/triage tooling only — it does not perform any
  offensive actions (no auto-blocking, no auto-isolation). Wire its output
  into your SOAR/ticketing system for that.
- No API keys are hardcoded anywhere; all providers read from environment
  variables at call time.
