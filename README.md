# SOC Agent Toolkit

**AI-assisted SOC alert triage and incident analysis toolkit for the command line.**

[![PyPI version](https://img.shields.io/pypi/v/soc-agent-toolkit.svg)](https://pypi.org/project/soc-agent-toolkit/)
[![Python](https://img.shields.io/pypi/pyversions/soc-agent-toolkit.svg)](https://pypi.org/project/soc-agent-toolkit/)
[![PyPI downloads](https://img.shields.io/pypi/dm/soc-agent-toolkit.svg)](https://pypi.org/project/soc-agent-toolkit/)
[![Publish to PyPI](https://github.com/ByteBreakerGhost-69/soc-agent-toolkit/actions/workflows/publish.yml/badge.svg)](https://github.com/ByteBreakerGhost-69/soc-agent-toolkit/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SOC Agent Toolkit is a modular Python CLI for terminal-based security operations. It parses and normalizes alerts, maps events to MITRE ATT&CK techniques, enriches indicators of compromise (IOCs), deduplicates related alerts, prioritizes incidents, and produces analyst-ready summaries.

Designed for **Linux, WSL, macOS, Windows PowerShell, and Windows CMD**.

> **Defensive security only.** Use this project only with systems, logs, domains, IPs, and files you are authorized to investigate.

## What it does

```text
                    Security Alerts
                           │
                           ▼
                 ┌──────────────────┐
                 │      Parser      │
                 │ JSON / CEF /     │
                 │      Syslog      │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   MITRE ATT&CK   │
                 │      Mapping     │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │  IOC Enrichment  │
                 │ IP / Domain /    │
                 │      Hash        │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Deduplication +  │
                 │ Priority Scoring │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Incident Summary │
                 │ AI / Deterministic│
                 └──────────────────┘
```

## Features

- **Multi-format parsing** — JSON, CEF, and syslog
- **MITRE ATT&CK mapping** — heuristic technique matching with optional STIX-based matching
- **IOC enrichment** — IP, domain, and file-hash reputation through configured threat-intelligence providers
- **Smart deduplication** — fuzzy signature matching with a configurable time window
- **Priority scoring** — 0–100 score with P1–P4 priority tiers
- **Asset criticality weighting** — increases priority for important assets
- **AI incident summaries** — Claude-powered summaries with a deterministic offline fallback
- **Interactive terminal UI** — Rich-based interface with status, commands, and progress
- **Live pipeline progress** — parsing, mapping, enrichment, triage, and summarization stages
- **Machine-readable JSON** — useful for scripts and automation
- **CLI-first design** — built for terminal workflows
- **Defensive-only behavior** — no automatic blocking, isolation, or production changes

## Installation

### From PyPI

```bash
python -m pip install soc-agent-toolkit
```

Then verify the installation:

```bash
soc-agent version
```

Launch the interactive terminal UI:

```bash
soc-agent
```

### From source

```bash
git clone https://github.com/ByteBreakerGhost-69/soc-agent-toolkit.git
cd soc-agent-toolkit
python -m venv .venv
```

Linux / WSL / macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Windows CMD:

```cmd
.venv\Scripts\activate
```

Install in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

## Quick Start

Analyze the included example alerts:

```bash
soc-agent analyze alerts.json
```

Return machine-readable JSON:

```bash
soc-agent analyze alerts.json --json
```

Analyze from stdin:

```bash
cat alerts.json | soc-agent analyze -
```

Map text to MITRE ATT&CK:

```bash
soc-agent mitre "SSH brute force login attempt"
```

Check an IP reputation:

```bash
soc-agent enrich-ip 8.8.8.8
```

Check a domain reputation:

```bash
soc-agent enrich-domain example.com
```

Check a file hash reputation:

```bash
soc-agent enrich-hash 44d88612fea8a8f36de82e1278abb02f
```

Show all CLI options:

```bash
soc-agent --help
```

## Example Usage

The repository includes [`alerts.json`](alerts.json) so you can try the full pipeline immediately after installation.

Example input:

```json
[
  {
    "timestamp": "2025-01-01T10:00:00Z",
    "src_ip": "10.0.0.12",
    "dest_ip": "192.168.1.20",
    "signature": "Suspicious PowerShell Execution",
    "severity": 8,
    "message": "Encoded PowerShell command executed on endpoint"
  },
  {
    "timestamp": "2025-01-01T10:10:00Z",
    "src_ip": "203.0.113.5",
    "dest_ip": "10.0.0.12",
    "signature": "SSH Brute Force Login Attempt",
    "severity": 9,
    "message": "Multiple failed SSH login attempts for admin account"
  }
]
```

Run:

```bash
soc-agent analyze alerts.json
```

The resulting workflow is:

```text
Raw alerts
   ↓
Normalized events
   ↓
MITRE ATT&CK techniques
   ↓
IOC reputation evidence
   ↓
Deduplicated alerts
   ↓
Priority score + P1–P4
   ↓
Incident summary
```

For automation:

```bash
soc-agent analyze alerts.json --json > result.json
```

## Interactive TUI

Running `soc-agent` without arguments opens the interactive terminal interface.

Available commands include:

```text
analyze <file>              Analyze security alerts
mitre "<text>"              Map text to MITRE ATT&CK
enrich-ip <ip>              Check IP reputation
enrich-domain <domain>      Check domain reputation
enrich-hash <hash>          Check file hash reputation
version                     Show version
help                        Show commands
exit                        Exit
```

The interface shows toolkit status and pipeline progress during analysis.

## Alert Analysis Pipeline

For an alert analysis request, the toolkit processes events through:

```text
Parse
  ↓
MITRE ATT&CK mapping
  ↓
IOC enrichment
  ↓
Deduplication
  ↓
Priority scoring
  ↓
Incident summary
```

Asset criticality can also be supplied to influence the final priority score:

```json
{
  "10.0.0.12": 15,
  "10.0.0.20": 10
}
```

```bash
soc-agent analyze alerts.json --assets assets.json
```

## JSON Automation

The `--json` mode is designed for shell pipelines and automation:

```bash
soc-agent analyze alerts.json --json > result.json
```

Because progress output is kept separate from the structured result, the JSON output can be consumed by other tools without mixing progress messages into the payload.

## MITRE ATT&CK Mapping

```bash
soc-agent mitre "SSH brute force login attempt"
```

Example result:

```text
MITRE ATT&CK Matches
====================
T1110 — Brute Force
Tactic: Credential Access
```

## IOC Enrichment

Supported indicator types:

| Indicator | Command |
| --- | --- |
| IP address | `soc-agent enrich-ip <ip>` |
| Domain | `soc-agent enrich-domain <domain>` |
| File hash | `soc-agent enrich-hash <hash>` |

Supported hash inputs include **MD5, SHA-1, and SHA-256**.

When a reputation provider is unavailable, the toolkit reports `unknown` rather than inventing reputation data.

## Threat Intelligence Providers

The toolkit can use the following external services when configured:

- AbuseIPDB
- VirusTotal
- AlienVault OTX
- Anthropic Claude for AI-generated incident summaries

Environment variables:

```text
ABUSEIPDB_API_KEY
VT_API_KEY
OTX_API_KEY
ANTHROPIC_API_KEY
```

Linux / WSL / macOS:

```bash
export VT_API_KEY="YOUR_KEY"
export ABUSEIPDB_API_KEY="YOUR_KEY"
export OTX_API_KEY="YOUR_KEY"
export ANTHROPIC_API_KEY="YOUR_KEY"
```

Windows PowerShell:

```powershell
$env:VT_API_KEY="YOUR_KEY"
$env:ABUSEIPDB_API_KEY="YOUR_KEY"
$env:OTX_API_KEY="YOUR_KEY"
$env:ANTHROPIC_API_KEY="YOUR_KEY"
```

**Never commit API keys, tokens, passwords, or secret `.env` files to GitHub.**

## Offline Behavior

External enrichment is optional. Without reputation API keys, unavailable reputation evidence is represented as `unknown`.

Without Claude, the toolkit uses a deterministic offline incident-summary fallback so the core parsing, MITRE mapping, deduplication, triage, and scoring flow can continue without an AI API call.

## Priority Model

Alerts receive a score from **0–100** and one of four priority levels:

```text
P1 — Critical
P2 — High
P3 — Medium
P4 — Low
```

The scoring model can incorporate factors such as alert severity, repeated occurrences, IOC reputation, MITRE ATT&CK matches, and asset criticality.

## Project Structure

```text
soc-agent-toolkit/
├── soc_agent_toolkit/
│   ├── __init__.py
│   ├── agent.py
│   ├── cache.py
│   ├── cli.py
│   ├── config.py
│   ├── enrichment.py
│   ├── enrichment_async.py
│   ├── logging_setup.py
│   ├── mitre.py
│   ├── models.py
│   ├── parser.py
│   ├── schemas.py
│   ├── summarizer.py
│   ├── triage.py
│   └── tui.py
├── tests/
├── alerts.json
├── pyproject.toml
├── LICENSE
├── .gitignore
└── README.md
```

### Core modules

| Module | Purpose |
| --- | --- |
| `parser.py` | Normalize JSON / CEF / syslog alerts |
| `mitre.py` | MITRE ATT&CK technique mapping |
| `enrichment.py` | IP / domain / hash reputation lookups |
| `enrichment_async.py` | Concurrent enrichment |
| `triage.py` | Deduplication and priority scoring |
| `summarizer.py` | AI and offline incident summaries |
| `schemas.py` | Tool definitions and dispatcher |
| `agent.py` | End-to-end analysis pipeline and agentic loop |
| `cli.py` | Command-line interface |
| `tui.py` | Interactive Rich terminal interface |
| `config.py` | Configurable scoring and toolkit settings |

## Development

Install development dependencies as needed for your environment, then run the test suite:

```bash
pytest -q
```

Useful validation commands:

```bash
python -m compileall -q soc_agent_toolkit
git diff --check
```

## Design Principles

### Defensive by design

The toolkit analyzes, enriches, prioritizes, and summarizes security events. It does not automatically block IP addresses, isolate endpoints, or modify production systems.

### Evidence over guessing

When reputation information is unavailable, the toolkit reports `unknown` instead of inventing a verdict.

### Deterministic core

The security pipeline is designed to remain inspectable and reproducible, while AI is used for analyst-facing natural-language summaries.

### CLI-first

The project is intended to fit naturally into terminal-based SOC workflows and automation pipelines.

## Roadmap

- Expand MITRE ATT&CK coverage
- Add more threat-intelligence providers
- Increase automated test coverage
- Improve AI-assisted analyst workflows
- Add richer operational documentation and examples

## Security

Please do not use this project to access, scan, or modify systems without authorization.

For security-sensitive issues, please avoid publishing credentials or exploit details in a public issue. Use the repository's supported private reporting path when available.

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE).

## Author

**Maulana Yasyfa’u Al Azhiim Yudho Leksono**

GitHub: https://github.com/ByteBreakerGhost-69

Project: https://github.com/ByteBreakerGhost-69/soc-agent-toolkit
