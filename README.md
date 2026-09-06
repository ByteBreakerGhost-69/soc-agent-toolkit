# SOC Agent Toolkit

**AI-assisted SOC alert triage and incident analysis toolkit for the command line.**

SOC Agent Toolkit is a modular Python CLI for processing security alerts from the terminal. It normalizes alerts, maps events to MITRE ATT&CK techniques, enriches indicators of compromise (IOCs), deduplicates related alerts, prioritizes incidents, and generates analyst-ready incident summaries.

Designed for **Linux, WSL, macOS, Windows PowerShell, and Windows CMD**.

> Defensive security tooling only. Use it only with systems, logs, domains, IPs, and files you are authorized to investigate.

## Features

- **Multi-format alert parsing** — JSON, CEF, and syslog
- **MITRE ATT&CK mapping** — heuristic mapping with optional STIX-based matching
- **IOC enrichment** — IP, domain, and file-hash reputation through configured threat-intelligence providers
- **Smart deduplication** — fuzzy signature matching with a configurable time window
- **Priority scoring** — scores alerts from 0–100 and assigns P1–P4 tiers
- **Asset criticality weighting** — increases priority for important hosts or assets
- **AI incident summaries** — Claude-powered summaries with an offline deterministic fallback
- **Interactive terminal UI** — logo, system status, command menu, and interactive prompt
- **Live pipeline progress** — visible stages for parsing, MITRE mapping, enrichment, triage, and summarization
- **Machine-readable JSON** — structured output for scripts and automation
- **CLI-first design** — built for terminal and security workflows
- **Defensive only** — no automatic blocking, isolation, or production changes

## Architecture

```text
                 Raw Security Alerts
                         │
                         ▼
                  ┌──────────────┐
                  │    Parser    │
                  │ JSON / CEF / │
                  │    Syslog    │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │    MITRE     │
                  │ ATT&CK Map   │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │     IOC      │
                  │  Enrichment  │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ Deduplication│
                  │  + Scoring   │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ Priority P1  │
                  │    to P4     │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │ AI Incident  │
                  │   Summary    │
                  └──────────────┘
```

## Requirements

- Python **3.10+**
- Git
- Internet access only when using external threat-intelligence providers or Claude

## Installation

### Development / from source

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

Install the package:

```bash
python -m pip install --upgrade pip
pip install -e .
```

The `soc-agent` executable is then available in the active environment.

### Package installation

Once published to PyPI, the intended user experience is:

```bash
pip install soc-agent-toolkit
soc-agent
```

## Interactive TUI

Running `soc-agent` without arguments opens the interactive terminal interface:

```bash
soc-agent
```

Available commands inside the prompt:

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

The interface also displays toolkit status, the author footer, and pipeline progress during analysis.

## CLI Usage

### Help

```bash
soc-agent --help
```

### Analyze alerts

```bash
soc-agent analyze alerts.json
```

The pipeline performs:

```text
Parse
 ↓
MITRE mapping
 ↓
IOC enrichment
 ↓
Deduplication
 ↓
Priority scoring
 ↓
Incident summary
```

### JSON output

```bash
soc-agent analyze alerts.json --json
```

The JSON result is suitable for automation and can be redirected to a file:

```bash
soc-agent analyze alerts.json --json > result.json
```

### Analyze from stdin

```bash
cat alerts.json | soc-agent analyze -
```

This allows SOC Agent Toolkit to be chained with other command-line tools.

### Asset criticality

Create `assets.json`:

```json
{
  "10.0.0.12": 15,
  "10.0.0.20": 10
}
```

Run:

```bash
soc-agent analyze alerts.json --assets assets.json
```

Higher asset criticality increases the priority score of related alerts.

## MITRE ATT&CK Mapping

```bash
soc-agent mitre "SSH brute force login attempt"
```

Example:

```text
MITRE ATT&CK Matches
====================
T1110 — Brute Force
Tactic: Credential Access
```

## IOC Enrichment

### IP

```bash
soc-agent enrich-ip 8.8.8.8
```

### Domain

```bash
soc-agent enrich-domain example.com
```

### File hash

```bash
soc-agent enrich-hash 44d88612fea8a8f36de82e1278abb02f
```

Supported hash inputs include MD5, SHA-1, and SHA-256.

When a reputation provider is unavailable, the toolkit reports `unknown` rather than inventing reputation data.

## Threat Intelligence Configuration

Supported environment variables:

```text
ABUSEIPDB_API_KEY
VT_API_KEY
OTX_API_KEY
```

Claude integration uses:

```text
ANTHROPIC_API_KEY
```

### Linux / WSL / macOS

```bash
export VT_API_KEY="YOUR_KEY"
export ABUSEIPDB_API_KEY="YOUR_KEY"
export OTX_API_KEY="YOUR_KEY"
export ANTHROPIC_API_KEY="YOUR_KEY"
```

### Windows PowerShell

```powershell
$env:VT_API_KEY="YOUR_KEY"
$env:ABUSEIPDB_API_KEY="YOUR_KEY"
$env:OTX_API_KEY="YOUR_KEY"
$env:ANTHROPIC_API_KEY="YOUR_KEY"
```

Never commit API keys, tokens, passwords, or secret `.env` files to GitHub.

## Offline Behavior

External enrichment is optional. Without reputation API keys, enrichment returns an `unknown` verdict when external evidence is unavailable.

Without Claude, the toolkit uses a deterministic offline incident-summary fallback so the core parsing, MITRE mapping, triage, deduplication, and scoring pipeline can continue.

## Priority Model

Alerts receive a score from **0–100** and one of four priority levels:

```text
P1 — Critical
P2 — High
P3 — Medium
P4 — Low
```

The score can incorporate alert severity, repeated occurrences, IOC reputation, MITRE ATT&CK matches, and asset criticality.

## Project Structure

```text
soc-agent-toolkit/
│
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
│
├── soc_agent_toolkit/tests/
├── alerts.json
├── pyproject.toml
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
| `schemas.py` | AI tool-use definitions and dispatcher |
| `agent.py` | End-to-end pipeline and agentic loop |
| `cli.py` | Command-line interface |
| `tui.py` | Interactive Rich terminal interface |
| `config.py` | Configurable scoring and toolkit settings |

## Example Workflow

```bash
# Launch interactive TUI
soc-agent

# Analyze alerts
soc-agent analyze alerts.json

# Get structured JSON output
soc-agent analyze alerts.json --json

# Map an alert to MITRE ATT&CK
soc-agent mitre "SSH brute force login attempt"

# Check an IP
soc-agent enrich-ip 8.8.8.8

# Check a domain
soc-agent enrich-domain example.com

# Check a file hash
soc-agent enrich-hash 44d88612fea8a8f36de82e1278abb02f

# Show version
soc-agent version
```

## Testing

Run the full test suite:

```bash
pytest -q
```

Expected project validation includes:

```bash
python -m py_compile soc_agent_toolkit/cli.py
python -m compileall -q soc_agent_toolkit
pytest -q
```

## Design Principles

### Defensive by design

The toolkit analyzes, enriches, prioritizes, and summarizes security events. It does not automatically block IP addresses, isolate endpoints, or modify production systems.

### Evidence over guessing

When reputation information is unavailable, the toolkit reports `unknown` instead of inventing a verdict.

### Deterministic core

The main security pipeline remains deterministic and inspectable, while AI is used for natural-language reasoning and analyst-facing summaries.

### CLI-first

The project is designed to work naturally inside terminal-based SOC workflows and automation pipelines.

## Roadmap

- Additional threat-intelligence providers
- Expanded MITRE ATT&CK coverage
- More extensive test coverage
- CI/CD automation
- Package distribution and release automation
- Improved AI agent workflows

## License

This project is currently distributed without a declared license.

A permissive open-source license such as **MIT** can be added before public package distribution.

## Author

**Maulana Yasyfa’u Al Azhiim Yudho Leksono**

GitHub: https://github.com/ByteBreakerGhost-69
