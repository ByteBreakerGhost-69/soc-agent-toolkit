# SOC Agent Toolkit

**AI-assisted SOC alert triage and incident analysis toolkit for the command line.**

SOC Agent Toolkit is a modular Python CLI designed to help SOC analysts process security alerts from the terminal. It normalizes alerts, maps events to MITRE ATT&CK techniques, enriches indicators of compromise (IOCs), deduplicates related alerts, prioritizes incidents, and generates analyst-ready incident summaries.

Designed for **Windows CMD, PowerShell, Linux, WSL, and macOS**.

---

## Features

* **Multi-format alert parsing** — JSON, CEF, and syslog
* **MITRE ATT&CK mapping** — heuristic mapping with optional STIX-based matching
* **IOC enrichment** — IP and domain reputation through configured threat-intelligence providers
* **Smart deduplication** — fuzzy signature matching combined with a configurable time window
* **Priority scoring** — scores alerts from 0–100 and assigns P1–P4 priority tiers
* **Asset criticality weighting** — increase priority for important hosts or assets
* **AI incident summaries** — Claude-powered summaries with an offline deterministic fallback
* **CLI-first design** — built to integrate with terminal and security workflows
* **Defensive only** — no automatic blocking or host isolation

---

## Architecture

```text
                Raw Security Alerts
                        │
                        ▼
                ┌──────────────┐
                │    Parser    │
                │ JSON/CEF/    │
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

---

## Requirements

* Python **3.10+**
* Git
* Internet connection only when using external threat-intelligence APIs or Claude

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ByteBreakerGhost-69/soc-agent-toolkit.git
cd soc-agent-toolkit
```

### 2. Create a virtual environment

Linux / WSL / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Windows CMD:

```cmd
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r soc_agent_toolkit/requirements.txt
```

### 4. Install the CLI

```bash
pip install -e .
```

The package installs the following executable:

```bash
soc-agent
```

Verify:

```bash
soc-agent --help
```

---

## CLI Usage

### Show help

```bash
soc-agent --help
```

Example:

```text
usage: soc-agent [-h] {analyze,mitre,enrich-ip,enrich-domain,version} ...

SOC Agent Toolkit — AI-assisted SOC alert triage and incident analysis

positional arguments:
  {analyze,mitre,enrich-ip,enrich-domain,version}
    analyze             Analyze and triage security alerts
    mitre               Map text to MITRE ATT&CK techniques
    enrich-ip           Check IP reputation
    enrich-domain       Check domain reputation
    version             Show SOC Agent Toolkit version
```

---

## Analyze Alerts

Analyze a JSON, CEF, or syslog alert file:

```bash
soc-agent analyze alerts.json
```

For the complete structured result:

```bash
soc-agent analyze alerts.json --json
```

The analysis pipeline performs:

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

---

## Analyze from stdin

SOC Agent Toolkit can read alert data directly from standard input:

```bash
cat alerts.json | soc-agent analyze -
```

This allows it to be chained with other command-line security tools.

Example:

```bash
some-security-tool | soc-agent analyze -
```

---

## Asset Criticality

You can provide an optional JSON file containing asset criticality weights.

Example `assets.json`:

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

Higher criticality increases the priority score of alerts involving those assets.

---

## MITRE ATT&CK Mapping

Map a security event directly from the terminal:

```bash
soc-agent mitre "SSH brute force login attempt"
```

Example output:

```text
MITRE ATT&CK Matches
====================
T1110 — Brute Force
Tactic: Credential Access
```

This command uses the toolkit's MITRE mapping engine.

---

## IP Reputation

Check an IP address:

```bash
soc-agent enrich-ip 8.8.8.8
```

Example without configured providers:

```json
{
  "ioc": "8.8.8.8",
  "type": "ip",
  "providers_used": [],
  "verdict": "unknown",
  "note": "No reputation API keys configured"
}
```

The toolkit does not invent reputation data when external providers are unavailable.

---

## Domain Reputation

Check a domain:

```bash
soc-agent enrich-domain example.com
```

Example:

```json
{
  "ioc": "example.com",
  "type": "domain",
  "providers_used": [],
  "verdict": "unknown"
}
```

---

## Version

Show the installed toolkit version:

```bash
soc-agent version
```

Example:

```text
SOC Agent Toolkit v0.1.0
```

---

## Threat Intelligence Configuration

External enrichment is optional.

Supported environment variables:

```bash
ABUSEIPDB_API_KEY
VT_API_KEY
OTX_API_KEY
```

Claude integration:

```bash
ANTHROPIC_API_KEY
```

### Linux / WSL / macOS

```bash
export ABUSEIPDB_API_KEY="YOUR_KEY"
export VT_API_KEY="YOUR_KEY"
export OTX_API_KEY="YOUR_KEY"
export ANTHROPIC_API_KEY="YOUR_KEY"
```

### Windows PowerShell

```powershell
$env:ABUSEIPDB_API_KEY="YOUR_KEY"
$env:VT_API_KEY="YOUR_KEY"
$env:OTX_API_KEY="YOUR_KEY"
$env:ANTHROPIC_API_KEY="YOUR_KEY"
```

Never commit API keys, tokens, passwords, or `.env` files containing secrets to GitHub.

---

## Offline Behavior

The toolkit is designed to degrade gracefully when external services are unavailable.

Without threat-intelligence API keys:

```text
IOC enrichment
      ↓
No provider available
      ↓
verdict = unknown
```

Without Claude:

```text
AI summary
    ↓
Offline deterministic fallback
```

This allows the core parsing, MITRE mapping, triage, deduplication, and scoring workflow to continue without external API access.

---

## Priority Model

Alerts receive a score from **0–100** and are assigned one of four priority levels:

```text
P1 — Critical
P2 — High
P3 — Medium
P4 — Low
```

The score can incorporate:

* Alert severity
* Repeated occurrences
* IOC reputation
* MITRE ATT&CK matches
* Asset criticality

The scoring configuration is centralized in the project configuration module.

---

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
│   └── triage.py
│
├── tests/
├── pyproject.toml
├── alerts.json
├── .gitignore
└── README.md
```

### Core modules

| Module                | Purpose                                   |
| --------------------- | ----------------------------------------- |
| `parser.py`           | Normalize JSON / CEF / syslog alerts      |
| `mitre.py`            | MITRE ATT&CK technique mapping            |
| `enrichment.py`       | IP / domain / hash reputation lookups     |
| `enrichment_async.py` | Concurrent enrichment                     |
| `triage.py`           | Deduplication and priority scoring        |
| `summarizer.py`       | AI and offline incident summaries         |
| `schemas.py`          | AI tool-use definitions and dispatcher    |
| `agent.py`            | End-to-end pipeline and agentic loop      |
| `cli.py`              | Command-line interface                    |
| `config.py`           | Configurable scoring and toolkit settings |

---

## Example Workflow

```bash
# Analyze alerts
soc-agent analyze alerts.json

# Get complete JSON output
soc-agent analyze alerts.json --json

# Map an alert to MITRE ATT&CK
soc-agent mitre "SSH brute force login attempt"

# Check an IP
soc-agent enrich-ip 8.8.8.8

# Check a domain
soc-agent enrich-domain example.com

# Show version
soc-agent version
```

---

## Example Output

```text
Incident batch: 3 alerts after dedup.

1 P2 (high) alert(s):
  - [59] SSH Brute Force Login Attempt
    src=203.0.113.5
    dest=10.0.0.12

[Note: generated by offline fallback — set
ANTHROPIC_API_KEY for a full AI summary.]

(3 deduped alerts — run with --json for full detail)
```

---

## Testing

Run the test suite with:

```bash
python -m pytest soc_agent_toolkit/tests/ -v
```

You can also validate the CLI source:

```bash
python -m py_compile soc_agent_toolkit/cli.py
```

---

## Design Principles

SOC Agent Toolkit follows several core principles:

### Defensive by design

The toolkit analyzes, enriches, prioritizes, and summarizes security events. It does not automatically block IP addresses, isolate endpoints, or modify production systems.

### Evidence over guessing

When reputation information is unavailable, the toolkit reports `unknown` instead of inventing a verdict.

### Deterministic core

The main security pipeline remains deterministic and inspectable, while AI is used for natural-language reasoning and analyst-facing summaries.

### CLI-first

The project is designed to work naturally inside terminal-based SOC workflows and automation pipelines.

---

## Roadmap

Planned improvements include:

* File hash CLI enrichment
* Expanded CLI subcommands
* Richer terminal output
* Additional threat-intelligence providers
* Better MITRE ATT&CK coverage
* More extensive test coverage
* CI/CD automation
* Package distribution
* Improved AI agent workflows

---

## Security Notice

This project is intended for **defensive security analysis, SOC operations, research, and authorized environments**.

Only analyze systems, logs, domains, IP addresses, and files that you are authorized to investigate.

---

## License

This project is currently distributed without a declared license.

A permissive open-source license such as **MIT** can be added before public package distribution.

---

## Author

**Maulana Yasyfa’u Al Azhiim Yudho Leksono**

GitHub:

https://github.com/ByteBreakerGhost-69
