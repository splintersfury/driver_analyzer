# Windows Driver Vulnerability Analyzer

A scalable pipeline for analyzing Windows drivers for potential vulnerabilities, built on top of [Karton](https://github.com/CERT-Polska/karton) and [MWDB Core](https://github.com/CERT-Polska/mwdb-core).

Automated patch diffing, semantic analysis, and vulnerability scoring is powered by **[AutoPiff](https://github.com/splintersfury/AutoPiff)** — see that repository for details on the analysis engine, rule sets, and Ghidra scripts.

## Overview

This project automatically processes and analyzes Windows drivers through a multi-stage pipeline. It monitors for new driver versions, extracts metadata, checks digital signatures, performs patch diffing with semantic analysis, traces reachability from attack surfaces, scores findings, and generates reports with alerting.

### Pipeline Stages

| Stage | Service | Description |
|-------|---------|-------------|
| **0** | Driver Monitor | Polls WinBIndex and VirusTotal for new driver versions, uploads to MWDB |
| **1-4** | Patch Differ | Binary diffing via Ghidra, semantic rule matching (58 rules across 22 categories) |
| **5** | Reachability | Ghidra call-graph analysis tracing paths from IOCTL/IRP entry points to changed functions, plus full decompilation export |
| **6** | Ranking | Scores and ranks findings based on reachability, semantic severity, and attack surface |
| **7** | Report | Generates markdown reports attached to MWDB samples |
| **8** | Alerter | Sends Telegram alerts for high-scoring findings (score >= 8.0) |

### Supporting Services

*   **Signature Service**: Verifies digital signatures using Sysinternals Sigcheck (via Wine).
*   **Classifier**: Identifies file type and architecture.
*   **IOCTLance**: Symbolic execution (via angr) to find vulnerabilities in IOCTL handlers.
*   **Reporter**: Aggregates Karton results and uploads to MWDB.
*   **Telegram Bot**: Interactive bot for dynamic watchlist management (`/watchdriver`).
*   **Dashboard**: Web UI for pipeline status and analysis results.

## Prerequisites

*   Docker and Docker Compose
*   (Optional) Python 3 for running helper scripts
*   (Optional) `VT_API_KEY` for VirusTotal driver monitoring
*   (Optional) `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` for alerts

## Quick Start

1.  **Clone the repositories:**
    ```bash
    git clone https://github.com/yourusername/driver_analyzer.git
    git clone https://github.com/splintersfury/AutoPiff.git
    cd driver_analyzer
    ```
    AutoPiff must be cloned alongside this repo (as `../AutoPiff`) — several services build from it.

2.  **Environment Setup (Required):**
    ```bash
    cp .env.example .env
    ```
    Edit `.env` and set:
    *   `MWDB_API_KEY` — generate after first MWDB login (see step 5)
    *   `TELEGRAM_BOT_TOKEN` — for alerts and the Telegram bot (optional)
    *   `TELEGRAM_CHAT_ID` — target chat for alerts (optional)
    *   `VT_API_KEY` — for VirusTotal driver monitoring (optional)

3.  **Start the services:**
    ```bash
    docker compose up -d --build
    ```

4.  **Access the dashboards:**
    *   **MWDB Core**: http://localhost:8080 (Login: `admin` / `admin` — default)
    *   **Karton Dashboard**: http://localhost:8081
    *   **Driver Dashboard**: http://localhost:8088

5.  **Final Configuration:**
    *   Log in to MWDB.
    *   Generate an API Key (Settings -> API Key).
    *   Update `MWDB_API_KEY` in your `.env` file.
    *   Restart the stack: `docker compose up -d`.

## Architecture

```
                    ┌──────────────────┐
                    │  Driver Monitor   │  (Stage 0)
                    │  WinBIndex + VT   │
                    └────────┬─────────┘
                             │ uploads new .sys to MWDB
                             ▼
                    ┌──────────────────┐
                    │    MWDB Core      │
                    └────────┬─────────┘
                             │ triggers Karton pipeline
                             ▼
              ┌──────────────────────────────┐
              │  Classifier + Signature       │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  Patch Differ (Stages 1-4)    │  ← AutoPiff
              │  diff + semantic rules        │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  Reachability (Stage 5)       │  ← AutoPiff
              │  call-graph + decompilation   │
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  Ranking (Stage 6)            │  ← AutoPiff
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  Report (Stage 7)             │  ← AutoPiff
              └──────────────┬───────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  Alerter (Stage 8)            │  ← AutoPiff
              │  Telegram high-score alerts   │
              └──────────────────────────────┘
```

Services marked **← AutoPiff** build from the [AutoPiff](https://github.com/splintersfury/AutoPiff) repository (`../AutoPiff`).

## Features

### Driver Monitor (Stage 0)
Continuously polls for new driver versions from two sources:
- **WinBIndex**: Monitors 14 system drivers (cldflt.sys, ntfs.sys, afd.sys, win32k.sys, etc.)
- **VirusTotal Intelligence**: Searches for new uploads from security vendors (CrowdStrike, SentinelOne, Sophos, ESET)
- Supports dynamic watchlist additions via Telegram `/watchdriver` command

### Patch Differ (Stages 1-4)
Automatically compares an uploaded driver against older versions found in the database.
- **Strict Arch Matching**: Ensures x64 is only diffed against x64.
- **Semantic Analysis**: 58 vulnerability detection rules across 22 categories.
- **Match Rate Tagging**: `diff_match:high` (>85%), `diff_match:medium` (70-85%), `diff_match:low` (<70%).
- **Reports**: Generates markdown reports highlighting changed functions and security fix patterns.

### Reachability (Stage 5)
Traces call paths from driver entry points to changed functions using Ghidra headless analysis.
- Classifies reachability as `ioctl`, `irp`, `pnp`, `internal`, or `unknown`.
- Exports full decompiled C source to MWDB for caching and review.

### Scoring & Ranking (Stage 6)
Scores findings based on reachability from attack surfaces, semantic severity, and exploitability indicators.

### Report Generation (Stage 7)
Produces structured markdown reports attached to MWDB samples.

### Alerter (Stage 8)
Sends Telegram notifications for high-confidence findings (score >= 8.0 with IOCTL/IRP/filesystem surface area).

### Hardened Storage
Files uploaded to MWDB are stored in a **Docker Named Volume** (`mwdb-uploads-data`), ensuring data persistence across container restarts.

## Utilities

### Re-analyzing Samples
```bash
python3 reanalyze_mwdb.py --days 1  # Reanalyze samples from the last 24h
```

## Related Projects

- **[AutoPiff](https://github.com/splintersfury/AutoPiff)** — The analysis engine powering Stages 1-8. Contains Ghidra scripts, semantic rules, Karton services, and the scoring framework.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
