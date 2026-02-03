# Windows Driver Vulnerability Analyzer

A scalable pipeline for analyzing Windows drivers for potential vulnerabilities, built on top of [Karton](https://github.com/CERT-Polska/karton) and [MWDB Core](https://github.com/CERT-Polska/mwdb-core).

## Overview

This project automatically processes and analyzes Windows drivers. It extracts metadata, checks digital signatures, detects patch differences, and performs symbolic execution to identify potential vulnerabilities.

### Key Components

*   **Signature Service**: Verifies digital signatures using Sysinternals Sigcheck (via Wine).
*   **Classifier**: Identifies file type and architecture.
*   **Patch Differ**: Automatically finds prior versions of a driver, generates a binary diff (using Ghidra), and reports changed functions and security fix patterns.
*   **Ghidra Service**: Headless decompilation and export of function data.
*   **IOCTLance Service**: Uses symbolic execution (via angr) to find vulnerabilities in IOCTL handlers.
*   **Reporter**: Aggregates results and uploads markdown reports to MWDB.

## Prerequisites

*   Docker and Docker Compose
*   (Optional) Python 3 for running helper scripts

## Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/driver_analyzer.git
    cd driver_analyzer
    ```

2.  **Environment Setup (Required):**
    Copy the example configuration and set your secrets.
    ```bash
    cp .env.example .env
    ```
    *   **Edit `.env`**: You must set `MWDB_API_KEY` (after first login) and `TELEGRAM_BOT_TOKEN` (optional).

3.  **Start the services:**
    ```bash
    docker-compose up -d --build
    ```

4.  **Access the dashboards:**
    *   **MWDB Core**: http://localhost:8080 (Login: `admin` / `admin` - *default*)
    *   **Karton Dashboard**: http://localhost:8081

5.  **Final Configuration**:
    *   Log in to MWDB.
    *   Generate an API Key (Settings -> API Key).
    *   Update `MWDB_API_KEY` in your `.env` file.
    *   Restart the stack: `docker-compose up -d`.

## Features

### 🛡️ Patch Differ (New)
Automatically compares an uploaded driver against older versions found in the database.
- **Strict Arch Matching**: Ensures x64 is only diffed against x64.
- **Match Rate Tagging**: Automatically tags analysis quality:
    - `diff_match:high` (>85% match)
    - `diff_match:medium` (70-85%)
    - `diff_match:low` (<70%)
- **Reports**: Generates a markdown report `Patch_Diff_*.md` attached to the sample, highlighting changed functions and potential security fixes.

### 💾 Hardened Storage
Files uploaded to MWDB are safely stored in a **Docker Named Volume** (`mwdb-uploads-data`). This ensures data persistence matches the database lifecycle and prevents data loss during container restarts.

## Utilities

### Re-analyzing Samples
If you need to re-trigger analysis for files (e.g., after updating the pipeline), use the included script:
```bash
python3 reanalyze_mwdb.py --days 1  # Reanalyze samples from the last 24h
```

## Services Detail

### Signature Service (`services/signature`)
Wraps `sigcheck.exe` to extract signer information.

### Patch Differ (`services/patch_differ`)
Orchestrates Ghidra to decompile and diff two versions of a binary, using fuzzy hashing to align functions and detect changes.

### IOCTLance (`services/ioctlance`)
Scalable vulnerability scanner for IOCTL handlers.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
