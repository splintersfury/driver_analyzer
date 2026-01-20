# Windows Driver Vulnerability Analyzer

A scalable pipeline for analyzing Windows drivers for potential vulnerabilities, built on top of [Karton](https://github.com/CERT-Polska/karton) and [MWDB Core](https://github.com/CERT-Polska/mwdb-core).

## Overview

This project provides a set of Karton services designed to automatically process and analyze Windows drivers. The pipeline extracts metadata, checks digital signatures, and performs static analysis to identify potentially vulnerable IOCTL handlers.

### Key Components

*   **Signature Service**: Verifies digital signatures using Sysinternals Sigcheck.
*   **Classifier**: Identifies file type and architecture.
*   **IOCTLance Service**: Uses symbolic execution (via angr) to find vulnerabilities in IOCTL handlers.
*   **Reporter**: Aggregates results and uploads them to MWDB.

## Prerequisites

*   Docker and Docker Compose
*   (Optional) Python 3 for running helper scripts

## Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/driver_analyzer.git
    cd driver_analyzer
    ```

2.  **Environment Setup (Optional):**
    You can create a `.env` file to customize passwords and keys, or rely on the defaults in `docker-compose.yml` for a quick test environment.
    
    ```bash
    # Example .env (optional)
    MWDB_SECRET_KEY=your-secure-random-key
    MWDB_API_KEY=your-generated-mwdb-api-key
    ```
    
    *Note: The default setup uses `dev-secret-key-change-me` and a placeholder for the API key. You will need to generate a real API key from MWDB to fully enable the Reporter service.*

3.  **Start the services:**
    ```bash
    docker-compose up --build -d
    ```

4.  **Access the dashboards:**
    *   **MWDB Core**: http://localhost:8082 (Login: `admin` / `mwdb-password`)
    *   **Karton Dashboard**: http://localhost:8081

## Configuration

### Generating an MWDB API Key

The `mwdb-reporter` service needs an API key to upload results to MWDB.
1.  Log in to MWDB (http://localhost:8082).
2.  Go to Settings -> API Key.
3.  Copy the API Key.
4.  Update your `.env` file or export the variable:
    ```bash
    export MWDB_API_KEY=your_copied_api_key
    ```
5.  Restart the reporter service:
    ```bash
    docker-compose up -d karton-driver-reporter
    ```

### Uploading Samples

You can upload samples directly through the MWDB web interface, or use the `upload_drivers.py` script provided (requires identifying the API key).

## Services Detail

### Signature Service (`services/signature`)
Wraps `sigcheck.exe` (running via Wine) to extract signer information and verification status.

### Classifier (`services/classifier`)
Determines if the file is a PE driver and tags it with architecture (x86/x64).

### IOCTLance (`services/ioctlance`)
A port of the IOCTLance vulnerability scanner to the Karton framework. It attempts to discover vulnerabilities like buffer overflows in IOCTL handlers.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
