# Patch Differ Service

Karton service that performs automated patch diffing between a new driver sample and its closest prior version found in the MWDB corpus.

## Features
- **Automated Matching**: Identifies Product Name and File Version from PE resources.
- **Corpus Search**: Finds the closest previous version of the same product/family in MWDB using `tag:product:*`.
- **Ghidra Decompilation**: Uses Ghidra Headless to decompile both the new and old samples.
- **Function Parsing**: Extracts functions using `// FUNCTION_START` delimiters for precise matching.
- **Advanced Diffing**:
    - **Change Heatmap**: Ranks changed functions by "Delta Score".
    - **Heuristics**: Detects fixes like "Input Length Validation", "Integer Overflow Fixes", and surface areas (IOCTL, NDIS).
- **Self-Healing**: Automatically re-decompiles legacy analysis results that lack function delimiters.

## How to Trigger
The service listens for tasks with:
```json
{
    "type": "driver",
    "kind": "driver:windows"
}
```

### Automatic Trigger
Upload a file to MWDB. If `karton-classifier` identifies it as a Windows Driver (`driver:windows`), this service will automatically pick it up.

### Manual / Re-analyze
If standard reanalysis doesn't trigger the service (e.g. if the classifier doesn't label it as a driver), you can **force** the analysis using the provided script in the root directory:

```bash
# Force patch diff on a local file (bypassing classifier)
python3 force_diff.py path/to/fortips_post.sys
```

This sends a task with `type: analysis` and `kind: patch_differ`, which the service now specifically listens for.

## Configuration (Environment Variables)
- `MWDB_API_URL`: URL of the MWDB instance (default: `http://mwdb-core:8080/api/`).
- `MWDB_API_KEY`: API Key for MWDB access.
- `GHIDRA_HOME`: Path to Ghidra installation (default: `/app/ghidra`).
- `KARTON_RABBITMQ_*`: RabbitMQ connection details.
- `KARTON_S3_*`: Minio/S3 connection details.
- `KARTON_REDIS_*`: Redis connection details.

## Troubleshooting
- **Logs**: `docker logs patch-differ-manual` (or the appropriate container name).
- **"No Product/Version info"**: The sample might be packed or lack standard version resources.
- **"No prior version found"**: This is the first sample of this product seen by the system. Upload an older version first.
