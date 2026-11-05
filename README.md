# subdomain-recon-pipeline

recon-dash is a decoupled, three-stage reconnaissance state machine and dashboard for asset discovery, health verification, and inventory management.

## Architecture: Decoupled 3-Stage State Machine

The workflow is decoupled into three sequentially executable, idempotent modules:

```
                  ┌──────────────────────────────────────────────┐
                  │ Stage 1: Harvesting & Normalization (0%-35%) │
                  └──────────────────────┬───────────────────────┘
                                         │ writes stage1_subdomains.json & manifest.json
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ Stage 2: Availability Verification (35%-75%) │ (Skips Stage 1 if cached)
                  └──────────────────────┬───────────────────────┘
                                         │ writes stage2_live_hosts.json
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │ Stage 3: Artifact Capture (75%-100%)         │
                  └──────────────────────┬───────────────────────┘
                                         │ writes stage3_final.json & screenshots/
                                         ▼
                             Consolidated Dashboard
```

### 1. Stage 1: Harvesting & Normalization (Progress: 0% – 35%)
- Queries passive registries: `crt.sh` (Certificate Transparency logs), `AlienVault OTX` (Passive DNS), `Wayback Machine CDX`, `Certspotter`, `Anubis`, and `HackerTarget`.
- Extracts apex domain and Subject Alternative Names (SANs) completely.
- Normalizes records by removing protocols, wildcards, ports, trailing paths, query strings, and duplicate entries.
- Emits immediate intermediate file: `stage1_subdomains.json`.
- Generates `manifest.json` tracking domain, timestamp, execution configuration, and stage status.

### 2. Stage 2: Availability & Status Verification (Progress: 35% – 75%)
- Consumes `stage1_subdomains.json`. If this file already exists in the scan folder, Stage 1 is skipped entirely (idempotency).
- Executes non-redirect-following HTTP and HTTPS health checks with strict socket timeouts (2.5s) and controlled concurrency (worker pools).
- Categorizes results explicitly into: `200 OK`, `Redirects (301/302)`, `Client Errors (4xx)`, `Server Errors (5xx)`, and `Unreachable`.
- Records response times (latency in ms) for each reachable host.
- Emits immediate intermediate file: `stage2_live_hosts.json`.

### 3. Stage 3: Artifact Generation & Capture (Progress: 75% – 100%)
- Consumes `stage2_live_hosts.json`, filtering exclusively for verified `200 OK` assets.
- Captures headless screenshots using Chrome/Chromium (or graceful SVG visual fallbacks in headless containers) with batch caps and per-host timeouts.
- Stores screenshots locally in `screenshots/` inside the scan folder and links relative file paths to host records.
- Consolidates final dashboard payload to `stage3_final.json`.

## Storage & Directory Hierarchy

All outputs are isolated into timestamped directories:
```
data/{domain}_{YYYYMMDD_HHMMSS}_{random8char}/
├── manifest.json            # Target domain, timestamp, execution configuration
├── stage1_subdomains.json   # Normalized inventory of discovered subdomains
├── stage2_live_hosts.json   # Status code categorization & response times
├── screenshots/             # Visual screenshot assets for 200 OK hosts
└── stage3_final.json        # Unified schema matching dashboard requirements
```

If any stage fails, execution terminates cleanly, preserves all completed stage files, and updates the task status to `failed` with the specific error context.

## Data Contracts & JSON Schemas

All stage boundaries validate inputs and outputs against JSON Schema (Draft-07):
- `schemas/manifest.schema.json`
- `schemas/stage1_subdomains.schema.json`
- `schemas/stage2_live_hosts.schema.json`
- `schemas/stage3_final.schema.json`

## API Reference

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/api/run-recon-async` | Trigger async 3-stage state machine (`{"domain": "...", "skip_stage1_if_cached": true}`) |
| `GET` | `/api/task-status?id={task_id}` | Poll real-time stage telemetry and milestone progress |
| `GET` | `/api/scans` | List all discovered scans with status and counts |
| `GET` | `/api/scans/{id}` | Read consolidated `stage3_final.json` payload |
| `GET` | `/api/scans/{id}/manifest` | Inspect `manifest.json` metadata |
| `GET` | `/api/scans/{id}/stage1` | Inspect `stage1_subdomains.json` artifact |
| `GET` | `/api/scans/{id}/stage2` | Inspect `stage2_live_hosts.json` artifact |
| `GET` | `/api/scans/{id}/screenshots/{file}` | Fetch captured visual assets |
| `GET` | `/api/scans/{id}/export?format=json\|csv` | Download normalized results in JSON or CSV |
| `GET` | `/api/scans/{id}/report` | Download Markdown report |
| `GET` | `/api/scans/{id}/diff?compare_to={id}` | Compare two scans for added/removed subdomains |
| `POST` | `/api/import` | Manual upload of existing .json or .csv results |

## CLI Execution

Run the complete pipeline:
```sh
./recon.sh example.com
```

Or execute individual stages independently:
```sh
# Stage 1: Harvesting & Normalization
python3 -m stages.stage1_harvest example.com data/example.com_custom

# Stage 2: Availability & Status Verification
python3 -m stages.stage2_verify data/example.com_custom --concurrency 30

# Stage 3: Artifact Generation & Capture
python3 -m stages.stage3_capture data/example.com_custom --cap 30
```

## Running the Dashboard

Start the runner service:
```sh
python3 runner.py
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Tests

Run the full test suite:
```sh
PATH=".venv/bin:$PATH" make test
```
