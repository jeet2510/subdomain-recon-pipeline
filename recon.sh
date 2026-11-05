#!/usr/bin/env bash
# ==============================================================================
# recon.sh - Decoupled 3-Stage Reconnaissance State Machine Runner
# ==============================================================================

set -eo pipefail

DOMAIN="${1:-}"
TARGET_DIR="${2:-}"

if [[ -z "$DOMAIN" ]]; then
    echo "Usage: ./recon.sh <domain.com> [output_directory]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="python3"

if [[ -x "$SCRIPT_DIR/.venv/bin/python3" ]]; then
    PYTHON_BIN="$SCRIPT_DIR/.venv/bin/python3"
elif [[ -x "$SCRIPT_DIR/venv/bin/python3" ]]; then
    PYTHON_BIN="$SCRIPT_DIR/venv/bin/python3"
fi

echo "[*] Initializing Reconnaissance State Machine for: $DOMAIN"

PYTHONPATH="$SCRIPT_DIR" "$PYTHON_BIN" - <<EOF
import sys
import os
from stages.state_machine import ReconStateMachine

domain = "$DOMAIN"
target_dir = "$TARGET_DIR"

if target_dir:
    data_dir = os.path.dirname(os.path.abspath(target_dir))
    scan_folder = os.path.basename(os.path.abspath(target_dir))
else:
    data_dir = os.path.join("$SCRIPT_DIR", "data")
    scan_folder = None

def on_telemetry(event):
    pct = event.get("progress", 0)
    stage = event.get("stage", "")
    msg = event.get("message", "")
    print(f"[{pct:3d}%] [{stage.upper()}] {msg}")

sm = ReconStateMachine(
    domain=domain,
    data_dir=data_dir,
    scan_folder_name=scan_folder,
    concurrency=35,
    socket_timeout=2.5,
    screenshot_cap=30,
    skip_stage1_if_cached=True,
    telemetry_callback=on_telemetry
)

try:
    res = sm.run()
    print(f"\n[✓] Recon state machine completed successfully!")
    print(f"[*] Artifacts directory : {sm.scan_dir}")
    print(f"[*] Total subdomains    : {res['summary']['total_subdomains']}")
    print(f"[*] HTTP 200 OK assets  : {res['summary']['total_http_200']}")
    print(f"[*] Final payload       : {sm.stage3_file}")
except Exception as e:
    print(f"\n[X] Recon state machine failed: {e}", file=sys.stderr)
    sys.exit(1)
EOF
