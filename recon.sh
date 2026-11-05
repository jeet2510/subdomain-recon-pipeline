#!/usr/bin/env bash
# ==============================================================================
# recon.sh - Complete Multi-Source Subdomain Harvester & HTTP Auditor
# ==============================================================================

set -eo pipefail

DOMAIN="${1:-}"
TARGET_DIR="${2:-results_${DOMAIN}}"

if [[ -z "$DOMAIN" ]]; then
    echo "Usage: ./recon.sh <domain.com> [output_directory]"
    exit 1
fi

mkdir -p "$TARGET_DIR"

RAW_SUBS="$TARGET_DIR/raw_subdomains.txt"
CLEAN_SUBS="$TARGET_DIR/clean_subdomains.txt"
ALL_RESP="$TARGET_DIR/all_responding.txt"
OUTPUT_JSON="$TARGET_DIR/recon_dash_${DOMAIN}.json"
COUNT_FILE="$TARGET_DIR/count.txt"

> "$RAW_SUBS"

echo "[*] Target Domain : $DOMAIN"
echo "[*] Storage Dir   : $TARGET_DIR"

# ------------------------------------------------------------------------------
# 1. Multi-Engine Passive Harvesting
# ------------------------------------------------------------------------------

# Source A: crt.sh (Full SAN and Common Name extraction via Python parser)
echo "[*] [1/7] Harvesting crt.sh (Full Certificate Transparency)..."
python3 - <<EOF >> "$RAW_SUBS" 2>/dev/null || true
import json
import urllib.request
import re

domain = "$DOMAIN"
url = f"https://crt.sh/?q=%25.{domain}&output=json"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})

try:
    with urllib.request.urlopen(req, timeout=35) as resp:
        data = json.loads(resp.read().decode('utf-8', errors='ignore'))
        for item in data:
            name_val = item.get("name_value", "")
            for entry in name_val.split("\n"):
                entry = entry.strip().lower()
                if entry.endswith(domain):
                    print(entry)
            cn = item.get("common_name", "").strip().lower()
            if cn.endswith(domain):
                print(cn)
except Exception:
    pass
EOF

# Source B: AlienVault OTX (Passive DNS Cache)
echo "[*] [2/7] Harvesting AlienVault OTX..."
curl -s -m 20 "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" 2>/dev/null \
  | grep -oE "\"hostname\":\s*\"[^\"]+\"" \
  | cut -d'"' -f4 >> "$RAW_SUBS" || true

# Source C: Wayback Machine CDX API (Historical subdomains)
echo "[*] [3/7] Harvesting Wayback Machine Archive..."
curl -s -m 25 "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" 2>/dev/null \
  | sed -e 's_https*://__' -e 's[/.*__' \
  | cut -d':' -f1 >> "$RAW_SUBS" || true

# Source D: Certspotter API
echo "[*] [4/7] Harvesting Certspotter..."
curl -s -m 20 "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" 2>/dev/null \
  | grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN}" >> "$RAW_SUBS" || true

# Source E: Anubis Registry
echo "[*] [5/7] Harvesting Anubis DB..."
curl -s -m 20 "https://jldc.me/anubis/subdomains/${DOMAIN}" 2>/dev/null \
  | grep -oE "[a-zA-Z0-9._-]+\.${DOMAIN}" >> "$RAW_SUBS" || true

# Source F: HackerTarget DNS
echo "[*] [6/7] Harvesting HackerTarget..."
curl -s -m 15 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" 2>/dev/null \
  | cut -d',' -f1 >> "$RAW_SUBS" || true

# Source G: OWASP Amass (Passive mode if installed)
if command -v amass &>/dev/null; then
    echo "[*] [7/7] Running OWASP Amass (Passive mode)..."
    amass enum -passive -d "$DOMAIN" -timeout 2 -silent >> "$RAW_SUBS" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 2. Resilient Cleaning & Deduplication (Includes Main Domain + All Subs)
# ------------------------------------------------------------------------------
# Always include the apex domain explicitly
echo "$DOMAIN" >> "$RAW_SUBS"
echo "www.$DOMAIN" >> "$RAW_SUBS"

# Normalize: strip protocol, port, wildcards, and trailing slashes
sed -E 's#^https?://##; s#/.*$##; s#:[0-9]+$##; s#^\*\.##; s/\r$//' "$RAW_SUBS" \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E "(^|\.)${DOMAIN}$" \
  | sed 's/^[.]*//' \
  | grep -v '\*' \
  | sort -u > "$CLEAN_SUBS"

TOTAL_DISCOVERED=$(wc -l < "$CLEAN_SUBS" | tr -d ' ')
echo "[+] Total Unique Assets Discovered: $TOTAL_DISCOVERED"

# Write intermediate count so runner.py updates the UI immediately
echo "$TOTAL_DISCOVERED" > "$COUNT_FILE"

# ------------------------------------------------------------------------------
# 3. HTTP Probing (Distinguishing 200 OK vs Redirects vs Inactive)
# ------------------------------------------------------------------------------
> "$ALL_RESP"

probe_target() {
    local host="$1"
    # Fast 2.5s socket check
    local code
    code=$(curl -s -m 2.5 -o /dev/null -w "%{http_code}" "https://${host}" 2>/dev/null || \
           curl -s -m 2.5 -o /dev/null -w "%{http_code}" "http://${host}" 2>/dev/null || echo "000")

    if [[ "$code" != "000" && -n "$code" ]]; then
        echo "${host},${code}" >> "$2"
    fi
}
export -f probe_target

echo "[*] Auditing live HTTP responses across $TOTAL_DISCOVERED assets (40 threads)..."
cat "$CLEAN_SUBS" | xargs -P 40 -I {} bash -c "probe_target '{}' '$ALL_RESP'"

TOTAL_RESPONDING=$(wc -l < "$ALL_RESP" | tr -d ' ')
echo "[+] Active Responding Hosts: $TOTAL_RESPONDING"

# ------------------------------------------------------------------------------
# 4. JSON Generation for Dashboard
# ------------------------------------------------------------------------------
python3 - <<EOF
import json
import os

domain = "$DOMAIN"
clean_subs = "$CLEAN_SUBS"
all_resp = "$ALL_RESP"
out_json = "$OUTPUT_JSON"

resp_map = {}
if os.path.exists(all_resp):
    with open(all_resp) as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) == 2 and parts[1].isdigit():
                resp_map[parts[0]] = int(parts[1])

subdomains = []
if os.path.exists(clean_subs):
    with open(clean_subs) as f:
        for line in f:
            h = line.strip()
            if h:
                subdomains.append({
                    "name": h,
                    "sources": ["osint-aggregator"]
                })

live_hosts = []
for host, code in resp_map.items():
    live_hosts.append({
        "host": host,
        "status_code": code,
        "is_200": (code == 200)
    })

data = {
    "domain": domain,
    "total_subdomains": len(subdomains),
    "total_responding": len(live_hosts),
    "total_http_200": sum(1 for h in live_hosts if h["is_200"]),
    "subdomains": subdomains,
    "live_hosts": live_hosts
}

with open(out_json, "w") as f:
    json.dump(data, f, indent=2)

print(f"[✓] Successfully exported {len(subdomains)} assets to {out_json}")
EOF