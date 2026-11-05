"""Stage 1: Harvesting & Normalization.

Collects subdomains from passive sources (crt.sh, AlienVault, Wayback CDX,
Certspotter, Anubis, HackerTarget), extracts apex domain and all SANs,
normalizes asset records, and saves stage1_subdomains.json and manifest.json.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from stages.schemas import MANIFEST_SCHEMA, STAGE1_SCHEMA, validate_schema

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def validate_target_domain(domain: str) -> str:
    cleaned = domain.strip().lower().rstrip(".")
    if not DOMAIN_PATTERN.fullmatch(cleaned):
        raise ValueError(f"Invalid domain name: {domain}")
    return cleaned


def normalize_record(raw: str, apex_domain: str) -> Optional[str]:
    """Normalize a raw record: remove protocol, wildcards, ports, trailing paths, query strings, and lowercase."""
    if not raw or not isinstance(raw, str):
        return None
    val = raw.strip()
    # Strip protocol if present
    if "://" in val:
        try:
            parsed = urlparse(val)
            val = parsed.hostname or parsed.path
        except Exception:
            val = re.sub(r"^https?://", "", val)
    else:
        val = re.sub(r"^https?://", "", val)

    # Strip path & query parameters
    val = val.split("/")[0].split("?")[0].split("#")[0]
    # Strip port (:80, :443, etc.)
    val = re.sub(r":[0-9]+$", "", val)
    # Strip wildcards (*., *), leading and trailing dots
    val = re.sub(r"^\*+\.?", "", val)
    val = val.strip().lower().rstrip(".").lstrip(".")

    # Filter out wildcards, empty strings, invalid characters
    if not val or "*" in val or " " in val:
        return None

    # Check scope: exact apex or subdomain ending with .{domain}
    if val == apex_domain or val.endswith(f".{apex_domain}"):
        return val
    return None


# ---------------------------------------------------------------------------
# Passive Source Collectors
# ---------------------------------------------------------------------------

def _fetch_url(url: str, timeout: float = 20.0) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def harvest_crtsh(domain: str) -> List[str]:
    """Source 1: crt.sh (Full SAN and Common Name extraction)."""
    results: List[str] = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        content = _fetch_url(url, timeout=30.0)
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                # All SANs in name_value
                nv = item.get("name_value", "")
                if isinstance(nv, str):
                    for line in nv.split("\n"):
                        results.append(line.strip())
                # Common Name
                cn = item.get("common_name", "")
                if isinstance(cn, str):
                    results.append(cn.strip())
    except Exception:
        pass
    return results


def harvest_alienvault(domain: str) -> List[str]:
    """Source 2: AlienVault OTX Passive DNS Cache."""
    results: List[str] = []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        content = _fetch_url(url, timeout=20.0)
        data = json.loads(content)
        records = data.get("passive_dns", [])
        for rec in records:
            hostname = rec.get("hostname", "")
            if hostname:
                results.append(hostname)
    except Exception:
        pass
    return results


def harvest_wayback(domain: str) -> List[str]:
    """Source 3: Wayback Machine CDX API."""
    results: List[str] = []
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    try:
        content = _fetch_url(url, timeout=25.0)
        for line in content.splitlines():
            line = line.strip()
            if line:
                results.append(line)
    except Exception:
        pass
    return results


def harvest_certspotter(domain: str) -> List[str]:
    """Source 4: Certspotter API."""
    results: List[str] = []
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        content = _fetch_url(url, timeout=20.0)
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                for name in item.get("dns_names", []):
                    results.append(name)
    except Exception:
        pass
    return results


def harvest_anubis(domain: str) -> List[str]:
    """Source 5: Anubis Registry."""
    results: List[str] = []
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        content = _fetch_url(url, timeout=20.0)
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    results.append(item)
    except Exception:
        pass
    return results


def harvest_hackertarget(domain: str) -> List[str]:
    """Source 6: HackerTarget DNS."""
    results: List[str] = []
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        content = _fetch_url(url, timeout=15.0)
        for line in content.splitlines():
            parts = line.strip().split(",")
            if parts and parts[0]:
                results.append(parts[0])
    except Exception:
        pass
    return results


def harvest_amass(domain: str) -> List[str]:
    """Optional Source 7: OWASP Amass (Passive mode if installed)."""
    results: List[str] = []
    if shutil.which("amass"):
        try:
            res = subprocess.run(
                ["amass", "enum", "-passive", "-d", domain, "-timeout", "2", "-silent"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in res.stdout.splitlines():
                if line.strip():
                    results.append(line.strip())
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Stage 1 Execution Engine
# ---------------------------------------------------------------------------

SOURCES = [
    ("crt.sh", "harvest_crtsh"),
    ("alienvault", "harvest_alienvault"),
    ("wayback", "harvest_wayback"),
    ("certspotter", "harvest_certspotter"),
    ("anubis", "harvest_anubis"),
    ("hackertarget", "harvest_hackertarget"),
]


def run_stage1(
    domain: str,
    scan_dir: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    execution_config: Optional[Dict] = None,
) -> Dict:
    """Execute Stage 1: Harvesting & Normalization.

    - Collects records using passive sources
    - Extracts apex domain and all SANs
    - Normalizes & deduplicates records
    - Writes stage1_subdomains.json and manifest.json
    - Emits progress in 0% - 35% range
    - Validates against standard JSON schemas
    """
    valid_domain = validate_target_domain(domain)
    os.makedirs(scan_dir, exist_ok=True)

    stage1_file = os.path.join(scan_dir, "stage1_subdomains.json")
    manifest_file = os.path.join(scan_dir, "manifest.json")
    start_time = datetime.now(timezone.utc).isoformat()

    cfg = execution_config or {"concurrency": 30, "timeout": 3.0, "screenshot_cap": 30}

    # Tracking discovered hosts and their sources
    host_sources: Dict[str, Set[str]] = {}
    sources_summary: Dict[str, int] = {}

    # Apex domain & www are always extracted
    for apex in (valid_domain, f"www.{valid_domain}"):
        norm = normalize_record(apex, valid_domain)
        if norm:
            host_sources.setdefault(norm, set()).add("apex-seed")

    total_sources = len(SOURCES)
    mod = sys.modules[__name__]

    for idx, (source_name, func_name) in enumerate(SOURCES):
        # Progress: 0% - 35% based on completed source queries
        pct = int(35.0 * idx / total_sources)
        if progress_callback:
            progress_callback(pct, f"Stage 1: Querying {source_name} for {valid_domain}...")

        harvester = getattr(mod, func_name, None)
        try:
            raw_entries = harvester(valid_domain) if callable(harvester) else []
        except Exception:
            raw_entries = []

        found_for_source = 0
        for entry in raw_entries:
            norm = normalize_record(entry, valid_domain)
            if norm:
                host_sources.setdefault(norm, set()).add(source_name)
                found_for_source += 1

        sources_summary[source_name] = found_for_source

    # Final normalization step
    subdomains_list = [
        {"name": name, "sources": sorted(list(sources))}
        for name, sources in sorted(host_sources.items())
    ]
    finish_time = datetime.now(timezone.utc).isoformat()

    stage1_payload = {
        "domain": valid_domain,
        "total": len(subdomains_list),
        "timestamp": finish_time,
        "sources_summary": sources_summary,
        "subdomains": subdomains_list,
    }

    # Validate against STAGE1_SCHEMA
    validate_schema(stage1_payload, STAGE1_SCHEMA)

    # Write stage1_subdomains.json immediately
    with open(stage1_file, "w", encoding="utf-8") as f:
        json.dump(stage1_payload, f, indent=2)

    # Write count.txt for legacy runner/monitoring loops
    count_file = os.path.join(scan_dir, "count.txt")
    try:
        with open(count_file, "w", encoding="utf-8") as f:
            f.write(str(len(subdomains_list)))
    except Exception:
        pass

    # Manifest file
    manifest_payload = {
        "target_domain": valid_domain,
        "timestamp": finish_time,
        "total_unique_subdomains": len(subdomains_list),
        "execution_config": cfg,
        "stages": {
            "stage1": {
                "status": "completed",
                "started_at": start_time,
                "finished_at": finish_time,
                "output_file": "stage1_subdomains.json",
                "count": len(subdomains_list),
                "error": None,
            },
            "stage2": {
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "output_file": None,
                "total_scanned": None,
                "total_200": None,
                "error": None,
            },
            "stage3": {
                "status": "pending",
                "started_at": None,
                "finished_at": None,
                "output_file": None,
                "total_captured": None,
                "error": None,
            },
        },
    }

    # Validate against MANIFEST_SCHEMA
    validate_schema(manifest_payload, MANIFEST_SCHEMA)

    with open(manifest_file, "w", encoding="utf-8") as f:
        json.dump(manifest_payload, f, indent=2)

    # Stage 1 milestone completed: 35%
    if progress_callback:
        progress_callback(35, f"Stage 1 complete: Discovered {len(subdomains_list)} unique subdomains.")

    return stage1_payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 1: Subdomain Harvesting & Normalization")
    parser.add_argument("domain", help="Target apex domain (e.g., example.com)")
    parser.add_argument("scan_dir", help="Scan output directory path")
    args = parser.parse_args()

    def print_progress(p: int, msg: str):
        print(f"[{p}%] {msg}")

    try:
        res = run_stage1(args.domain, args.scan_dir, progress_callback=print_progress)
        print(f"[✓] Stage 1 finished successfully: {res['total']} subdomains stored in stage1_subdomains.json")
    except Exception as e:
        print(f"[X] Stage 1 failed: {e}", file=sys.stderr)
        sys.exit(1)
