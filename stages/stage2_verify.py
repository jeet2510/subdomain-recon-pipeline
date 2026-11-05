"""Stage 2: Availability & Status Verification.

Accepts stage1_subdomains.json as input.
Executes non-redirect-following HTTP/HTTPS health checks with controlled
concurrency and strict socket timeouts.
Categorizes results explicitly by HTTP response code (200 OK, redirects 301/302,
client/server errors 4xx/5xx, unreachable hosts).
Saves output immediately to stage2_live_hosts.json.
"""

import argparse
import concurrent.futures
import json
import os
import http.client
import re
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    import httpx
except ImportError:
    httpx = None

from stages.schemas import MANIFEST_SCHEMA, STAGE2_SCHEMA, validate_schema

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(html_text: str) -> Optional[str]:
    match = TITLE_PATTERN.search(html_text)
    if match:
        title = match.group(1).strip()
        # Clean up whitespace and newlines
        title = re.sub(r"\s+", " ", title)
        return title[:256] if title else None
    return None


def _probe_httpx(host: str, timeout_sec: float) -> Dict[str, Any]:
    transport = httpx.HTTPTransport(verify=False, retries=0)
    client_timeout = httpx.Timeout(timeout_sec, connect=timeout_sec, read=timeout_sec, write=timeout_sec)

    # 1. Try HTTPS
    url = f"https://{host}"
    t0 = time.perf_counter()
    try:
        with httpx.Client(
            transport=transport,
            timeout=client_timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = client.get(url)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
            code = resp.status_code
            title = None
            if "text/html" in resp.headers.get("content-type", ""):
                try:
                    title = extract_title(resp.text[:8192])
                except Exception:
                    pass

            return _categorize_host(host, url, code, elapsed_ms, title=title, error=None)
    except Exception:
        pass

    # 2. Try HTTP as fallback
    url_http = f"http://{host}"
    t0 = time.perf_counter()
    try:
        with httpx.Client(
            transport=transport,
            timeout=client_timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            resp = client.get(url_http)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
            code = resp.status_code
            title = None
            if "text/html" in resp.headers.get("content-type", ""):
                try:
                    title = extract_title(resp.text[:8192])
                except Exception:
                    pass

            return _categorize_host(host, url_http, code, elapsed_ms, title=title, error=None)
    except Exception as e_http:
        return _categorize_host(
            host,
            url,
            status_code=None,
            elapsed_ms=None,
            title=None,
            error=str(e_http) or "Connection failed",
        )


def _probe_stdlib(host: str, timeout_sec: float) -> Dict[str, Any]:
    ssl_ctx = ssl._create_unverified_context()

    # 1. Try HTTPS
    url = f"https://{host}"
    t0 = time.perf_counter()
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout_sec, context=ssl_ctx)
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT})
        resp = conn.getresponse()
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        code = resp.status
        title = None
        ctype = resp.getheader("Content-Type", "")
        if "text/html" in ctype:
            try:
                title = extract_title(resp.read(8192).decode("utf-8", errors="ignore"))
            except Exception:
                pass
        conn.close()
        return _categorize_host(host, url, code, elapsed_ms, title=title, error=None)
    except Exception:
        pass

    # 2. Try HTTP as fallback
    url_http = f"http://{host}"
    t0 = time.perf_counter()
    try:
        conn = http.client.HTTPConnection(host, timeout=timeout_sec)
        conn.request("GET", "/", headers={"User-Agent": USER_AGENT})
        resp = conn.getresponse()
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        code = resp.status
        title = None
        ctype = resp.getheader("Content-Type", "")
        if "text/html" in ctype:
            try:
                title = extract_title(resp.read(8192).decode("utf-8", errors="ignore"))
            except Exception:
                pass
        conn.close()
        return _categorize_host(host, url_http, code, elapsed_ms, title=title, error=None)
    except Exception as e_http:
        return _categorize_host(
            host,
            url,
            status_code=None,
            elapsed_ms=None,
            title=None,
            error=str(e_http) or "Connection failed",
        )


def probe_single_host(
    host: str,
    timeout_sec: float = 2.5,
) -> Dict[str, Any]:
    """Perform non-redirect-following health check on a host.

    Uses httpx when installed; otherwise uses standard library http.client.
    Tries HTTPS first; if that fails or times out, tries HTTP.
    Returns categorized host record with status code and response time.
    """
    if httpx is not None:
        return _probe_httpx(host, timeout_sec)
    return _probe_stdlib(host, timeout_sec)


def _categorize_host(
    host: str,
    url: str,
    status_code: Optional[int],
    elapsed_ms: Optional[float],
    title: Optional[str] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Categorize host explicitly by HTTP status code."""
    if status_code == 200:
        category = "200 OK"
        is_200 = True
    elif status_code in (301, 302, 303, 307, 308):
        category = "redirect"
        is_200 = False
    elif status_code is not None and 400 <= status_code <= 499:
        category = "client_error"
        is_200 = False
    elif status_code is not None and 500 <= status_code <= 599:
        category = "server_error"
        is_200 = False
    else:
        category = "unreachable"
        is_200 = False

    return {
        "host": host,
        "url": url,
        "status_code": status_code,
        "category": category,
        "is_200": is_200,
        "response_time_ms": elapsed_ms,
        "title": title,
        "error": error,
    }


def run_stage2(
    scan_dir: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    concurrency: int = 30,
    socket_timeout: float = 2.5,
) -> Dict[str, Any]:
    """Execute Stage 2: Availability & Status Verification.

    - Reads stage1_subdomains.json from scan_dir
    - Probes each host using non-redirect-following health checks
    - Emits progress in 35% - 75% range
    - Categorizes by HTTP response code
    - Saves stage2_live_hosts.json immediately
    - Updates manifest.json
    - Validates against STAGE2_SCHEMA
    """
    stage1_file = os.path.join(scan_dir, "stage1_subdomains.json")
    if not os.path.exists(stage1_file):
        raise FileNotFoundError(f"Input file not found: {stage1_file}. Stage 1 must be executed first.")

    with open(stage1_file, "r", encoding="utf-8") as f:
        stage1_data = json.load(f)

    domain = stage1_data.get("domain", "")
    subdomains = stage1_data.get("subdomains", [])
    hosts = [item["name"] if isinstance(item, dict) else str(item) for item in subdomains]

    total_hosts = len(hosts)
    stage2_file = os.path.join(scan_dir, "stage2_live_hosts.json")
    manifest_file = os.path.join(scan_dir, "manifest.json")
    start_time = datetime.now(timezone.utc).isoformat()

    if progress_callback:
        progress_callback(35, f"Stage 2 active: Starting health checks for {total_hosts} hosts (concurrency={concurrency})...")

    results: List[Dict[str, Any]] = []
    completed_count = 0
    lock = threading.Lock()

    if total_hosts > 0:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_host = {
                executor.submit(probe_single_host, h, socket_timeout): h
                for h in hosts
            }

            for future in concurrent.futures.as_completed(future_to_host):
                res = future.result()
                with lock:
                    results.append(res)
                    completed_count += 1
                    # Progress: 35% - 75% based on processed hosts / total harvested hosts
                    pct = 35 + int(40.0 * completed_count / total_hosts)
                    if progress_callback and (completed_count % 5 == 0 or completed_count == total_hosts):
                        progress_callback(
                            pct,
                            f"Stage 2: Checked {completed_count}/{total_hosts} hosts [{res['host']} -> {res['category']}]",
                        )

    # Sort results by host name for deterministic ordering
    results.sort(key=lambda x: x["host"])

    # Aggregate categorization summary
    summary = {
        "200_ok": sum(1 for h in results if h["category"] == "200 OK"),
        "redirects": sum(1 for h in results if h["category"] == "redirect"),
        "client_errors": sum(1 for h in results if h["category"] == "client_error"),
        "server_errors": sum(1 for h in results if h["category"] == "server_error"),
        "unreachable": sum(1 for h in results if h["category"] == "unreachable"),
    }

    finish_time = datetime.now(timezone.utc).isoformat()
    stage2_payload = {
        "domain": domain,
        "total_scanned": total_hosts,
        "timestamp": finish_time,
        "summary": summary,
        "live_hosts": results,
    }

    # Validate against STAGE2_SCHEMA
    validate_schema(stage2_payload, STAGE2_SCHEMA)

    # Save immediately to stage2_live_hosts.json
    with open(stage2_file, "w", encoding="utf-8") as f:
        json.dump(stage2_payload, f, indent=2)

    # Update manifest.json if present
    if os.path.exists(manifest_file):
        try:
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest = json.load(f)
            manifest["stages"]["stage2"] = {
                "status": "completed",
                "started_at": start_time,
                "finished_at": finish_time,
                "output_file": "stage2_live_hosts.json",
                "total_scanned": total_hosts,
                "total_200": summary["200_ok"],
                "error": None,
            }
            validate_schema(manifest, MANIFEST_SCHEMA)
            with open(manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except Exception:
            pass

    # Milestone 75% reached
    if progress_callback:
        progress_callback(
            75,
            f"Stage 2 complete: {summary['200_ok']} hosts returned HTTP 200 OK, {summary['redirects']} redirects, {summary['unreachable']} unreachable.",
        )

    return stage2_payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stage 2: Availability & Status Verification")
    parser.add_argument("scan_dir", help="Directory containing stage1_subdomains.json")
    parser.add_argument("--concurrency", type=int, default=30, help="Worker pool concurrency")
    parser.add_argument("--timeout", type=float, default=2.5, help="Socket timeout in seconds")
    args = parser.parse_args()

    def print_progress(p: int, msg: str):
        print(f"[{p}%] {msg}")

    try:
        res = run_stage2(args.scan_dir, progress_callback=print_progress, concurrency=args.concurrency, socket_timeout=args.timeout)
        print(f"[✓] Stage 2 finished successfully: {res['summary']['200_ok']} 200 OK hosts saved to stage2_live_hosts.json")
    except Exception as e:
        print(f"[X] Stage 2 failed: {e}", file=sys.stderr)
        sys.exit(1)
