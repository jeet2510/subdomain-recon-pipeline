"""Backend runner & API server for the decoupled 3-stage reconnaissance pipeline.

Provides real-time telemetry polling (/api/task-status), asynchronous execution
(/api/run-recon-async), artifact retrieval, scan comparisons, and static file delivery.
"""

import csv
import io
import json
import mimetypes
import os
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from stages.schemas import validate_schema
from stages.stage1_harvest import validate_target_domain
from stages.state_machine import ReconStateMachine

PORT = int(os.getenv("PORT", "8000"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
GLOBAL_SCREENSHOT_DIR = os.path.join(STATIC_DIR, "screenshots")
INDEX_FILE = os.path.join(DATA_DIR, "scans.json")

# Ensure essential directories exist safely
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(GLOBAL_SCREENSHOT_DIR, exist_ok=True)

if not os.path.exists(INDEX_FILE):
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump({}, f)

# In-memory store for active and completed task telemetry
TASKS = {}


def load_scans():
    """Load registry of scans, discovering any scan folders in DATA_DIR."""
    scans = {}
    if os.path.exists(INDEX_FILE):
        try:
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                scans = json.load(f)
        except Exception:
            scans = {}

    # Auto-index scan folders created directly on disk
    if os.path.exists(DATA_DIR):
        for entry in os.listdir(DATA_DIR):
            scan_path = os.path.join(DATA_DIR, entry)
            if os.path.isdir(scan_path) and entry not in scans:
                # Check for stage3_final.json or scan_result.json
                final_json = os.path.join(scan_path, "stage3_final.json")
                legacy_json = os.path.join(scan_path, "scan_result.json")
                manifest_json = os.path.join(scan_path, "manifest.json")

                target_file = final_json if os.path.exists(final_json) else (legacy_json if os.path.exists(legacy_json) else None)
                if target_file:
                    try:
                        with open(target_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            scans[entry] = data
                    except Exception:
                        pass
                elif os.path.exists(manifest_json):
                    try:
                        with open(manifest_json, "r", encoding="utf-8") as f:
                            m = json.load(f)
                            scans[entry] = {
                                "id": entry,
                                "domain": m.get("target_domain", entry.split("_")[0]),
                                "started_at": m.get("timestamp", datetime.now(timezone.utc).isoformat()),
                                "status": "partial",
                                "subdomains": [],
                                "live_hosts": [],
                            }
                    except Exception:
                        pass
    return scans


def save_scans(data):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def run_state_machine_worker(domain: str, task_id: str, scan_folder: str, skip_stage1: bool):
    """Background worker executing the three-stage state machine with strict telemetry."""
    def telemetry_callback(event: dict):
        if task_id in TASKS:
            pct = event.get("progress", 0)
            stage = event.get("stage", "unknown")
            msg = event.get("message", "")
            err = event.get("error")

            TASKS[task_id]["progress"] = pct
            TASKS[task_id]["stage"] = stage
            TASKS[task_id]["message"] = msg
            if err:
                TASKS[task_id]["error"] = err

            # Stage milestones mapping
            TASKS[task_id]["milestone"] = {
                "stage1_completed": pct >= 35,
                "stage2_completed": pct >= 75,
                "stage3_completed": pct >= 100,
            }

            final_data = event.get("final_data")
            if final_data:
                TASKS[task_id]["subdomains_count"] = final_data.get("summary", {}).get("total_subdomains", 0)
                TASKS[task_id]["live_count"] = final_data.get("summary", {}).get("total_http_200", 0)

    try:
        sm = ReconStateMachine(
            domain=domain,
            data_dir=DATA_DIR,
            scan_folder_name=scan_folder,
            concurrency=35,
            socket_timeout=2.5,
            screenshot_cap=30,
            screenshot_timeout=8.0,
            skip_stage1_if_cached=skip_stage1,
            telemetry_callback=telemetry_callback,
        )

        final_payload = sm.run()

        # Update persistent index
        scans = load_scans()
        scans[scan_folder] = final_payload
        save_scans(scans)

        # Legacy file compatibility: write scan_result.json in the folder
        scan_result_path = os.path.join(sm.scan_dir, "scan_result.json")
        try:
            with open(scan_result_path, "w", encoding="utf-8") as f:
                json.dump(final_payload, f, indent=2)
        except Exception:
            pass

        TASKS[task_id]["status"] = "completed"
        TASKS[task_id]["progress"] = 100
        TASKS[task_id]["message"] = (
            f"Scan complete! {final_payload['summary']['total_subdomains']} subdomains cataloged, "
            f"{final_payload['summary']['total_http_200']} verified 200 OK."
        )
        TASKS[task_id]["scan_id"] = scan_folder
        TASKS[task_id]["subdomains_count"] = final_payload["summary"]["total_subdomains"]
        TASKS[task_id]["live_count"] = final_payload["summary"]["total_http_200"]

    except Exception as e:
        TASKS[task_id]["status"] = "failed"
        TASKS[task_id]["error"] = str(e)
        TASKS[task_id]["message"] = f"Execution failed: {str(e)}"


class ReconHandler(BaseHTTPRequestHandler):
    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. Concrete milestone-derived telemetry polling
        if path == "/api/task-status":
            tid = query.get("id", [""])[0]
            if tid in TASKS:
                return self._send_json(200, TASKS[tid])
            return self._send_json(404, {"detail": "Task not found"})

        # 2. List all scans
        if path == "/api/scans":
            domain = query.get("domain", [""])[0].strip().lower()
            scans = load_scans()
            results = [
                {
                    "id": sid,
                    "domain": s.get("domain"),
                    "started_at": s.get("started_at"),
                    "status": s.get("status", "completed"),
                    "count": len(s.get("subdomains", [])),
                    "live_count": s.get("summary", {}).get("total_http_200", sum(1 for h in s.get("live_hosts", []) if h.get("is_200"))),
                }
                for sid, s in scans.items()
                if not domain or s.get("domain", "").lower() == domain
            ]
            results.sort(key=lambda x: str(x.get("started_at", "")), reverse=True)
            return self._send_json(200, results)

        # 3. Retrieve specific scan artifacts
        if path.startswith("/api/scans/"):
            parts = path.split("/")
            if len(parts) >= 4:
                sid = parts[3]
                scans = load_scans()
                scan_dir = os.path.join(DATA_DIR, sid)

                # Serve stage artifact files directly if requested
                if len(parts) >= 5:
                    subpath = parts[4]

                    # /api/scans/{id}/manifest
                    if subpath == "manifest":
                        m_file = os.path.join(scan_dir, "manifest.json")
                        if os.path.isfile(m_file):
                            with open(m_file, "r", encoding="utf-8") as f:
                                return self._send_json(200, json.load(f))
                        return self._send_json(404, {"detail": "Manifest artifact not found"})

                    # /api/scans/{id}/stage1
                    if subpath == "stage1":
                        s1_file = os.path.join(scan_dir, "stage1_subdomains.json")
                        if os.path.isfile(s1_file):
                            with open(s1_file, "r", encoding="utf-8") as f:
                                return self._send_json(200, json.load(f))
                        return self._send_json(404, {"detail": "Stage 1 artifact not found"})

                    # /api/scans/{id}/stage2
                    if subpath == "stage2":
                        s2_file = os.path.join(scan_dir, "stage2_live_hosts.json")
                        if os.path.isfile(s2_file):
                            with open(s2_file, "r", encoding="utf-8") as f:
                                return self._send_json(200, json.load(f))
                        return self._send_json(404, {"detail": "Stage 2 artifact not found"})

                    # /api/scans/{id}/screenshots/{filename}
                    if subpath == "screenshots" and len(parts) >= 6:
                        img_name = parts[5]
                        shot_path = os.path.join(scan_dir, "screenshots", img_name)
                        # Also fallback to global screenshot dir
                        if not os.path.isfile(shot_path):
                            shot_path = os.path.join(GLOBAL_SCREENSHOT_DIR, img_name)

                        if os.path.isfile(shot_path):
                            ctype, _ = mimetypes.guess_type(shot_path)
                            if shot_path.endswith(".svg"):
                                ctype = "image/svg+xml"
                            with open(shot_path, "rb") as f:
                                return self._send_raw(200, ctype or "image/png", f.read())
                        return self._send_json(404, {"detail": "Screenshot not found"})

                    # /api/scans/{id}/export
                    if subpath == "export":
                        fmt = query.get("format", ["json"])[0]
                        if sid not in scans:
                            return self._send_json(404, {"detail": "Scan not found"})
                        scan = scans[sid]
                        if fmt == "csv":
                            out = io.StringIO()
                            writer = csv.writer(out)
                            writer.writerow(["name", "sources", "status_code", "category", "is_200", "response_time_ms"])
                            live_map = {x["host"]: x for x in scan.get("live_hosts", [])}
                            for s in scan.get("subdomains", []):
                                h_info = live_map.get(s["name"], {})
                                writer.writerow([
                                    s["name"],
                                    ",".join(s.get("sources", [])),
                                    h_info.get("status_code", ""),
                                    h_info.get("category", "unreachable"),
                                    h_info.get("is_200", False),
                                    h_info.get("response_time_ms", ""),
                                ])
                            return self._send_raw(200, "text/csv", out.getvalue().encode("utf-8"))
                        return self._send_json(200, scan)

                    # /api/scans/{id}/report
                    if subpath == "report":
                        if sid not in scans:
                            return self._send_json(404, {"detail": "Scan not found"})
                        scan = scans[sid]
                        summary = scan.get("summary", {})
                        ok_count = summary.get("total_http_200", sum(1 for h in scan.get("live_hosts", []) if h.get("is_200")))
                        report = (
                            f"# Reconnaissance Report: {scan['domain']}\n\n"
                            f"- **Scan ID**: `{sid}`\n"
                            f"- **Directory**: `{scan.get('folder', sid)}`\n"
                            f"- **Timestamp**: {scan.get('started_at')}\n"
                            f"- **Discovered Subdomains**: {len(scan.get('subdomains', []))}\n"
                            f"- **Active (HTTP 200 OK)**: {ok_count}\n"
                            f"- **Redirects (301/302)**: {summary.get('total_redirects', 'N/A')}\n"
                            f"- **Client Errors (4xx)**: {summary.get('total_client_errors', 'N/A')}\n"
                            f"- **Server Errors (5xx)**: {summary.get('total_server_errors', 'N/A')}\n"
                            f"- **Unreachable Hosts**: {summary.get('total_unreachable', 'N/A')}\n\n"
                            f"## Preserved Stage Artifacts\n"
                            f"- `manifest.json`\n"
                            f"- `stage1_subdomains.json`\n"
                            f"- `stage2_live_hosts.json`\n"
                            f"- `stage3_final.json`\n"
                        )
                        return self._send_raw(200, "text/markdown", report.encode("utf-8"))

                    # /api/scans/{id}/diff
                    if subpath == "diff":
                        comp_id = query.get("compare_to", [""])[0]
                        if sid not in scans or comp_id not in scans:
                            return self._send_json(404, {"detail": "Scan not found"})
                        newer = {s["name"] for s in scans[sid].get("subdomains", [])}
                        older = {s["name"] for s in scans[comp_id].get("subdomains", [])}
                        return self._send_json(200, {
                            "new": sorted(list(newer - older)),
                            "removed": sorted(list(older - newer)),
                            "unchanged": sorted(list(newer & older)),
                        })

                # /api/scans/{id} - Full scan payload
                if sid in scans:
                    return self._send_json(200, scans[sid])
                return self._send_json(404, {"detail": "Scan not found"})

        # 4. Global screenshot directory delivery
        if path.startswith("/screenshots/"):
            shot_file = os.path.basename(path)
            target_path = os.path.join(GLOBAL_SCREENSHOT_DIR, shot_file)
            if os.path.isfile(target_path):
                ctype, _ = mimetypes.guess_type(target_path)
                with open(target_path, "rb") as f:
                    return self._send_raw(200, ctype or "image/png", f.read())

        # 5. Static file delivery
        clean_path = path.lstrip("/")
        if clean_path in ("", "index.html"):
            target_file = os.path.join(STATIC_DIR, "index.html")
        elif clean_path in ("history", "history.html"):
            target_file = os.path.join(STATIC_DIR, "history.html")
        else:
            target_file = os.path.join(STATIC_DIR, clean_path)

        if os.path.isfile(target_file):
            content_type, _ = mimetypes.guess_type(target_file)
            content_type = content_type or "application/octet-stream"
            with open(target_file, "rb") as f:
                return self._send_raw(200, content_type, f.read())

        self._send_json(404, {"detail": "Resource not found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        # Trigger async 3-stage recon state machine
        if parsed.path == "/api/run-recon-async":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                domain_raw = body.get("domain", "").strip()
                skip_stage1 = body.get("skip_stage1_if_cached", True)
            except Exception:
                domain_raw = ""
                skip_stage1 = True

            try:
                domain = validate_target_domain(domain_raw)
            except Exception as e:
                return self._send_json(400, {"detail": str(e)})

            task_id = str(uuid.uuid4())
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rand8 = secrets.token_hex(4)
            scan_folder_name = f"{domain}_{ts}_{rand8}"

            TASKS[task_id] = {
                "task_id": task_id,
                "domain": domain,
                "scan_id": scan_folder_name,
                "status": "running",
                "stage": "stage1",
                "progress": 0,
                "message": "Initializing decoupled 3-stage state machine...",
                "error": None,
                "milestone": {
                    "stage1_completed": False,
                    "stage2_completed": False,
                    "stage3_completed": False,
                },
                "subdomains_count": 0,
                "live_count": 0,
            }

            thread = threading.Thread(
                target=run_state_machine_worker,
                args=(domain, task_id, scan_folder_name, skip_stage1),
                daemon=True,
            )
            thread.start()

            return self._send_json(200, {"task_id": task_id, "scan_id": scan_folder_name})

        # Manual import handler
        if parsed.path == "/api/import":
            content_type = self.headers.get("Content-Type", "")
            if "multipart/form-data" not in content_type:
                return self._send_json(400, {"detail": "Expected multipart/form-data"})

            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length)

            boundary = content_type.split("boundary=")[-1].encode()
            parts = raw_body.split(b"--" + boundary)

            domain_raw = ""
            file_bytes = b""
            filename = ""

            for part in parts:
                if b'name="domain"' in part:
                    domain_raw = part.split(b"\r\n\r\n")[1].split(b"\r\n")[0].decode("utf-8").strip()
                elif b'name="file"' in part:
                    header, body = part.split(b"\r\n\r\n", 1)
                    file_bytes = body.rsplit(b"\r\n", 1)[0]
                    if b'filename="' in header:
                        filename = header.split(b'filename="')[1].split(b'"')[0].decode("utf-8")

            try:
                domain = validate_target_domain(domain_raw)
            except Exception as e:
                return self._send_json(400, {"detail": str(e)})

            if not file_bytes:
                return self._send_json(400, {"detail": "File is required"})

            subdomains = []
            live_hosts = []

            if filename.endswith(".csv") or file_bytes.startswith(b"name"):
                reader = csv.DictReader(io.StringIO(file_bytes.decode("utf-8", errors="ignore")))
                for row in reader:
                    name = row.get("name", "").strip()
                    if name:
                        subdomains.append({"name": name, "sources": ["manual-import"]})
            else:
                try:
                    parsed_json = json.loads(file_bytes.decode("utf-8"))
                    if isinstance(parsed_json, dict):
                        raw_subs = parsed_json.get("subdomains", [])
                        for item in raw_subs:
                            if isinstance(item, str):
                                subdomains.append({"name": item, "sources": ["manual-import"]})
                            elif isinstance(item, dict) and "name" in item:
                                subdomains.append(item)
                        live_hosts = parsed_json.get("live_hosts", [])
                    elif isinstance(parsed_json, list):
                        for item in parsed_json:
                            subdomains.append({
                                "name": item if isinstance(item, str) else item.get("name", ""),
                                "sources": ["manual-import"],
                            })
                except Exception as e:
                    return self._send_json(400, {"detail": f"Failed to parse file: {str(e)}"})

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rand8 = secrets.token_hex(4)
            scan_folder_name = f"{domain}_{ts}_{rand8}"
            scan_dir = os.path.join(DATA_DIR, scan_folder_name)
            os.makedirs(scan_dir, exist_ok=True)
            os.makedirs(os.path.join(scan_dir, "screenshots"), exist_ok=True)

            now_iso = datetime.now(timezone.utc).isoformat()

            # Create standard stage artifacts for imported data
            manifest_payload = {
                "target_domain": domain,
                "timestamp": now_iso,
                "total_unique_subdomains": len(subdomains),
                "execution_config": {"concurrency": 0, "timeout": 0, "screenshot_cap": 0},
                "stages": {
                    "stage1": {"status": "completed", "started_at": now_iso, "finished_at": now_iso, "output_file": "stage1_subdomains.json", "count": len(subdomains), "error": None},
                    "stage2": {"status": "completed", "started_at": now_iso, "finished_at": now_iso, "output_file": "stage2_live_hosts.json", "total_scanned": len(live_hosts), "total_200": sum(1 for h in live_hosts if h.get("status_code") == 200 or h.get("is_200")), "error": None},
                    "stage3": {"status": "completed", "started_at": now_iso, "finished_at": now_iso, "output_file": "stage3_final.json", "total_captured": 0, "error": None},
                },
            }
            with open(os.path.join(scan_dir, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest_payload, f, indent=2)

            stage1_payload = {
                "domain": domain,
                "total": len(subdomains),
                "timestamp": now_iso,
                "sources_summary": {"manual-import": len(subdomains)},
                "subdomains": subdomains,
            }
            with open(os.path.join(scan_dir, "stage1_subdomains.json"), "w", encoding="utf-8") as f:
                json.dump(stage1_payload, f, indent=2)

            # Categorize live hosts
            categorized_hosts = []
            for h in live_hosts:
                code = h.get("status_code")
                is_200 = (code == 200) or h.get("is_200", False)
                if code == 200:
                    cat = "200 OK"
                elif code in (301, 302, 303, 307, 308):
                    cat = "redirect"
                elif code is not None and 400 <= code <= 499:
                    cat = "client_error"
                elif code is not None and 500 <= code <= 599:
                    cat = "server_error"
                else:
                    cat = "unreachable"

                categorized_hosts.append({
                    "host": h.get("host", ""),
                    "url": h.get("url", f"https://{h.get('host', '')}"),
                    "status_code": code,
                    "category": cat,
                    "is_200": is_200,
                    "response_time_ms": h.get("response_time_ms"),
                    "screenshot": h.get("screenshot"),
                    "title": h.get("title"),
                    "error": None,
                })

            stage2_payload = {
                "domain": domain,
                "total_scanned": len(categorized_hosts),
                "timestamp": now_iso,
                "summary": {
                    "200_ok": sum(1 for h in categorized_hosts if h["category"] == "200 OK"),
                    "redirects": sum(1 for h in categorized_hosts if h["category"] == "redirect"),
                    "client_errors": sum(1 for h in categorized_hosts if h["category"] == "client_error"),
                    "server_errors": sum(1 for h in categorized_hosts if h["category"] == "server_error"),
                    "unreachable": sum(1 for h in categorized_hosts if h["category"] == "unreachable"),
                },
                "live_hosts": categorized_hosts,
            }
            with open(os.path.join(scan_dir, "stage2_live_hosts.json"), "w", encoding="utf-8") as f:
                json.dump(stage2_payload, f, indent=2)

            final_record = {
                "id": scan_folder_name,
                "domain": domain,
                "started_at": now_iso,
                "finished_at": now_iso,
                "status": "completed",
                "manifest": manifest_payload,
                "summary": {
                    "total_subdomains": len(subdomains),
                    "total_responding": len(categorized_hosts),
                    "total_http_200": stage2_payload["summary"]["200_ok"],
                    "total_redirects": stage2_payload["summary"]["redirects"],
                    "total_client_errors": stage2_payload["summary"]["client_errors"],
                    "total_server_errors": stage2_payload["summary"]["server_errors"],
                    "total_unreachable": stage2_payload["summary"]["unreachable"],
                    "screenshots_captured": 0,
                    "avg_response_time_ms": None,
                },
                "subdomains": subdomains,
                "live_hosts": categorized_hosts,
            }

            with open(os.path.join(scan_dir, "stage3_final.json"), "w", encoding="utf-8") as f:
                json.dump(final_record, f, indent=2)

            # Legacy file
            with open(os.path.join(scan_dir, "scan_result.json"), "w", encoding="utf-8") as f:
                json.dump(final_record, f, indent=2)

            scans = load_scans()
            scans[scan_folder_name] = final_record
            save_scans(scans)

            return self._send_json(200, {
                "id": scan_folder_name,
                "subdomains": len(subdomains),
                "live_hosts": len(categorized_hosts),
            })

        self._send_json(404, {"detail": "Route not found"})

    def _send_json(self, status, payload):
        self._send_raw(status, "application/json", json.dumps(payload).encode("utf-8"))

    def _send_raw(self, status, content_type, body_bytes):
        self.send_response(status)
        self._set_cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), ReconHandler)
    print(f"[*] Recon Dashboard & 3-Stage State Machine listening on: http://127.0.0.1:{PORT}")
    print(f"[*] Storing scans in: {DATA_DIR}")
    server.serve_forever()
