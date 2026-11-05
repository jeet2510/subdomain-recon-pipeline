"""Comprehensive test suite for the three-stage decoupled reconnaissance state machine."""

import json
import os
import shutil
import tempfile
from unittest.mock import patch

import pytest
from stages.schemas import (
    MANIFEST_SCHEMA,
    STAGE1_SCHEMA,
    STAGE2_SCHEMA,
    STAGE3_SCHEMA,
    SchemaValidationError,
    validate_schema,
)
from stages.stage1_harvest import (
    harvest_crtsh,
    normalize_record,
    run_stage1,
    validate_target_domain,
)
from stages.stage2_verify import _categorize_host, probe_single_host, run_stage2
from stages.stage3_capture import generate_svg_preview, run_stage3
from stages.state_machine import ReconStateMachine, execute_recon


@pytest.fixture
def temp_scan_dir(tmp_path):
    scan_dir = tmp_path / "test_scan_folder"
    scan_dir.mkdir(parents=True, exist_ok=True)
    return str(scan_dir)


# ---------------------------------------------------------------------------
# 1. Normalization & Schema Validation Tests
# ---------------------------------------------------------------------------

def test_normalization_removes_protocols_wildcards_ports_paths():
    domain = "example.com"
    assert normalize_record("https://api.example.com:8443/v1/auth?token=abc#hash", domain) == "api.example.com"
    assert normalize_record("http://*.dev.example.com/", domain) == "dev.example.com"
    assert normalize_record("*.SUB.EXAMPLE.COM", domain) == "sub.example.com"
    assert normalize_record("example.com", domain) == "example.com"
    assert normalize_record("www.example.com", domain) == "www.example.com"
    # Out of scope rejected
    assert normalize_record("example.com.attacker.com", domain) is None
    assert normalize_record("notexample.com", domain) is None
    assert normalize_record("", domain) is None


def test_schema_validator_enforces_contracts():
    valid_stage1 = {
        "domain": "example.com",
        "total": 1,
        "timestamp": "2026-11-06T00:00:00Z",
        "sources_summary": {"crt.sh": 1},
        "subdomains": [{"name": "api.example.com", "sources": ["crt.sh"]}],
    }
    # Should pass without error
    validate_schema(valid_stage1, STAGE1_SCHEMA)

    # Missing required field
    invalid_stage1 = dict(valid_stage1)
    del invalid_stage1["subdomains"]
    with pytest.raises(SchemaValidationError):
        validate_schema(invalid_stage1, STAGE1_SCHEMA)

    # Wrong type
    invalid_type = dict(valid_stage1, total="one")
    with pytest.raises(SchemaValidationError):
        validate_schema(invalid_type, STAGE1_SCHEMA)


# ---------------------------------------------------------------------------
# 2. Stage 1 (Harvesting & Normalization) Tests
# ---------------------------------------------------------------------------

def test_stage1_harvest_creates_stage1_and_manifest(temp_scan_dir, monkeypatch):
    # Mock passive collectors to avoid real network lookups in unit tests
    monkeypatch.setattr("stages.stage1_harvest.harvest_crtsh", lambda d: [f"a.{d}", f"b.{d}", f"*.c.{d}"])
    monkeypatch.setattr("stages.stage1_harvest.harvest_alienvault", lambda d: [f"b.{d}", f"d.{d}"])
    monkeypatch.setattr("stages.stage1_harvest.harvest_wayback", lambda d: [f"https://e.{d}:8080/index.php"])
    monkeypatch.setattr("stages.stage1_harvest.harvest_certspotter", lambda d: [])
    monkeypatch.setattr("stages.stage1_harvest.harvest_anubis", lambda d: [])
    monkeypatch.setattr("stages.stage1_harvest.harvest_hackertarget", lambda d: [])

    progress_events = []
    res = run_stage1(
        domain="example.com",
        scan_dir=temp_scan_dir,
        progress_callback=lambda p, msg: progress_events.append((p, msg)),
    )

    stage1_file = os.path.join(temp_scan_dir, "stage1_subdomains.json")
    manifest_file = os.path.join(temp_scan_dir, "manifest.json")

    assert os.path.exists(stage1_file)
    assert os.path.exists(manifest_file)

    with open(stage1_file, "r") as f:
        s1_data = json.load(f)
    validate_schema(s1_data, STAGE1_SCHEMA)

    with open(manifest_file, "r") as f:
        m_data = json.load(f)
    validate_schema(m_data, MANIFEST_SCHEMA)

    # Apex and www must be present
    names = {item["name"] for item in s1_data["subdomains"]}
    assert "example.com" in names
    assert "www.example.com" in names
    assert "a.example.com" in names
    assert "c.example.com" in names  # normalized from *.c.example.com
    assert "e.example.com" in names  # stripped port & path

    # Telemetry should stay in 0% - 35% range
    assert any(p == 35 for p, _ in progress_events)
    assert all(p <= 35 for p, _ in progress_events)


# ---------------------------------------------------------------------------
# 3. Stage 2 (Availability & Status Verification) Tests
# ---------------------------------------------------------------------------

def test_stage2_categorization():
    h200 = _categorize_host("a.com", "https://a.com", 200, 50.0)
    assert h200["category"] == "200 OK"
    assert h200["is_200"] is True

    h301 = _categorize_host("b.com", "https://b.com", 301, 40.0)
    assert h301["category"] == "redirect"
    assert h301["is_200"] is False

    h404 = _categorize_host("c.com", "https://c.com", 404, 30.0)
    assert h404["category"] == "client_error"

    h500 = _categorize_host("d.com", "https://d.com", 500, 30.0)
    assert h500["category"] == "server_error"

    hunreach = _categorize_host("e.com", "https://e.com", None, None, error="Timeout")
    assert hunreach["category"] == "unreachable"


def test_stage2_verify_execution(temp_scan_dir, monkeypatch):
    # Seed stage1 file
    stage1_file = os.path.join(temp_scan_dir, "stage1_subdomains.json")
    with open(stage1_file, "w") as f:
        json.dump({
            "domain": "example.com",
            "total": 3,
            "timestamp": "2026-11-06T00:00:00Z",
            "subdomains": [
                {"name": "ok.example.com", "sources": ["seed"]},
                {"name": "redir.example.com", "sources": ["seed"]},
                {"name": "dead.example.com", "sources": ["seed"]},
            ],
        }, f)

    # Mock probe_single_host
    def mock_probe(host, timeout):
        if "ok" in host:
            return _categorize_host(host, f"https://{host}", 200, 85.2, title="OK Page")
        if "redir" in host:
            return _categorize_host(host, f"https://{host}", 302, 60.1)
        return _categorize_host(host, f"https://{host}", None, None, error="Unreachable")

    monkeypatch.setattr("stages.stage2_verify.probe_single_host", mock_probe)

    progress_events = []
    res = run_stage2(
        scan_dir=temp_scan_dir,
        progress_callback=lambda p, msg: progress_events.append((p, msg)),
        concurrency=5,
    )

    stage2_file = os.path.join(temp_scan_dir, "stage2_live_hosts.json")
    assert os.path.exists(stage2_file)
    validate_schema(res, STAGE2_SCHEMA)

    assert res["summary"]["200_ok"] == 1
    assert res["summary"]["redirects"] == 1
    assert res["summary"]["unreachable"] == 1

    # Stage 2 progress reaches 75%
    assert any(p == 75 for p, _ in progress_events)
    assert all(35 <= p <= 75 for p, _ in progress_events)


# ---------------------------------------------------------------------------
# 4. Stage 3 (Artifact Generation & Capture) Tests
# ---------------------------------------------------------------------------

def test_stage3_captures_previews_and_consolidates_final(temp_scan_dir, monkeypatch):
    # Seed stage 1 and stage 2 files
    with open(os.path.join(temp_scan_dir, "stage1_subdomains.json"), "w") as f:
        json.dump({
            "domain": "example.com",
            "total": 2,
            "timestamp": "2026-11-06T00:00:00Z",
            "subdomains": [
                {"name": "ok1.example.com", "sources": ["seed"]},
                {"name": "dead.example.com", "sources": ["seed"]},
            ],
        }, f)

    with open(os.path.join(temp_scan_dir, "stage2_live_hosts.json"), "w") as f:
        json.dump({
            "domain": "example.com",
            "total_scanned": 2,
            "timestamp": "2026-11-06T00:00:00Z",
            "summary": {"200_ok": 1, "redirects": 0, "client_errors": 0, "server_errors": 0, "unreachable": 1},
            "live_hosts": [
                {"host": "ok1.example.com", "url": "https://ok1.example.com", "status_code": 200, "category": "200 OK", "is_200": True, "response_time_ms": 110.0, "title": "Home", "error": None},
                {"host": "dead.example.com", "url": "https://dead.example.com", "status_code": None, "category": "unreachable", "is_200": False, "response_time_ms": None, "title": None, "error": "timeout"},
            ],
        }, f)

    # Mock screenshot capture to generate SVG preview
    def mock_capture(url, output_png, host, resp_time, per_host_timeout):
        svg_file = os.path.splitext(output_png)[0] + ".svg"
        generate_svg_preview(host, url, resp_time, svg_file)
        return True, os.path.basename(svg_file)

    monkeypatch.setattr("stages.stage3_capture.capture_screenshot", mock_capture)

    progress_events = []
    final_res = run_stage3(
        scan_dir=temp_scan_dir,
        progress_callback=lambda p, msg: progress_events.append((p, msg)),
    )

    stage3_file = os.path.join(temp_scan_dir, "stage3_final.json")
    assert os.path.exists(stage3_file)
    validate_schema(final_res, STAGE3_SCHEMA)

    # Check that only verified 200 OK assets have screenshots
    live_map = {h["host"]: h for h in final_res["live_hosts"]}
    assert live_map["ok1.example.com"]["screenshot"] is not None
    assert live_map["ok1.example.com"]["screenshot"].startswith("screenshots/")
    assert live_map["dead.example.com"]["screenshot"] is None

    # Check progress ends at 100%
    assert any(p == 100 for p, _ in progress_events)
    assert all(75 <= p <= 100 for p, _ in progress_events)


# ---------------------------------------------------------------------------
# 5. State Machine Orchestration, Idempotency & Clean Failure Termination
# ---------------------------------------------------------------------------

def test_state_machine_idempotency_skips_stage1_when_cached(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    scan_folder = "example.com_20261106_120000_12345678"
    scan_dir = data_dir / scan_folder
    scan_dir.mkdir(parents=True, exist_ok=True)

    # Pre-populate stage1_subdomains.json
    s1_file = scan_dir / "stage1_subdomains.json"
    with open(s1_file, "w") as f:
        json.dump({
            "domain": "example.com",
            "total": 1,
            "timestamp": "2026-11-06T00:00:00Z",
            "subdomains": [{"name": "cached.example.com", "sources": ["cached"]}],
        }, f)

    # Mock stage 1 to raise an exception if it's called
    def fail_if_stage1_called(*args, **kwargs):
        raise RuntimeError("Stage 1 should have been skipped!")

    monkeypatch.setattr("stages.state_machine.run_stage1", fail_if_stage1_called)
    monkeypatch.setattr("stages.stage2_verify.probe_single_host", lambda h, t: _categorize_host(h, f"https://{h}", 200, 50.0))
    monkeypatch.setattr("stages.stage3_capture.capture_screenshot", lambda *a, **k: (True, "cached.svg"))

    events = []
    sm = ReconStateMachine(
        domain="example.com",
        data_dir=str(data_dir),
        scan_folder_name=scan_folder,
        skip_stage1_if_cached=True,
        telemetry_callback=lambda ev: events.append(ev),
    )

    result = sm.run()
    assert sm.status == "completed"
    assert result["summary"]["total_subdomains"] == 1
    # Verify stage1 skip notification was emitted
    assert any("Skipping passive lookups" in ev["message"] for ev in events)


def test_clean_failure_termination_preserves_completed_stage_files(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    scan_folder = "example.com_20261106_120000_failtest"
    scan_dir = data_dir / scan_folder

    # Let Stage 1 succeed
    monkeypatch.setattr("stages.stage1_harvest.harvest_crtsh", lambda d: [f"sub.{d}"])
    monkeypatch.setattr("stages.stage1_harvest.harvest_alienvault", lambda d: [])
    monkeypatch.setattr("stages.stage1_harvest.harvest_wayback", lambda d: [])
    monkeypatch.setattr("stages.stage1_harvest.harvest_certspotter", lambda d: [])
    monkeypatch.setattr("stages.stage1_harvest.harvest_anubis", lambda d: [])
    monkeypatch.setattr("stages.stage1_harvest.harvest_hackertarget", lambda d: [])

    # Force Stage 2 to fail with an error
    def failing_stage2(*args, **kwargs):
        raise ConnectionResetError("Simulated socket pool exhaustion")

    monkeypatch.setattr("stages.state_machine.run_stage2", failing_stage2)

    events = []
    sm = ReconStateMachine(
        domain="example.com",
        data_dir=str(data_dir),
        scan_folder_name=scan_folder,
        telemetry_callback=lambda ev: events.append(ev),
    )

    with pytest.raises(ConnectionResetError):
        sm.run()

    assert sm.status == "failed"
    assert "Simulated socket pool exhaustion" in (sm.error_context or "")

    # Verify Stage 1 files were preserved!
    assert (scan_dir / "stage1_subdomains.json").exists()
    assert (scan_dir / "manifest.json").exists()

    with open(scan_dir / "manifest.json") as f:
        manifest = json.load(f)
    assert manifest["stages"]["stage1"]["status"] == "completed"
    assert manifest["stages"]["stage2"]["status"] == "failed"
    assert "Simulated socket pool exhaustion" in manifest["stages"]["stage2"]["error"]


# ---------------------------------------------------------------------------
# 6. Runner API Server Endpoints Tests
# ---------------------------------------------------------------------------

def test_runner_api_endpoints(tmp_path, monkeypatch):
    import runner
    from unittest.mock import MagicMock

    data_dir = tmp_path / "runner_data"
    data_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(runner, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(runner, "INDEX_FILE", str(data_dir / "scans.json"))

    scan_folder = "example.com_20261106_120000_apitest1"
    scan_dir = data_dir / scan_folder
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "screenshots").mkdir(parents=True, exist_ok=True)

    # Write stage files
    manifest = {
        "target_domain": "example.com",
        "timestamp": "2026-11-06T00:00:00Z",
        "total_unique_subdomains": 1,
        "stages": {
            "stage1": {"status": "completed"},
            "stage2": {"status": "completed"},
            "stage3": {"status": "completed"},
        },
    }
    stage1 = {
        "domain": "example.com",
        "total": 1,
        "timestamp": "2026-11-06T00:00:00Z",
        "subdomains": [{"name": "api.example.com", "sources": ["test"]}],
    }
    stage2 = {
        "domain": "example.com",
        "total_scanned": 1,
        "timestamp": "2026-11-06T00:00:00Z",
        "summary": {"200_ok": 1, "redirects": 0, "client_errors": 0, "server_errors": 0, "unreachable": 0},
        "live_hosts": [{"host": "api.example.com", "url": "https://api.example.com", "status_code": 200, "category": "200 OK", "is_200": True}],
    }
    stage3 = {
        "id": scan_folder,
        "domain": "example.com",
        "started_at": "2026-11-06T00:00:00Z",
        "finished_at": "2026-11-06T00:00:05Z",
        "status": "completed",
        "manifest": manifest,
        "summary": {"total_subdomains": 1, "total_responding": 1, "total_http_200": 1},
        "subdomains": stage1["subdomains"],
        "live_hosts": stage2["live_hosts"],
    }

    with open(scan_dir / "manifest.json", "w") as f:
        json.dump(manifest, f)
    with open(scan_dir / "stage1_subdomains.json", "w") as f:
        json.dump(stage1, f)
    with open(scan_dir / "stage2_live_hosts.json", "w") as f:
        json.dump(stage2, f)
    with open(scan_dir / "stage3_final.json", "w") as f:
        json.dump(stage3, f)
    with open(scan_dir / "screenshots" / "api_example_com.svg", "w") as f:
        f.write("<svg></svg>")

    # Test load_scans
    scans = runner.load_scans()
    assert scan_folder in scans
    assert scans[scan_folder]["domain"] == "example.com"

    # Test task telemetry storage
    task_id = "test-task-123"
    runner.TASKS[task_id] = {
        "task_id": task_id,
        "status": "running",
        "stage": "stage2",
        "progress": 55,
        "message": "Probing hosts...",
    }

    # Simulate GET requests via a mock handler
    class MockRequest:
        def __init__(self, path):
            self.path = path

    def invoke_get(path):
        handler = runner.ReconHandler.__new__(runner.ReconHandler)
        handler.path = path
        handler.headers = {}
        sent_status = []
        sent_content = []

        def mock_send_raw(status, content_type, body_bytes):
            sent_status.append(status)
            sent_content.append(body_bytes)

        handler._send_raw = mock_send_raw
        handler.do_GET()
        return sent_status[0], sent_content[0]

    # Test /api/task-status
    status, body = invoke_get(f"/api/task-status?id={task_id}")
    assert status == 200
    assert json.loads(body)["progress"] == 55

    # Test /api/scans
    status, body = invoke_get("/api/scans")
    assert status == 200
    assert any(s["id"] == scan_folder for s in json.loads(body))

    # Test /api/scans/{id}/manifest
    status, body = invoke_get(f"/api/scans/{scan_folder}/manifest")
    assert status == 200
    assert json.loads(body)["target_domain"] == "example.com"

    # Test /api/scans/{id}/stage1
    status, body = invoke_get(f"/api/scans/{scan_folder}/stage1")
    assert status == 200
    assert json.loads(body)["total"] == 1

    # Test /api/scans/{id}/stage2
    status, body = invoke_get(f"/api/scans/{scan_folder}/stage2")
    assert status == 200
    assert json.loads(body)["summary"]["200_ok"] == 1

    # Test /api/scans/{id}/screenshots/{filename}
    status, body = invoke_get(f"/api/scans/{scan_folder}/screenshots/api_example_com.svg")
    assert status == 200
    assert b"<svg></svg>" in body

    # Test /api/scans/{id}/export (CSV)
    status, body = invoke_get(f"/api/scans/{scan_folder}/export?format=csv")
    assert status == 200
    assert b"api.example.com" in body

    # Test /api/scans/{id}/report
    status, body = invoke_get(f"/api/scans/{scan_folder}/report")
    assert status == 200
    assert b"Reconnaissance Report: example.com" in body

