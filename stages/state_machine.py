"""Decoupled Three-Stage Reconnaissance State Machine.

Orchestrates sequential execution of:
- Stage 1: Harvesting & Normalization (0% - 35%)
- Stage 2: Availability & Status Verification (35% - 75%)
- Stage 3: Artifact Generation & Capture (75% - 100%)

Handles idempotency, directory isolation, telemetry reporting,
JSON schema validation, and clean error termination preserving stage artifacts.
"""

import json
import os
import secrets
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from stages.schemas import (
    MANIFEST_SCHEMA,
    STAGE1_SCHEMA,
    STAGE2_SCHEMA,
    STAGE3_SCHEMA,
    validate_schema,
)
from stages.stage1_harvest import run_stage1, validate_target_domain
from stages.stage2_verify import run_stage2
from stages.stage3_capture import run_stage3


class ReconStateMachine:
    def __init__(
        self,
        domain: str,
        data_dir: str = "data",
        scan_folder_name: Optional[str] = None,
        concurrency: int = 30,
        socket_timeout: float = 2.5,
        screenshot_cap: int = 30,
        screenshot_timeout: float = 8.0,
        skip_stage1_if_cached: bool = True,
        telemetry_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.raw_domain = domain
        self.domain = validate_target_domain(domain)
        self.data_dir = os.path.abspath(data_dir)
        self.concurrency = concurrency
        self.socket_timeout = socket_timeout
        self.screenshot_cap = screenshot_cap
        self.screenshot_timeout = screenshot_timeout
        self.skip_stage1_if_cached = skip_stage1_if_cached
        self.telemetry_callback = telemetry_callback

        # Distinct timestamped directory hierarchy: {domain}_{YYYYMMDD_HHMMSS}_{random8char}
        if scan_folder_name:
            self.scan_folder = scan_folder_name
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rand8 = secrets.token_hex(4)  # 8 hex chars
            self.scan_folder = f"{self.domain}_{ts}_{rand8}"

        self.scan_dir = os.path.join(self.data_dir, self.scan_folder)
        self.manifest_file = os.path.join(self.scan_dir, "manifest.json")
        self.stage1_file = os.path.join(self.scan_dir, "stage1_subdomains.json")
        self.stage2_file = os.path.join(self.scan_dir, "stage2_live_hosts.json")
        self.stage3_file = os.path.join(self.scan_dir, "stage3_final.json")
        self.screenshots_dir = os.path.join(self.scan_dir, "screenshots")

        self.current_stage = "pending"
        self.progress = 0
        self.status = "pending"
        self.error_context: Optional[str] = None

    def emit_telemetry(self, progress: int, stage: str, message: str, **kwargs):
        self.progress = progress
        self.current_stage = stage
        payload = {
            "domain": self.domain,
            "scan_id": self.scan_folder,
            "scan_dir": self.scan_dir,
            "status": self.status,
            "stage": stage,
            "progress": progress,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }
        if self.telemetry_callback:
            try:
                self.telemetry_callback(payload)
            except Exception:
                pass

    def run(self) -> Dict[str, Any]:
        """Execute the state machine through stages 1, 2, and 3.

        Preserves all completed artifacts on failure and records specific error context.
        """
        os.makedirs(self.scan_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)
        self.status = "running"
        self.emit_telemetry(0, "stage1", f"Initializing recon state machine for {self.domain}...")

        cfg = {
            "concurrency": self.concurrency,
            "timeout": self.socket_timeout,
            "screenshot_cap": self.screenshot_cap,
        }

        # -------------------------------------------------------------------
        # STAGE 1: Harvesting & Normalization (0% - 35%)
        # -------------------------------------------------------------------
        self.current_stage = "stage1"
        try:
            # Idempotency check: skip Stage 1 if stage1_subdomains.json already exists
            if self.skip_stage1_if_cached and os.path.exists(self.stage1_file):
                self.emit_telemetry(35, "stage1", f"Stage 1 cached artifact found ({self.stage1_file}). Skipping passive lookups.")
                with open(self.stage1_file, "r", encoding="utf-8") as f:
                    stage1_data = json.load(f)
                validate_schema(stage1_data, STAGE1_SCHEMA)
            else:
                def stage1_progress(pct: int, msg: str):
                    self.emit_telemetry(pct, "stage1", msg)

                stage1_data = run_stage1(
                    domain=self.domain,
                    scan_dir=self.scan_dir,
                    progress_callback=stage1_progress,
                    execution_config=cfg,
                )
        except Exception as e:
            self._handle_failure("stage1", str(e))
            raise

        # -------------------------------------------------------------------
        # STAGE 2: Availability & Status Verification (35% - 75%)
        # -------------------------------------------------------------------
        self.current_stage = "stage2"
        try:
            # Validate input data contract
            validate_schema(stage1_data, STAGE1_SCHEMA)

            def stage2_progress(pct: int, msg: str):
                self.emit_telemetry(pct, "stage2", msg)

            stage2_data = run_stage2(
                scan_dir=self.scan_dir,
                progress_callback=stage2_progress,
                concurrency=self.concurrency,
                socket_timeout=self.socket_timeout,
            )
        except Exception as e:
            self._handle_failure("stage2", str(e))
            raise

        # -------------------------------------------------------------------
        # STAGE 3: Artifact Generation & Capture (75% - 100%)
        # -------------------------------------------------------------------
        self.current_stage = "stage3"
        try:
            # Validate input data contract
            validate_schema(stage2_data, STAGE2_SCHEMA)

            def stage3_progress(pct: int, msg: str):
                self.emit_telemetry(pct, "stage3", msg)

            stage3_data = run_stage3(
                scan_dir=self.scan_dir,
                progress_callback=stage3_progress,
                batch_cap=self.screenshot_cap,
                per_host_timeout=self.screenshot_timeout,
            )
        except Exception as e:
            self._handle_failure("stage3", str(e))
            raise

        # Final success transition
        self.status = "completed"
        self.emit_telemetry(
            100,
            "completed",
            f"Recon completed successfully for {self.domain}! {stage3_data['summary']['total_subdomains']} subdomains, {stage3_data['summary']['total_http_200']} live 200 OK assets.",
            final_data=stage3_data,
        )

        return stage3_data

    def _handle_failure(self, stage: str, error_message: str):
        """Clean termination preserving completed stage files and recording error context."""
        self.status = "failed"
        self.error_context = f"{stage} error: {error_message}"
        traceback_str = traceback.format_exc()

        # Update manifest.json with failure state if manifest exists or create one
        manifest_data = {}
        if os.path.exists(self.manifest_file):
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            except Exception:
                pass

        if "stages" not in manifest_data:
            manifest_data["stages"] = {"stage1": {}, "stage2": {}, "stage3": {}}

        if stage in manifest_data["stages"]:
            manifest_data["stages"][stage]["status"] = "failed"
            manifest_data["stages"][stage]["error"] = error_message
            manifest_data["stages"][stage]["finished_at"] = datetime.now(timezone.utc).isoformat()

        manifest_data.setdefault("target_domain", self.domain)
        manifest_data.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        manifest_data.setdefault("total_unique_subdomains", 0)

        try:
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)
        except Exception:
            pass

        self.emit_telemetry(
            self.progress,
            stage,
            f"Failed at {stage}: {error_message}",
            error=error_message,
            traceback=traceback_str,
        )


def execute_recon(
    domain: str,
    data_dir: str = "data",
    concurrency: int = 30,
    socket_timeout: float = 2.5,
    screenshot_cap: int = 30,
    skip_stage1_if_cached: bool = True,
    telemetry_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Convenience functional interface to launch the state machine."""
    sm = ReconStateMachine(
        domain=domain,
        data_dir=data_dir,
        concurrency=concurrency,
        socket_timeout=socket_timeout,
        screenshot_cap=screenshot_cap,
        skip_stage1_if_cached=skip_stage1_if_cached,
        telemetry_callback=telemetry_callback,
    )
    return sm.run()
