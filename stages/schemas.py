"""JSON Schemas and validator for the three-stage reconnaissance state machine."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple


class SchemaValidationError(ValueError):
    """Raised when an artifact fails standard JSON schema validation."""
    pass


# ---------------------------------------------------------------------------
# Standard JSON Schema Definitions (Draft-07 Compatible)
# ---------------------------------------------------------------------------

MANIFEST_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "ManifestSchema",
    "type": "object",
    "required": ["target_domain", "timestamp", "total_unique_subdomains", "stages"],
    "properties": {
        "target_domain": {"type": "string"},
        "timestamp": {"type": "string"},
        "total_unique_subdomains": {"type": "integer", "minimum": 0},
        "execution_config": {
            "type": "object",
            "properties": {
                "concurrency": {"type": "integer"},
                "timeout": {"type": "number"},
                "screenshot_cap": {"type": "integer"},
            },
        },
        "stages": {
            "type": "object",
            "required": ["stage1", "stage2", "stage3"],
            "properties": {
                "stage1": {
                    "type": "object",
                    "required": ["status"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["pending", "running", "completed", "failed", "skipped"],
                        },
                        "started_at": {"type": ["string", "null"]},
                        "finished_at": {"type": ["string", "null"]},
                        "output_file": {"type": ["string", "null"]},
                        "count": {"type": ["integer", "null"]},
                        "error": {"type": ["string", "null"]},
                    },
                },
                "stage2": {
                    "type": "object",
                    "required": ["status"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["pending", "running", "completed", "failed", "skipped"],
                        },
                        "started_at": {"type": ["string", "null"]},
                        "finished_at": {"type": ["string", "null"]},
                        "output_file": {"type": ["string", "null"]},
                        "total_scanned": {"type": ["integer", "null"]},
                        "total_200": {"type": ["integer", "null"]},
                        "error": {"type": ["string", "null"]},
                    },
                },
                "stage3": {
                    "type": "object",
                    "required": ["status"],
                    "properties": {
                        "status": {
                            "type": "string",
                            "enum": ["pending", "running", "completed", "failed", "skipped"],
                        },
                        "started_at": {"type": ["string", "null"]},
                        "finished_at": {"type": ["string", "null"]},
                        "output_file": {"type": ["string", "null"]},
                        "total_captured": {"type": ["integer", "null"]},
                        "error": {"type": ["string", "null"]},
                    },
                },
            },
        },
    },
}

STAGE1_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Stage1SubdomainsSchema",
    "type": "object",
    "required": ["domain", "total", "timestamp", "subdomains"],
    "properties": {
        "domain": {"type": "string"},
        "total": {"type": "integer", "minimum": 0},
        "timestamp": {"type": "string"},
        "sources_summary": {
            "type": "object",
            "additionalProperties": {"type": "integer"},
        },
        "subdomains": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "sources": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
    },
}

STAGE2_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Stage2LiveHostsSchema",
    "type": "object",
    "required": ["domain", "total_scanned", "timestamp", "summary", "live_hosts"],
    "properties": {
        "domain": {"type": "string"},
        "total_scanned": {"type": "integer", "minimum": 0},
        "timestamp": {"type": "string"},
        "summary": {
            "type": "object",
            "required": ["200_ok", "redirects", "client_errors", "server_errors", "unreachable"],
            "properties": {
                "200_ok": {"type": "integer", "minimum": 0},
                "redirects": {"type": "integer", "minimum": 0},
                "client_errors": {"type": "integer", "minimum": 0},
                "server_errors": {"type": "integer", "minimum": 0},
                "unreachable": {"type": "integer", "minimum": 0},
            },
        },
        "live_hosts": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["host", "url", "status_code", "category", "is_200"],
                "properties": {
                    "host": {"type": "string"},
                    "url": {"type": "string"},
                    "status_code": {"type": ["integer", "null"]},
                    "category": {
                        "type": "string",
                        "enum": ["200 OK", "redirect", "client_error", "server_error", "unreachable"],
                    },
                    "is_200": {"type": "boolean"},
                    "response_time_ms": {"type": ["number", "null"]},
                    "title": {"type": ["string", "null"]},
                    "error": {"type": ["string", "null"]},
                },
            },
        },
    },
}

STAGE3_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Stage3FinalSchema",
    "type": "object",
    "required": ["id", "domain", "started_at", "finished_at", "status", "summary", "subdomains", "live_hosts"],
    "properties": {
        "id": {"type": "string"},
        "domain": {"type": "string"},
        "started_at": {"type": "string"},
        "finished_at": {"type": "string"},
        "status": {"type": "string", "enum": ["completed", "failed"]},
        "manifest": {"type": "object"},
        "summary": {
            "type": "object",
            "required": ["total_subdomains", "total_responding", "total_http_200"],
            "properties": {
                "total_subdomains": {"type": "integer"},
                "total_responding": {"type": "integer"},
                "total_http_200": {"type": "integer"},
                "total_redirects": {"type": "integer"},
                "total_client_errors": {"type": "integer"},
                "total_server_errors": {"type": "integer"},
                "total_unreachable": {"type": "integer"},
                "screenshots_captured": {"type": "integer"},
                "avg_response_time_ms": {"type": ["number", "null"]},
            },
        },
        "subdomains": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "sources": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
        "live_hosts": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["host", "url", "status_code", "category", "is_200"],
                "properties": {
                    "host": {"type": "string"},
                    "url": {"type": "string"},
                    "status_code": {"type": ["integer", "null"]},
                    "category": {"type": "string"},
                    "is_200": {"type": "boolean"},
                    "response_time_ms": {"type": ["number", "null"]},
                    "screenshot": {"type": ["string", "null"]},
                    "screenshot_url": {"type": ["string", "null"]},
                    "title": {"type": ["string", "null"]},
                    "error": {"type": ["string", "null"]},
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Strict JSON Schema Validator
# ---------------------------------------------------------------------------

def _match_type(val: Any, expected_type: str) -> bool:
    if expected_type == "string":
        return isinstance(val, str)
    if expected_type == "integer":
        return isinstance(val, int) and not isinstance(val, bool)
    if expected_type == "number":
        return (isinstance(val, (int, float))) and not isinstance(val, bool)
    if expected_type == "boolean":
        return isinstance(val, bool)
    if expected_type == "array":
        return isinstance(val, list)
    if expected_type == "object":
        return isinstance(val, dict)
    if expected_type == "null":
        return val is None
    return True


def validate_schema(data: Any, schema: Dict[str, Any], path: str = "$") -> None:
    """Validate data against a JSON Schema. Raises SchemaValidationError on failure."""
    if not isinstance(schema, dict):
        return

    # Check type
    if "type" in schema:
        expected = schema["type"]
        if isinstance(expected, list):
            if not any(_match_type(data, t) for t in expected):
                types_str = " | ".join(expected)
                raise SchemaValidationError(
                    f"At {path}: expected one of [{types_str}], got {type(data).__name__} ({repr(data)})"
                )
        elif isinstance(expected, str):
            if not _match_type(data, expected):
                raise SchemaValidationError(
                    f"At {path}: expected {expected}, got {type(data).__name__} ({repr(data)})"
                )

    # If null and allowed, stop further checks
    if data is None:
        return

    # Check enum
    if "enum" in schema:
        if data not in schema["enum"]:
            raise SchemaValidationError(
                f"At {path}: value {repr(data)} is not in allowed enum {schema['enum']}"
            )

    # Number minimum / maximum
    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            raise SchemaValidationError(
                f"At {path}: value {data} is less than minimum {schema['minimum']}"
            )
        if "maximum" in schema and data > schema["maximum"]:
            raise SchemaValidationError(
                f"At {path}: value {data} is greater than maximum {schema['maximum']}"
            )

    # Object validation
    if isinstance(data, dict):
        required = schema.get("required", [])
        for field in required:
            if field not in data:
                raise SchemaValidationError(f"At {path}: missing required field '{field}'")

        properties = schema.get("properties", {})
        for key, val in data.items():
            if key in properties:
                validate_schema(val, properties[key], path=f"{path}.{key}")
            elif "additionalProperties" in schema:
                add_prop = schema["additionalProperties"]
                if isinstance(add_prop, dict):
                    validate_schema(val, add_prop, path=f"{path}.{key}")
                elif add_prop is False:
                    raise SchemaValidationError(f"At {path}: unexpected property '{key}'")

    # Array validation
    if isinstance(data, list):
        if "minItems" in schema and len(data) < schema["minItems"]:
            raise SchemaValidationError(f"At {path}: array length {len(data)} < minItems {schema['minItems']}")
        if "items" in schema:
            item_schema = schema["items"]
            for idx, item in enumerate(data):
                validate_schema(item, item_schema, path=f"{path}[{idx}]")
