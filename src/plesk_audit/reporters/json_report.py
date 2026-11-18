"""JSON serialization and private file output."""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from plesk_audit.models import AuditRun

SCHEMA_VERSION = "1.0"


def to_jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    return value


def dumps(value: Any) -> str:
    return json.dumps(to_jsonable(value), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_private(path: Path, text: str) -> None:
    """Create a new file readable only by the owner; never overwrite."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_documents(audit: AuditRun) -> dict[str, dict[str, Any]]:
    run_id = audit.run.run_id
    collectors = [
        {
            "name": c.name,
            "status": c.status,
            "message": c.message,
            "evidence_ids": [e.evidence_id for e in c.evidence],
        }
        for c in audit.collectors
    ]
    evidence = [e for c in audit.collectors for e in c.evidence]
    return {
        "manifest.json": {
            "schema_version": SCHEMA_VERSION,
            "run": audit.run,
            "collectors": collectors,
            "limitations": audit.limitations,
        },
        "evidence.json": {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "evidence": sorted(evidence, key=lambda e: e.evidence_id),
        },
        "findings.json": {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "findings": audit.findings,
        },
    }


def write_json_reports(audit: AuditRun, directory: Path) -> list[Path]:
    written: list[Path] = []
    for name, document in build_documents(audit).items():
        path = directory / name
        write_private(path, dumps(document))
        written.append(path)
    return written
