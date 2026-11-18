from __future__ import annotations

import dataclasses
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from plesk_audit.collectors import IMPLEMENTED
from plesk_audit.collectors.base import CollectorContext
from plesk_audit.config import load_config
from plesk_audit.models import AuditRun, CollectorResult, Evidence
from plesk_audit.reporters.html_report import render_html
from plesk_audit.reporters.json_report import build_documents, dumps
from plesk_audit.runner import run_audit, write_reports
from tests.conftest import FIXED_NOW
from tests.test_config import REPO_CONFIG

RUN_ID = "0123456789abcdef0123456789abcdef"


def audit(ctx: CollectorContext, **kwargs: Any) -> AuditRun:
    return run_audit(load_config(REPO_CONFIG), ctx, run_id=RUN_ID, **kwargs)


def test_run_audit_statuses_and_metadata(healthy_host_ctx: CollectorContext) -> None:
    result = audit(healthy_host_ctx)
    statuses = {c.name: (c.status, c.message) for c in result.collectors}
    assert statuses["system"] == ("ok", None)
    assert statuses["network"][0] == "partial"
    assert statuses["packages"] == ("ok", None)
    assert statuses["web_stack"] == ("skipped", "not implemented yet")
    assert statuses["logs"] == ("skipped", "disabled in configuration")
    assert result.run.hostname == "host.example.test"
    assert result.run.plesk_version == "18.0.82.31"
    assert result.run.read_only is True and result.run.external_checks is False
    assert any(item.startswith("collector network partial") for item in result.limitations)


def test_collector_exception_is_isolated(healthy_host_ctx: CollectorContext) -> None:
    def broken(ctx: CollectorContext) -> CollectorResult:
        raise RuntimeError("secret=should-not-leak")

    result = audit(healthy_host_ctx, collectors={**IMPLEMENTED, "network": broken})
    network = next(c for c in result.collectors if c.name == "network")
    assert (network.status, network.message) == ("error", "unexpected RuntimeError")
    assert "should-not-leak" not in dumps(build_documents(result))


def test_json_output_is_deterministic(healthy_host_ctx: CollectorContext) -> None:
    first = {k: dumps(v) for k, v in build_documents(audit(healthy_host_ctx)).items()}
    second = {k: dumps(v) for k, v in build_documents(audit(healthy_host_ctx)).items()}
    assert first == second
    manifest = json.loads(first["manifest.json"])
    assert manifest["schema_version"] == "1.0"
    assert manifest["run"]["started_at"] == "2026-01-02T03:04:05Z"
    findings = json.loads(first["findings.json"])["findings"]
    required = {
        "id",
        "title",
        "domain",
        "severity",
        "confidence",
        "status",
        "summary",
        "evidence_refs",
        "impact",
        "recommendation",
        "detected_at",
        "references",
    }
    assert all(set(f) == required for f in findings)


def test_html_escapes_host_derived_text(healthy_host_ctx: CollectorContext) -> None:
    result = audit(healthy_host_ctx)
    payload = '<script>alert("x")</script>'
    result.run.hostname = payload
    result.collectors[0].evidence.append(
        Evidence("EV-x", "system", payload, FIXED_NOW, {"value": payload})
    )
    result.findings[0] = dataclasses.replace(result.findings[0], title=payload)
    html = render_html(result)
    assert "<script" not in html
    assert "&lt;script&gt;" in html
    assert "Content-Security-Policy" in html
    assert "http://" not in html and "https://" not in html


def test_write_reports_is_private_and_never_overwrites(
    tmp_path: Path, healthy_host_ctx: CollectorContext
) -> None:
    result = audit(healthy_host_ctx)
    run_dir = write_reports(result, tmp_path / "reports", frozenset({"json", "html"}))
    assert sorted(p.name for p in run_dir.iterdir()) == [
        "evidence.json",
        "findings.json",
        "manifest.json",
        "report.html",
    ]
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in run_dir.iterdir())
    with pytest.raises(FileExistsError):
        write_reports(result, tmp_path / "reports", frozenset({"json"}))
