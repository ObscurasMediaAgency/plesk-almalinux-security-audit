from __future__ import annotations

from typing import Any

from plesk_audit.collectors import network, system
from plesk_audit.collectors.base import CollectorContext
from plesk_audit.models import Evidence, Finding
from plesk_audit.rules import evaluate
from tests.conftest import FIXED_NOW


def findings_for(ctx: CollectorContext) -> list[Finding]:
    evidence = system.collect(ctx).evidence + network.collect(ctx).evidence
    findings, failures = evaluate(evidence, FIXED_NOW)
    assert failures == []
    return findings


def ev(evidence_id: str, data: dict[str, Any]) -> Evidence:
    return Evidence(evidence_id, "test", "fixture", FIXED_NOW, data)


def test_healthy_fixture_produces_expected_findings(healthy_host_ctx: CollectorContext) -> None:
    findings = findings_for(healthy_host_ctx)
    assert [f.id for f in findings] == ["NET-001-tcp-3306", "NET-002"]
    db = findings[0]
    assert (db.severity, db.confidence, db.status) == ("medium", "medium", "needs_review")
    assert "mariadbd" in db.summary
    assert db.evidence_refs == ["EV-network-listeners"]
    assert "tcp/22" in findings[1].summary and "tcp/7080" not in findings[1].summary


def test_loopback_database_is_not_flagged() -> None:
    listeners = [{"protocol": "tcp", "port": 3306, "bind_scope": "loopback", "processes": []}]
    findings, _ = evaluate([ev("EV-network-listeners", {"listeners": listeners})], FIXED_NOW)
    assert findings == []


def test_unexpected_os_is_info_needs_review() -> None:
    data = {"ID": "rocky", "VERSION_ID": "9.4"}
    findings, _ = evaluate([ev("EV-system-os-release", data)], FIXED_NOW)
    assert [(f.id, f.severity, f.status) for f in findings] == [("SYS-001", "info", "needs_review")]


def test_unsynchronized_clock() -> None:
    data = {"ntp_enabled": True, "ntp_synchronized": False}
    findings, _ = evaluate([ev("EV-system-time", data)], FIXED_NOW)
    assert [(f.id, f.severity) for f in findings] == [("SYS-002", "low")]
    assert "not synchronized" in findings[0].summary


def test_failing_rule_is_reported_not_raised() -> None:
    def broken(index: object, now: object) -> list[Finding]:
        raise KeyError("boom")

    findings, failures = evaluate([], FIXED_NOW, rules=[broken])
    assert findings == [] and failures == ["rule broken failed: KeyError"]
