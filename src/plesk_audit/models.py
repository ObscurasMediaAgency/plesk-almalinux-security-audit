from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
FindingStatus = Literal["observed", "needs_review", "confirmed", "not_applicable"]
CollectorStatus = Literal["ok", "partial", "skipped", "error"]


@dataclass(slots=True)
class Evidence:
    evidence_id: str
    collector: str
    source: str
    collected_at: datetime
    data: dict[str, Any] = field(default_factory=dict)
    redacted: bool = True


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    domain: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    summary: str
    evidence_refs: list[str]
    impact: str
    recommendation: str
    detected_at: datetime
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CollectorResult:
    name: str
    status: CollectorStatus
    evidence: list[Evidence] = field(default_factory=list)
    message: str | None = None


@dataclass(slots=True)
class RunMetadata:
    run_id: str
    tool_version: str
    profile: str
    started_at: datetime
    finished_at: datetime
    hostname: str | None
    os: str | None
    plesk_version: str | None
    read_only: bool = True
    external_checks: bool = False


@dataclass(slots=True)
class AuditRun:
    run: RunMetadata
    collectors: list[CollectorResult]
    findings: list[Finding]
    limitations: list[str]
