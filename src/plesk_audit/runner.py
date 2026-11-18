"""Audit orchestration: collector selection, rule evaluation and report output."""

from __future__ import annotations

import logging
import os
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

from plesk_audit import __version__
from plesk_audit.collectors import IMPLEMENTED, CollectorContext, CollectorFn
from plesk_audit.config import KNOWN_COLLECTORS, AuditConfig, ConfigError, load_config
from plesk_audit.external import Prober, SocketProber, run_external_checks
from plesk_audit.file_reader import BoundedFileReader
from plesk_audit.models import AuditRun, CollectorResult, Evidence, RunMetadata
from plesk_audit.redaction import redact_text
from plesk_audit.reporters.html_report import write_html_report
from plesk_audit.reporters.json_report import write_json_reports
from plesk_audit.rules import evaluate
from plesk_audit.safe_exec import SafeCommandRunner

log = logging.getLogger(__name__)

STATIC_LIMITATIONS = (
    (
        "A clean result does not prove the host is uncompromised; log rotation, tampering, "
        "root-level attacker access and incomplete telemetry can conceal activity."
    ),
    (
        "Listener exposure is assessed against firewalld only; direct nftables/iptables rules, "
        "Plesk Firewall rules not applied via firewalld and upstream/provider firewalls are not "
        "evaluated."
    ),
)


EXTERNAL_LIMITATIONS = (
    (
        "External results reflect only the auditor's source address and network path; "
        "firewall allow-lists, geo-blocking or upstream filtering can produce different "
        "results for other clients."
    ),
    (
        "Only TCP connects and implicit-TLS handshakes are tested; STARTTLS services, UDP, "
        "application-layer behaviour and vulnerabilities are not assessed."
    ),
)


def utc_now() -> datetime:
    return datetime.now(UTC)


def _skip_reason(name: str, config: AuditConfig, profile: str) -> str | None:
    """Return why a collector is skipped, or None if it should run."""
    if not config.collectors.get(name, False):
        return "disabled in configuration"
    if name == "persistence" and profile != "triage":
        return "requires profile 'triage'"
    if name == "logs" and (profile != "triage" or not config.logs.enabled):
        return "log triage requires profile 'triage' and logs.enabled"
    return None


def _run_collector(name: str, fn: CollectorFn, ctx: CollectorContext) -> CollectorResult:
    try:
        result = fn(ctx)
    except Exception as exc:  # noqa: BLE001 - one collector must not abort the run
        log.warning("collector %s raised %s", name, type(exc).__name__)
        return CollectorResult(name, "error", [], f"unexpected {type(exc).__name__}")
    if result.message:
        result.message = redact_text(result.message)
    return result


def _evidence_value(evidence: Mapping[str, Evidence], ev_id: str, key: str) -> str | None:
    ev = evidence.get(ev_id)
    value = ev.data.get(key) if ev else None
    return str(value) if value is not None else None


def run_audit(
    config: AuditConfig,
    ctx: CollectorContext,
    *,
    profile: str | None = None,
    run_id: str | None = None,
    collectors: Mapping[str, CollectorFn] = IMPLEMENTED,
) -> AuditRun:
    active_profile = profile or config.profile
    started = ctx.now()
    results: list[CollectorResult] = []
    for name in KNOWN_COLLECTORS:
        reason = _skip_reason(name, config, active_profile)
        fn = collectors.get(name)
        if reason is None and fn is not None:
            results.append(_run_collector(name, fn, ctx))
        else:
            results.append(CollectorResult(name, "skipped", [], reason or "not implemented yet"))
        log.info("collector %s: %s", name, results[-1].status)

    evidence = {e.evidence_id: e for r in results for e in r.evidence}
    findings, rule_failures = evaluate(evidence.values(), ctx.now())
    limitations = list(STATIC_LIMITATIONS)
    limitations += [
        f"collector {r.name} {r.status}: {r.message}"
        for r in results
        if r.status in ("error", "partial")
    ]
    limitations += rule_failures

    run = RunMetadata(
        run_id=run_id or uuid.uuid4().hex,
        tool_version=__version__,
        profile=active_profile,
        started_at=started,
        finished_at=ctx.now(),
        hostname=_evidence_value(evidence, "EV-system-hostname", "hostname"),
        os=_evidence_value(evidence, "EV-system-os-release", "PRETTY_NAME"),
        plesk_version=(
            _evidence_value(evidence, "EV-plesk-version", "version")
            or _evidence_value(evidence, "EV-system-plesk-version", "version")
        ),
    )
    return AuditRun(run, results, findings, limitations)


def write_reports(audit: AuditRun, output_root: Path, formats: frozenset[str]) -> Path:
    """Write reports into a new owner-only run directory; existing runs are never overwritten."""
    output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = audit.run.started_at.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / f"run-{stamp}-{audit.run.run_id[:8]}"
    run_dir.mkdir(mode=0o700)
    os.chmod(run_dir, 0o700)
    if "json" in formats:
        write_json_reports(audit, run_dir)
    if "html" in formats:
        write_html_report(audit, run_dir)
    return run_dir


def collect(
    config_path: Path,
    output_dir: Path | None,
    profile: str | None = None,
    *,
    now: Callable[[], datetime] = utc_now,
) -> Path:
    config = load_config(config_path)
    ctx = CollectorContext(
        commands=SafeCommandRunner(
            config.runtime.command_timeout_seconds, config.runtime.max_command_output_bytes
        ),
        files=BoundedFileReader(config.runtime.max_file_bytes),
        now=now,
        logs=config.logs,
    )
    audit = run_audit(config, ctx, profile=profile)
    return write_reports(audit, output_dir or config.output_directory, config.output_formats)


def run_external(
    config: AuditConfig,
    ctx: CollectorContext,
    prober: Prober,
    *,
    run_id: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> AuditRun:
    """Run the opt-in external validation; local collectors are not executed."""
    if not config.external.enabled or not config.external.allowed_targets:
        raise ConfigError("external validation requires audit.external_checks and targets")
    started = ctx.now()
    result = run_external_checks(
        config.external,
        ctx,
        prober,
        timeout=config.runtime.command_timeout_seconds,
        sleep=sleep,
    )
    if result.message:
        result.message = redact_text(result.message)
    findings, rule_failures = evaluate(result.evidence, ctx.now())
    limitations = [*STATIC_LIMITATIONS[:1], *EXTERNAL_LIMITATIONS]
    if result.status in ("error", "partial"):
        limitations.append(f"collector external {result.status}: {result.message}")
    limitations += rule_failures
    run = RunMetadata(
        run_id=run_id or uuid.uuid4().hex,
        tool_version=__version__,
        profile="external",
        started_at=started,
        finished_at=ctx.now(),
        hostname=None,
        os=None,
        plesk_version=None,
        external_checks=True,
    )
    return AuditRun(run, [result], findings, limitations)


def external(
    config_path: Path,
    output_dir: Path | None,
    *,
    prober: Prober | None = None,
    now: Callable[[], datetime] = utc_now,
) -> Path:
    config = load_config(config_path)
    ctx = CollectorContext(
        commands=SafeCommandRunner(
            config.runtime.command_timeout_seconds, config.runtime.max_command_output_bytes
        ),
        files=BoundedFileReader(config.runtime.max_file_bytes),
        now=now,
    )
    audit = run_external(config, ctx, prober or SocketProber())
    return write_reports(audit, output_dir or config.output_directory, config.output_formats)
