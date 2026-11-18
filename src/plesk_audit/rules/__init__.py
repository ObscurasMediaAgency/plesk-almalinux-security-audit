"""Rule registry and evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from plesk_audit.models import Evidence, Finding
from plesk_audit.rules import network_rules, system_rules
from plesk_audit.rules.base import Rule

RULES: Sequence[Rule] = (
    system_rules.os_matches_target,
    system_rules.time_synchronization,
    network_rules.backend_on_wildcard,
    network_rules.wildcard_listener_inventory,
)


def evaluate(
    evidence: Iterable[Evidence], now: datetime, rules: Sequence[Rule] = RULES
) -> tuple[list[Finding], list[str]]:
    """Run all rules; a failing rule is reported as a limitation, never silently ignored."""
    index = {item.evidence_id: item for item in evidence}
    findings: list[Finding] = []
    failures: list[str] = []
    for rule in rules:
        try:
            findings.extend(rule(index, now))
        except Exception as exc:  # noqa: BLE001 - isolate rule failures
            name = getattr(rule, "__name__", repr(rule))
            failures.append(f"rule {name} failed: {type(exc).__name__}")
    findings.sort(key=lambda f: f.id)
    return findings, failures
