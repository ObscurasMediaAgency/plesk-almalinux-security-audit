"""Rule registry and evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from plesk_audit.models import Evidence, Finding
from plesk_audit.rules import (
    hardening_rules,
    host_rules,
    network_rules,
    plesk_rules,
    system_rules,
    triage_rules,
)
from plesk_audit.rules.base import Rule

RULES: Sequence[Rule] = (
    system_rules.os_matches_target,
    system_rules.time_synchronization,
    network_rules.backend_on_wildcard,
    network_rules.wildcard_listener_inventory,
    host_rules.security_updates,
    host_rules.kernel_reboot_pending,
    host_rules.failed_units,
    host_rules.extra_uid0,
    host_rules.sudo_nopasswd,
    host_rules.root_authorized_keys,
    hardening_rules.ssh_root_login,
    hardening_rules.ssh_password_auth,
    hardening_rules.ssh_empty_passwords,
    hardening_rules.ssh_weak_algorithms,
    hardening_rules.firewalld_not_running,
    hardening_rules.firewalld_accept_zone,
    hardening_rules.selinux_not_enforcing,
    hardening_rules.fail2ban_inactive,
    hardening_rules.auditd_inactive,
    plesk_rules.plesk_matches_target,
    triage_rules.root_password_login,
    triage_rules.ssh_brute_force,
    triage_rules.login_after_failures,
    triage_rules.mail_brute_force,
    triage_rules.ld_preload,
    triage_rules.recent_persistence_changes,
    triage_rules.unsafe_persistence_permissions,
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
