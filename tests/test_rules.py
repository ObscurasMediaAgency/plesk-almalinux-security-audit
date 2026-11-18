from __future__ import annotations

from typing import Any

import pytest

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
    assert "could not evaluate" in db.summary
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


def ids(findings: list[Finding]) -> list[str]:
    return [f.id for f in findings]


def test_host_rules_from_fixture(healthy_host_ctx: CollectorContext) -> None:
    from plesk_audit.collectors import accounts, packages, services

    evidence = [
        e
        for mod in (system, packages, services, accounts)
        for e in mod.collect(healthy_host_ctx).evidence
    ]
    findings, failures = evaluate(evidence, FIXED_NOW)
    assert failures == []
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"PKG-001", "PKG-002", "SVC-001", "ACC-001", "ACC-002", "ACC-003"}
    assert by_id["PKG-001"].severity == "medium"
    assert "5.14.0-001.el9.x86_64" in by_id["PKG-002"].summary
    assert by_id["ACC-001"].severity == "high" and "toor" in by_id["ACC-001"].summary
    assert by_id["ACC-001"].summary.endswith(": toor.")
    assert "1 without from=/command=" in by_id["ACC-003"].summary


def test_host_rules_quiet_on_clean_evidence() -> None:
    evidence = [
        ev("EV-packages-security-updates", {"advisory_count": 0, "by_severity": {}}),
        ev("EV-packages-installed", {"kernels": [{"release": "5.14.0-1.el9.x86_64"}]}),
        ev("EV-system-kernel", {"kernel_release": "5.14.0-1.el9.x86_64"}),
        ev(
            "EV-services-units",
            {
                "failed": [],
                "units": [
                    {"unit": "auditd.service", "active": "active"},
                    {"unit": "fail2ban.service", "active": "active"},
                ],
            },
        ),
        ev("EV-accounts-local", {"uid0": ["root"]}),
        ev("EV-accounts-sudoers", {"files": [{"path": "/etc/sudoers", "rules": []}]}),
        ev("EV-accounts-authorized-keys", {"files": []}),
    ]
    findings, failures = evaluate(evidence, FIXED_NOW)
    assert (findings, failures) == ([], [])


def test_low_severity_advisories_only() -> None:
    data = {"advisory_count": 1, "package_count": 1, "by_severity": {"Moderate": 1}}
    findings, _ = evaluate([ev("EV-packages-security-updates", data)], FIXED_NOW)
    assert ids(findings) == ["PKG-001"] and findings[0].severity == "low"


def test_hardening_rules_from_fixture(healthy_host_ctx: CollectorContext) -> None:
    from plesk_audit.collectors import security_controls, services, ssh

    evidence = [
        e
        for mod in (network, services, ssh, security_controls)
        for e in mod.collect(healthy_host_ctx).evidence
    ]
    findings, failures = evaluate(evidence, FIXED_NOW)
    assert failures == []
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"NET-001-tcp-3306", "NET-002", "SSH-002", "SVC-001"}
    db = by_id["NET-001-tcp-3306"]
    assert db.severity == "medium" and "specific sources" in db.summary
    assert db.evidence_refs == ["EV-network-listeners", "EV-security_controls-firewalld"]
    assert by_id["SSH-002"].summary == "Enabled: PasswordAuthentication."


def _fw(running: bool = True, **zone: Any) -> Evidence:
    base = {"name": "public", "active": True, "default": True, "target": "default"}
    base |= {"interfaces": ["eth0"], "sources": [], "services": [], "ports": [], "rich_rules": []}
    return ev(
        "EV-security_controls-firewalld",
        {"running": running, "zones": [base | zone] if running else None},
    )


@pytest.mark.parametrize(
    ("firewall", "severity", "text"),
    [
        (_fw(running=False), "high", "not running"),
        (_fw(services=["mysql"]), "high", "allows this port"),
        (_fw(ports=["3000-4000/tcp"]), "high", "allows this port"),
        (_fw(ports=["3306/udp"]), "low", "No active"),
        (_fw(target="ACCEPT"), "high", "allows this port"),
        (
            _fw(default=False, interfaces=[], sources=["192.0.2.0/24"], ports=["3306/tcp"]),
            "medium",
            "specific",
        ),
        (_fw(), "low", "No active"),
    ],
)
def test_backend_exposure_uses_firewalld(firewall: Evidence, severity: str, text: str) -> None:
    listeners = [{"protocol": "tcp", "port": 3306, "bind_scope": "wildcard", "processes": []}]
    evidence = [ev("EV-network-listeners", {"listeners": listeners}), firewall]
    findings, _ = evaluate(evidence, FIXED_NOW)
    db = next(f for f in findings if f.id == "NET-001-tcp-3306")
    assert db.severity == severity and text in db.summary


def test_ssh_rules_fire_on_insecure_config() -> None:
    data = {
        "permitrootlogin": "yes",
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "yes",
        "usepam": "yes",
        "permitemptypasswords": "yes",
        "ciphers": ["aes128-cbc", "aes256-ctr"],
        "macs": ["hmac-md5", "hmac-sha1"],
        "kexalgorithms": ["diffie-hellman-group1-sha1"],
    }
    findings, _ = evaluate([ev("EV-ssh-effective-config", data)], FIXED_NOW)
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"SSH-001", "SSH-002", "SSH-003", "SSH-004"}
    assert by_id["SSH-003"].severity == "high"
    assert by_id["SSH-004"].summary == (
        "Weak algorithm(s) enabled: aes128-cbc, hmac-md5, diffie-hellman-group1-sha1."
    )


@pytest.mark.parametrize(
    ("runtime", "config", "severity"),
    [
        ("disabled", "disabled", "medium"),
        ("permissive", "enforcing", "low"),
        ("enforcing", "permissive", "low"),
    ],
)
def test_selinux_rule(runtime: str, config: str, severity: str) -> None:
    data = {"runtime_mode": runtime, "config_mode": config}
    findings, _ = evaluate([ev("EV-security_controls-selinux", data)], FIXED_NOW)
    assert [(f.id, f.severity) for f in findings] == [("SEC-001", severity)]


def test_firewall_and_fail2ban_and_auditd_rules() -> None:
    units = {"units": [{"unit": "fail2ban.service", "active": "active"}], "failed": []}
    evidence = [
        _fw(running=False),
        ev("EV-services-units", units),
        ev("EV-security_controls-fail2ban", {"installed": True, "jails": ["plesk-apache"]}),
    ]
    findings, _ = evaluate(evidence, FIXED_NOW)
    by_id = {f.id: f for f in findings}
    assert set(by_id) == {"FW-001", "SEC-002", "SEC-003"}
    assert by_id["SEC-002"].title == "Fail2Ban has no SSH jail"
    assert by_id["SEC-003"].summary == "auditd.service is not installed."

    accept = [_fw(name="trusted", target="ACCEPT")]
    findings, _ = evaluate(accept, FIXED_NOW)
    assert [f.id for f in findings] == ["FW-002"]
