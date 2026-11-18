"""Findings for SSH, SELinux, firewalld, Fail2Ban and auditd."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from plesk_audit.models import Evidence, Finding, Severity
from plesk_audit.rules.base import EvidenceIndex

# Conservative list: algorithms broken or deprecated by OpenSSH upstream. hmac-sha1 is
# intentionally excluded because the EL9 DEFAULT crypto policy still enables it.
WEAK_CIPHER_MARKERS = ("-cbc", "3des", "arcfour", "blowfish", "cast128")
WEAK_MAC_MARKERS = ("md5", "-96", "umac-64")
WEAK_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    }
)


def _ssh(index: EvidenceIndex) -> Evidence | None:
    return index.get("EV-ssh-effective-config")


def _units(index: EvidenceIndex) -> tuple[Evidence, dict[str, dict[str, Any]]] | None:
    ev = index.get("EV-services-units")
    if ev is None:
        return None
    return ev, {u["unit"]: u for u in ev.data.get("units", [])}


def ssh_root_login(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = _ssh(index)
    if ev is None or ev.data.get("permitrootlogin") != "yes":
        return []
    return [
        Finding(
            id="SSH-001",
            title="SSH permits root login with any authentication method",
            domain="ssh",
            severity="medium",
            confidence="high",
            status="observed",
            summary="Effective sshd configuration has PermitRootLogin yes.",
            evidence_refs=[ev.evidence_id],
            impact="The root account can be targeted directly by password guessing.",
            recommendation=(
                "Use PermitRootLogin prohibit-password (keys only) or no, after confirming "
                "an alternative administrative access path."
            ),
            detected_at=now,
        )
    ]


def ssh_password_auth(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = _ssh(index)
    if ev is None:
        return []
    data = ev.data
    methods = []
    if data.get("passwordauthentication") == "yes":
        methods.append("PasswordAuthentication")
    if data.get("kbdinteractiveauthentication") == "yes" and data.get("usepam") == "yes":
        methods.append("KbdInteractiveAuthentication (PAM)")
    if not methods:
        return []
    return [
        Finding(
            id="SSH-002",
            title="SSH accepts password-based authentication",
            domain="ssh",
            severity="low",
            confidence="high",
            status="observed",
            summary=f"Enabled: {', '.join(methods)}.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Password authentication is exposed to brute-force and credential-stuffing "
                "attacks; Fail2Ban only slows these down."
            ),
            recommendation=(
                "Prefer key-based authentication for administrators. If passwords are needed "
                "(e.g. for Plesk subscription users), restrict them with Match blocks and "
                "ensure Fail2Ban covers SSH."
            ),
            detected_at=now,
        )
    ]


def ssh_empty_passwords(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = _ssh(index)
    if ev is None or ev.data.get("permitemptypasswords") != "yes":
        return []
    return [
        Finding(
            id="SSH-003",
            title="SSH permits empty passwords",
            domain="ssh",
            severity="high",
            confidence="high",
            status="observed",
            summary="Effective sshd configuration has PermitEmptyPasswords yes.",
            evidence_refs=[ev.evidence_id],
            impact="Accounts without a password could log in remotely without credentials.",
            recommendation="Set PermitEmptyPasswords no.",
            detected_at=now,
        )
    ]


def ssh_weak_algorithms(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = _ssh(index)
    if ev is None:
        return []
    weak = [
        *(c for c in ev.data.get("ciphers", []) if any(m in c for m in WEAK_CIPHER_MARKERS)),
        *(m for m in ev.data.get("macs", []) if any(x in m for x in WEAK_MAC_MARKERS)),
        *(k for k in ev.data.get("kexalgorithms", []) if k in WEAK_KEX),
    ]
    if not weak:
        return []
    return [
        Finding(
            id="SSH-004",
            title="SSH offers weak or legacy algorithms",
            domain="ssh",
            severity="low",
            confidence="medium",
            status="observed",
            summary=f"Weak algorithm(s) enabled: {', '.join(weak)}.",
            evidence_refs=[ev.evidence_id],
            impact="Legacy algorithms weaken transport security against capable attackers.",
            recommendation=(
                "Use the system-wide crypto policy (update-crypto-policies) instead of "
                "per-daemon overrides and remove legacy algorithms."
            ),
            detected_at=now,
        )
    ]


def firewalld_not_running(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-security_controls-firewalld")
    if ev is None or ev.data.get("running"):
        return []
    return [
        Finding(
            id="FW-001",
            title="firewalld is not running",
            domain="firewall",
            severity="medium",
            confidence="medium",
            status="needs_review",
            summary="firewall-cmd reports that firewalld is not running.",
            evidence_refs=[ev.evidence_id],
            impact=(
                "Without a host firewall every wildcard listener is reachable unless another "
                "packet filter (nftables/iptables, provider firewall) is in place."
            ),
            recommendation=(
                "Confirm which packet filter protects the host. Plesk Firewall on EL9 uses "
                "firewalld."
            ),
            detected_at=now,
        )
    ]


def firewalld_accept_zone(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-security_controls-firewalld")
    zones = (ev.data.get("zones") or []) if ev else []
    if ev is None:
        return []
    open_zones = [
        z["name"]
        for z in zones
        if z.get("target") == "ACCEPT"
        and (z.get("default") or (z.get("active") and z.get("interfaces")))
    ]
    if not open_zones:
        return []
    return [
        Finding(
            id="FW-002",
            title="Active firewalld zone accepts all traffic",
            domain="firewall",
            severity="medium",
            confidence="high",
            status="observed",
            summary=f"Zone(s) with target ACCEPT bound to interfaces: {', '.join(open_zones)}.",
            evidence_refs=[ev.evidence_id],
            impact="All ports on the affected interfaces are reachable regardless of service rules.",
            recommendation="Bind public interfaces to a restrictive zone (e.g. public).",
            detected_at=now,
        )
    ]


def selinux_not_enforcing(index: EvidenceIndex, now: datetime) -> list[Finding]:
    ev = index.get("EV-security_controls-selinux")
    if ev is None:
        return []
    runtime = ev.data.get("runtime_mode")
    config = ev.data.get("config_mode")
    severity: Severity
    if runtime == "disabled":
        severity, summary = "medium", "SELinux is disabled."
    elif runtime == "permissive":
        severity, summary = "low", "SELinux is in permissive mode (violations are only logged)."
    elif runtime == "enforcing" and config not in (None, "enforcing"):
        severity, summary = "low", f"SELinux enforces now but is configured as {config} on boot."
    else:
        return []
    return [
        Finding(
            id="SEC-001",
            title="SELinux is not enforcing",
            domain="security_controls",
            severity=severity,
            confidence="high",
            status="observed",
            summary=summary,
            evidence_refs=[ev.evidence_id],
            impact="SELinux confinement limits the impact of a compromised web or mail process.",
            recommendation=(
                "Plan a switch to enforcing (permissive first, review AVC denials). Plesk "
                "supports SELinux on EL9."
            ),
            detected_at=now,
        )
    ]


def fail2ban_inactive(index: EvidenceIndex, now: datetime) -> list[Finding]:
    found = _units(index)
    f2b = index.get("EV-security_controls-fail2ban")
    refs: list[str] = []
    if found is not None:
        services_ev, units = found
        unit = units.get("fail2ban.service")
        if unit is None or unit.get("active") != "active":
            state = "not installed" if unit is None else f"{unit.get('active')}"
            return [
                Finding(
                    id="SEC-002",
                    title="Fail2Ban is not active",
                    domain="security_controls",
                    severity="medium",
                    confidence="high",
                    status="observed",
                    summary=f"fail2ban.service is {state}.",
                    evidence_refs=[services_ev.evidence_id],
                    impact="Brute-force attempts against SSH, mail and Plesk are not throttled.",
                    recommendation="Enable Plesk IP Address Banning (Fail2Ban) with SSH jails.",
                    detected_at=now,
                )
            ]
        refs.append(services_ev.evidence_id)
    if f2b is None or not f2b.data.get("installed"):
        return []
    jails = f2b.data.get("jails") or []
    if any("ssh" in j for j in jails):
        return []
    return [
        Finding(
            id="SEC-002",
            title="Fail2Ban has no SSH jail",
            domain="security_controls",
            severity="low",
            confidence="medium",
            status="observed",
            summary=f"Active jails: {', '.join(jails) or 'none'}.",
            evidence_refs=[*refs, f2b.evidence_id],
            impact="Brute-force attempts against SSH are not throttled.",
            recommendation="Enable the SSH jail in Plesk IP Address Banning.",
            detected_at=now,
        )
    ]


def auditd_inactive(index: EvidenceIndex, now: datetime) -> list[Finding]:
    found = _units(index)
    if found is None:
        return []
    ev, units = found
    unit = units.get("auditd.service")
    if unit is not None and unit.get("active") == "active":
        return []
    return [
        Finding(
            id="SEC-003",
            title="auditd is not active",
            domain="security_controls",
            severity="low",
            confidence="high",
            status="observed",
            summary="auditd.service is " + ("not installed." if unit is None else "not active."),
            evidence_refs=[ev.evidence_id],
            impact="Security-relevant events (logins, privilege use) are not audited.",
            recommendation="Enable auditd and forward its logs off-host if possible.",
            detected_at=now,
        )
    ]
