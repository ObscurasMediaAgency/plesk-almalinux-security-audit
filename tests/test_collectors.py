from __future__ import annotations

from plesk_audit.collectors import accounts, network, packages, services, system
from plesk_audit.collectors.base import CollectorContext
from plesk_audit.file_reader import FileReadResult
from plesk_audit.safe_exec import CommandResult
from tests.conftest import dir_entry, fixture_text, make_ctx


def test_system_collects_full_baseline(healthy_host_ctx: CollectorContext) -> None:
    result = system.collect(healthy_host_ctx)
    assert result.status == "ok" and result.message is None
    data = {e.evidence_id: e.data for e in result.evidence}
    assert data["EV-system-os-release"]["ID"] == "almalinux"
    assert data["EV-system-os-release"]["VERSION_ID"] == "9.9"
    assert "HOME_URL" not in data["EV-system-os-release"]
    assert data["EV-system-hostname"] == {"hostname": "host.example.test"}
    assert data["EV-system-uptime"] == {"uptime_seconds": 12345}
    assert data["EV-system-kernel"]["machine"] == "x86_64"
    assert data["EV-system-time"] == {
        "ntp_enabled": True,
        "ntp_synchronized": True,
        "timezone": "Europe/Berlin",
    }
    assert data["EV-system-plesk-version"]["version"] == "18.0.82"


def test_system_partial_when_sources_fail() -> None:
    ctx = make_ctx(
        commands={"uname": "unexpected"},
        files={
            "/etc/os-release": fixture_text("os-release-almalinux-9.9.txt"),
            "/proc/uptime": FileReadResult("/proc/uptime", "permission_denied"),
        },
    )
    result = system.collect(ctx)
    assert result.status == "partial"
    assert result.message is not None
    assert "uname: unparsable" in result.message
    assert "/proc/uptime: permission_denied" in result.message
    assert "timedatectl_show: missing" in result.message
    # Missing Plesk is an observation, not a failure.
    plesk = [e for e in result.evidence if e.evidence_id == "EV-system-plesk-version"]
    assert plesk[0].data == {"installed": False}


def test_parse_ss_handles_ipv6_interfaces_and_garbage() -> None:
    listeners, unparsable = network.parse_ss(fixture_text("ss-listening.txt"))
    assert unparsable == 1
    keyed = {(item["protocol"], item["address"], item["port"]): item for item in listeners}
    assert keyed[("tcp", "*", 3306)]["bind_scope"] == "wildcard"
    assert keyed[("tcp", "::", 80)]["bind_scope"] == "wildcard"
    assert keyed[("tcp", "127.0.0.1", 7080)]["bind_scope"] == "loopback"
    assert keyed[("udp", "127.0.0.53", 53)]["interface"] == "lo"
    assert keyed[("tcp", "fe80::1", 546)]["interface"] == "eth0"
    assert keyed[("tcp", "192.0.2.10", 8443)]["bind_scope"] == "specific"
    nginx = keyed[("tcp", "0.0.0.0", 80)]
    assert nginx["processes"] == ["nginx"] and nginx["pids"] == [1200, 1201]


def test_network_output_is_sorted_and_deterministic() -> None:
    text = fixture_text("ss-listening.txt")
    shuffled = "\n".join(reversed(text.splitlines()))
    assert network.parse_ss(text) == network.parse_ss(shuffled)


def test_network_partial_without_process_attribution(healthy_host_ctx: CollectorContext) -> None:
    result = network.collect(healthy_host_ctx)
    assert result.status == "partial"
    assert result.message is not None
    assert "1 unparsable line(s)" in result.message
    assert "2 listener(s) without process attribution" in result.message


def test_network_error_when_ss_fails() -> None:
    failed = CommandResult("ss_listening", ("ss",), "timeout", error="timed out")
    result = network.collect(make_ctx(commands={"ss_listening": failed}))
    assert result.status == "error" and result.evidence == []


def test_packages_inventory_and_advisories(healthy_host_ctx: CollectorContext) -> None:
    result = packages.collect(healthy_host_ctx)
    assert (result.status, result.message) == ("ok", None)
    data = {e.evidence_id: e.data for e in result.evidence}
    installed = data["EV-packages-installed"]
    assert installed["count"] == 4
    assert [k["release"] for k in installed["kernels"]] == [
        "5.14.0-001.el9.x86_64",
        "5.14.0-000.el9.x86_64",
    ]
    updates = data["EV-packages-security-updates"]
    assert (updates["advisory_count"], updates["package_count"]) == (2, 3)
    assert updates["by_severity"]["Important"] == 1


def test_packages_garbage_and_missing_dnf() -> None:
    ctx = make_ctx(commands={"rpm_packages": "not\ttab separated\n"})
    result = packages.collect(ctx)
    assert result.status == "error"
    assert "rpm_packages: unparsable" in (result.message or "")
    assert "dnf_security_updates: missing" in (result.message or "")


def test_updateinfo_counts_unparsable_lines() -> None:
    advisories, unparsable = packages.parse_updateinfo(
        "ALSA-1 Critical/Sec. a-1.x86_64\nnoise line\nALSA-1 Critical/Sec. a-1.x86_64\n"
    )
    assert len(advisories) == 1 and unparsable == 1


def test_services_merge_and_failed(healthy_host_ctx: CollectorContext) -> None:
    result = services.collect(healthy_host_ctx)
    assert result.status == "ok"
    data = result.evidence[0].data
    assert data["failed"] == ["backup-example.service"]
    cups = next(u for u in data["units"] if u["unit"] == "cups.service")
    assert (cups["load"], cups["unit_file_state"]) == ("not-loaded", "disabled")
    assert data["enabled_count"] == 3


def test_accounts_collects_metadata_without_secrets(healthy_host_ctx: CollectorContext) -> None:
    result = accounts.collect(healthy_host_ctx)
    data = {e.evidence_id: e.data for e in result.evidence}
    local = data["EV-accounts-local"]
    assert local["uid0"] == ["root", "toor"]
    assert local["interactive_regular"] == ["alice"]
    assert all("gecos" not in a for a in local["accounts"])
    assert data["EV-accounts-privileged-groups"]["groups"]["wheel"] == ["alice"]
    sudo = data["EV-accounts-sudoers"]["files"]
    assert [f["path"] for f in sudo] == ["/etc/sudoers", "/etc/sudoers.d/deploy"]
    assert sudo[0]["includes"] == ["#includedir /etc/sudoers.d"]
    assert [r["nopasswd"] for r in sudo[1]["rules"]] == [True]
    keys = data["EV-accounts-authorized-keys"]["files"]
    root = next(f for f in keys if f["user"] == "root")
    assert (root["key_count"], root["restricted_keys"]) == (2, 1)
    assert root["key_types"] == {"ssh-ed25519": 1, "ssh-rsa": 1}
    rendered = repr(result)
    assert "PLACEHOLDER" not in rendered and "Alice Example" not in rendered
    assert result.status == "ok"


def test_accounts_skips_disallowed_sudoers_names_and_reports_denied() -> None:
    from plesk_audit.file_reader import FileReadResult

    ctx = make_ctx(
        files={
            "/etc/passwd": "root:x:0:0::/root:/bin/bash\n",
            "/etc/group": "",
            "/etc/sudoers": FileReadResult("/etc/sudoers", "permission_denied"),
        },
        dirs={"/etc/sudoers.d": [dir_entry("bad.name~"), dir_entry("sub", kind="dir")]},
    )
    result = accounts.collect(ctx)
    assert result.status == "partial"
    assert "/etc/sudoers: permission_denied" in (result.message or "")
    assert "EV-accounts-sudoers" not in {e.evidence_id for e in result.evidence}
