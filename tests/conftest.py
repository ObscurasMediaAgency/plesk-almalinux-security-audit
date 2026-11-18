from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from plesk_audit.collectors.base import CollectorContext
from plesk_audit.file_reader import DirEntry, DirListResult, FileReadResult
from plesk_audit.safe_exec import ALLOWED_COMMANDS, CommandResult

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class FakeCommands:
    """Returns canned output; unknown names behave like a missing binary."""

    def __init__(self, outputs: dict[str, str | CommandResult]) -> None:
        self.outputs = outputs
        self.calls: list[str] = []

    def run(self, name: str) -> CommandResult:
        assert name in ALLOWED_COMMANDS, f"collector requested non-allow-listed command {name}"
        self.calls.append(name)
        argv = ALLOWED_COMMANDS[name]
        value = self.outputs.get(name)
        if value is None:
            return CommandResult(name, argv, "missing")
        if isinstance(value, CommandResult):
            return value
        return CommandResult(name, argv, "ok", returncode=0, stdout=value)


class FakeFiles:
    def __init__(
        self,
        files: dict[str, str | FileReadResult],
        dirs: dict[str, list[DirEntry] | DirListResult] | None = None,
    ) -> None:
        self.files = files
        self.dirs = dirs or {}
        self.tail_reads: list[str] = []

    def list_dir(self, path: str) -> DirListResult:
        value = self.dirs.get(path)
        if value is None:
            return DirListResult(path, "missing")
        if isinstance(value, DirListResult):
            return value
        return DirListResult(path, "ok", value)

    def read(self, path: str, *, tail: bool = False) -> FileReadResult:
        if tail:
            self.tail_reads.append(path)
        value = self.files.get(path)
        if value is None:
            return FileReadResult(path, "missing")
        if isinstance(value, FileReadResult):
            return value
        return FileReadResult(path, "ok", value)


def make_ctx(
    commands: dict[str, str | CommandResult] | None = None,
    files: dict[str, str | FileReadResult] | None = None,
    dirs: dict[str, list[DirEntry] | DirListResult] | None = None,
) -> CollectorContext:
    return CollectorContext(
        FakeCommands(commands or {}), FakeFiles(files or {}, dirs), lambda: FIXED_NOW
    )


def dir_entry(name: str, kind: str = "file", mode: str = "0644", uid: int = 0) -> DirEntry:
    return DirEntry(name, kind, mode, uid, 0, 10, FIXED_NOW)  # type: ignore[arg-type]


@pytest.fixture
def healthy_host_ctx() -> CollectorContext:
    return make_ctx(
        commands={
            "uname": "Linux 5.14.0-000.el9.x86_64 x86_64\n",
            "timedatectl_show": fixture_text("timedatectl-synced.txt"),
            "ss_listening": fixture_text("ss-listening.txt"),
            "rpm_packages": fixture_text("rpm-qa.txt"),
            "dnf_security_updates": fixture_text("dnf-updateinfo-security.txt"),
            "systemctl_units": fixture_text("systemctl-list-units.txt"),
            "systemctl_unit_files": fixture_text("systemctl-list-unit-files.txt"),
            "sshd_effective": fixture_text("sshd-T.txt"),
            "getenforce": "Enforcing\n",
            "firewalld_state": "running\n",
            "firewalld_default_zone": "public\n",
            "firewalld_zones": fixture_text("firewalld-list-all-zones.txt"),
            "fail2ban_status": fixture_text("fail2ban-status.txt"),
        },
        files={
            "/etc/os-release": fixture_text("os-release-almalinux-9.9.txt"),
            "/proc/sys/kernel/hostname": "host.example.test\n",
            "/proc/uptime": "12345.67 23456.78\n",
            "/usr/local/psa/version": fixture_text("plesk-version.txt"),
            "/etc/passwd": fixture_text("passwd.txt"),
            "/etc/group": fixture_text("group.txt"),
            "/etc/login.defs": "UID_MIN 1000\nUID_MAX 60000\n",
            "/etc/sudoers": fixture_text("sudoers.txt"),
            "/etc/sudoers.d/deploy": "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx\n",
            "/root/.ssh/authorized_keys": fixture_text("authorized-keys.txt"),
            "/etc/selinux/config": fixture_text("selinux-config.txt"),
        },
        dirs={"/etc/sudoers.d": [dir_entry("deploy", mode="0440")]},
    )
