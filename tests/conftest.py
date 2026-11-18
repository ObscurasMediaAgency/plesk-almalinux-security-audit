from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from plesk_audit.collectors.base import CollectorContext
from plesk_audit.file_reader import FileReadResult
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
    def __init__(self, files: dict[str, str | FileReadResult]) -> None:
        self.files = files

    def read(self, path: str) -> FileReadResult:
        value = self.files.get(path)
        if value is None:
            return FileReadResult(path, "missing")
        if isinstance(value, FileReadResult):
            return value
        return FileReadResult(path, "ok", value)


def make_ctx(
    commands: dict[str, str | CommandResult] | None = None,
    files: dict[str, str | FileReadResult] | None = None,
) -> CollectorContext:
    return CollectorContext(FakeCommands(commands or {}), FakeFiles(files or {}), lambda: FIXED_NOW)


@pytest.fixture
def healthy_host_ctx() -> CollectorContext:
    return make_ctx(
        commands={
            "uname": "Linux 5.14.0-000.el9.x86_64 x86_64\n",
            "timedatectl_show": fixture_text("timedatectl-synced.txt"),
            "ss_listening": fixture_text("ss-listening.txt"),
        },
        files={
            "/etc/os-release": fixture_text("os-release-almalinux-9.9.txt"),
            "/proc/sys/kernel/hostname": "host.example.test\n",
            "/proc/uptime": "12345.67 23456.78\n",
            "/usr/local/psa/version": fixture_text("plesk-version.txt"),
        },
    )
