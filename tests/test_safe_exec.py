from __future__ import annotations

import pytest

from plesk_audit.safe_exec import (
    ALLOWED_COMMANDS,
    CommandNotAllowedError,
    SafeCommandRunner,
)

TEST_COMMANDS = {
    "hello": ("printf", "hello"),
    "secret": ("printf", "password=hunter2"),
    "big": ("head", "-c", "100000", "/dev/zero"),
    "slow": ("sleep", "5"),
    "fail": ("false",),
    "absent": ("definitely-not-an-installed-binary",),
    "env": ("env",),
}


def runner(timeout: float = 5, limit: int = 4096) -> SafeCommandRunner:
    return SafeCommandRunner(timeout, limit, allowed=TEST_COMMANDS)


def test_runs_allow_listed_command() -> None:
    result = runner().run("hello")
    assert (result.status, result.returncode, result.stdout) == ("ok", 0, "hello")


def test_rejects_unknown_command_name() -> None:
    with pytest.raises(CommandNotAllowedError):
        runner().run("rm")


def test_redacts_output() -> None:
    assert "hunter2" not in runner().run("secret").stdout


def test_truncates_output_at_limit() -> None:
    result = runner(limit=1000).run("big")
    assert result.stdout_truncated is True
    assert len(result.stdout) == 1000


def test_kills_on_timeout() -> None:
    result = runner(timeout=0.2).run("slow")
    assert result.status == "timeout"
    assert result.duration_ms < 3000


def test_nonzero_and_missing() -> None:
    assert runner().run("fail").status == "nonzero"
    assert runner().run("absent").status == "missing"


def test_environment_is_minimal() -> None:
    env = dict(line.split("=", 1) for line in runner().run("env").stdout.splitlines())
    assert env["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert env["LC_ALL"] == "C"
    assert "HOME" not in env


def test_default_allow_list_uses_no_shell_interpreters() -> None:
    shells = {"sh", "bash", "dash", "zsh", "python3", "perl", "env", "xargs"}
    assert not {argv[0] for argv in ALLOWED_COMMANDS.values()} & shells
