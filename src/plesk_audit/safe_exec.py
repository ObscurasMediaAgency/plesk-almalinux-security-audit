"""Safe, allow-listed command execution.

Commands are identified by a symbolic name and resolved against an in-code allow-list.
Arguments are fixed; nothing is taken from configuration or host data. Output is bounded,
decoded and redacted before it leaves this module.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import IO, Literal, Protocol

from plesk_audit.redaction import redact_text

SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_SAFE_ENV: Mapping[str, str] = MappingProxyType(
    {
        "PATH": SAFE_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "PAGER": "cat",
        "SYSTEMD_PAGER": "",
        "SYSTEMD_COLORS": "0",
    }
)

# All commands must be read-only. Additions require review against AGENT.md.
ALLOWED_COMMANDS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "uname": ("uname", "-s", "-r", "-m"),
        "timedatectl_show": (
            "timedatectl",
            "show",
            "--property=Timezone",
            "--property=NTP",
            "--property=NTPSynchronized",
        ),
        # -H no header, -t/-u TCP/UDP, -l listening, -n numeric, -p process (needs root).
        "ss_listening": ("ss", "-H", "-t", "-u", "-l", "-n", "-p"),
    }
)

CommandStatus = Literal["ok", "nonzero", "timeout", "missing", "error"]
_CHUNK = 65536


class CommandNotAllowedError(ValueError):
    """Raised when code requests a command that is not in the allow-list."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    name: str
    argv: tuple[str, ...]
    status: CommandStatus
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_ms: int = 0
    error: str | None = None


class CommandExecutor(Protocol):
    def run(self, name: str) -> CommandResult: ...


class _BoundedSink:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.chunks: list[bytes] = []
        self.kept = 0
        self.truncated = False

    def drain(self, stream: IO[bytes]) -> None:
        try:
            while chunk := stream.read(_CHUNK):
                remaining = self.limit - self.kept
                if remaining > 0:
                    part = chunk[:remaining]
                    self.chunks.append(part)
                    self.kept += len(part)
                if len(chunk) > max(remaining, 0):
                    self.truncated = True
        finally:
            stream.close()

    def text(self) -> str:
        return redact_text(b"".join(self.chunks).decode("utf-8", errors="replace"))


class SafeCommandRunner:
    def __init__(
        self,
        timeout_seconds: float,
        max_output_bytes: int,
        allowed: Mapping[str, tuple[str, ...]] = ALLOWED_COMMANDS,
    ) -> None:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("timeout and output limit must be positive")
        self._timeout = timeout_seconds
        self._max_bytes = max_output_bytes
        self._allowed = allowed

    def run(self, name: str) -> CommandResult:
        argv = self._allowed.get(name)
        if argv is None:
            raise CommandNotAllowedError(name)
        executable = shutil.which(argv[0], path=SAFE_PATH)
        if executable is None:
            return CommandResult(name, argv, "missing", error=f"{argv[0]} not found in {SAFE_PATH}")

        started = time.monotonic()
        try:
            proc = subprocess.Popen(  # fixed argv from in-code allow-list
                [executable, *argv[1:]],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(_SAFE_ENV),
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            return CommandResult(name, argv, "error", error=f"{type(exc).__name__}: {exc.strerror}")

        assert proc.stdout is not None and proc.stderr is not None
        out, err = _BoundedSink(self._max_bytes), _BoundedSink(self._max_bytes)
        readers = [
            threading.Thread(target=out.drain, args=(proc.stdout,), daemon=True),
            threading.Thread(target=err.drain, args=(proc.stderr,), daemon=True),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            proc.wait(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Only our own child process group is signalled.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        for reader in readers:
            reader.join(timeout=2)

        duration_ms = int((time.monotonic() - started) * 1000)
        status: CommandStatus
        if timed_out:
            status = "timeout"
        elif proc.returncode == 0:
            status = "ok"
        else:
            status = "nonzero"
        return CommandResult(
            name=name,
            argv=argv,
            status=status,
            returncode=None if timed_out else proc.returncode,
            stdout=out.text(),
            stderr=err.text(),
            stdout_truncated=out.truncated,
            stderr_truncated=err.truncated,
            duration_ms=duration_ms,
            error=f"timed out after {self._timeout}s" if timed_out else None,
        )
