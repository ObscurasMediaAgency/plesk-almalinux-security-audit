"""Bounded, allow-listed file reading.

Both the requested path and its resolved target must be in the in-code allow-list.
Only regular files are read, at most ``max_bytes``; content is redacted immediately.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import Literal, Protocol

from plesk_audit.redaction import redact_text

ALLOWED_FILES: frozenset[str] = frozenset(
    {
        "/etc/os-release",
        "/usr/lib/os-release",  # /etc/os-release is a symlink to this on EL9
        "/proc/uptime",
        "/proc/sys/kernel/hostname",
        # VERIFY: Plesk version file location on Obsidian 18.0.82 (believed standard).
        "/usr/local/psa/version",
    }
)

FileStatus = Literal[
    "ok", "missing", "permission_denied", "outside_allow_list", "not_regular", "error"
]


class FileNotAllowedError(ValueError):
    """Raised when code requests a path that is not in the allow-list."""


@dataclass(frozen=True, slots=True)
class FileReadResult:
    path: str
    status: FileStatus
    content: str = ""
    truncated: bool = False
    error: str | None = None


class FileReader(Protocol):
    def read(self, path: str) -> FileReadResult: ...


class BoundedFileReader:
    def __init__(self, max_bytes: int, allowed: frozenset[str] = ALLOWED_FILES) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self._max_bytes = max_bytes
        self._allowed = allowed

    def read(self, path: str) -> FileReadResult:
        if path not in self._allowed:
            raise FileNotAllowedError(path)
        try:
            real = os.path.realpath(path, strict=True)
        except FileNotFoundError:
            return FileReadResult(path, "missing")
        except PermissionError:
            return FileReadResult(path, "permission_denied")
        except OSError as exc:
            return FileReadResult(path, "error", error=type(exc).__name__)
        if real not in self._allowed:
            return FileReadResult(path, "outside_allow_list", error="resolved target not allowed")

        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            fd = os.open(real, flags)
        except FileNotFoundError:
            return FileReadResult(path, "missing")
        except PermissionError:
            return FileReadResult(path, "permission_denied")
        except OSError as exc:
            return FileReadResult(path, "error", error=type(exc).__name__)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return FileReadResult(path, "not_regular")
            chunks: list[bytes] = []
            total = 0
            # /proc files report size 0, so read until EOF or limit + 1.
            while total <= self._max_bytes and (chunk := os.read(fd, 65536)):
                chunks.append(chunk)
                total += len(chunk)
        except OSError as exc:
            return FileReadResult(path, "error", error=type(exc).__name__)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        truncated = len(data) > self._max_bytes
        text = data[: self._max_bytes].decode("utf-8", errors="replace")
        return FileReadResult(path, "ok", redact_text(text), truncated)
