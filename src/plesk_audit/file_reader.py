"""Bounded, allow-listed file reading and directory metadata listing.

Both the requested path and its resolved target must be allow-listed (exact path or
in-code pattern). Only regular files are read, at most ``max_bytes``; content is redacted
immediately. Directory listings return metadata only and never recurse.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal, Protocol

from plesk_audit.redaction import redact_text

# Log files that may be selected for triage via logs.sources.
KNOWN_LOG_FILES: frozenset[str] = frozenset(
    {
        "/var/log/secure",
        "/var/log/messages",
        "/var/log/maillog",
    }
)

ALLOWED_FILES: frozenset[str] = frozenset(
    {
        "/etc/os-release",
        "/usr/lib/os-release",  # /etc/os-release is a symlink to this on EL9
        "/proc/uptime",
        "/proc/sys/kernel/hostname",
        # VERIFY: Plesk version file location on Obsidian 18.0.82 (believed standard).
        "/usr/local/psa/version",
        "/etc/passwd",  # never /etc/shadow or /etc/gshadow
        "/etc/group",
        "/etc/login.defs",
        "/etc/sudoers",
        "/etc/selinux/config",
        "/etc/crontab",
        "/etc/ld.so.preload",  # persistence indicator; normally absent
        *KNOWN_LOG_FILES,
    }
)

_USER = r"[a-z_][a-z0-9_.-]{0,31}"
ALLOWED_FILE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/etc/sudoers\.d/[A-Za-z0-9_-]{1,64}"),
    re.compile(r"/root/\.ssh/authorized_keys"),
    re.compile(rf"/home/{_USER}/\.ssh/authorized_keys"),
    # Plesk subscription system users live below /var/www/vhosts/<domain>.
    re.compile(r"/var/www/vhosts/[a-z0-9][a-z0-9.-]{0,252}/\.ssh/authorized_keys"),
)

ALLOWED_DIRS: frozenset[str] = frozenset(
    {
        "/etc/sudoers.d",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/etc/systemd/system",
        "/etc/profile.d",
    }
)

FileStatus = Literal[
    "ok", "missing", "permission_denied", "outside_allow_list", "not_regular", "error"
]
EntryKind = Literal["file", "dir", "symlink", "other"]


class FileNotAllowedError(ValueError):
    """Raised when code requests a path that is not in the allow-list."""


@dataclass(frozen=True, slots=True)
class FileReadResult:
    path: str
    status: FileStatus
    content: str = ""
    truncated: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class DirEntry:
    name: str
    kind: EntryKind
    mode: str
    uid: int
    gid: int
    size: int
    mtime: datetime


@dataclass(frozen=True, slots=True)
class DirListResult:
    path: str
    status: FileStatus
    entries: list[DirEntry] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None


class FileReader(Protocol):
    def read(self, path: str, *, tail: bool = False) -> FileReadResult: ...

    def list_dir(self, path: str) -> DirListResult: ...


def is_allowed_file(
    path: str,
    allowed: frozenset[str] = ALLOWED_FILES,
    patterns: tuple[re.Pattern[str], ...] = ALLOWED_FILE_PATTERNS,
) -> bool:
    if ".." in path.split("/"):
        return False
    return path in allowed or any(p.fullmatch(path) for p in patterns)


def _kind(mode: int) -> EntryKind:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


class BoundedFileReader:
    def __init__(
        self,
        max_bytes: int,
        allowed: frozenset[str] = ALLOWED_FILES,
        patterns: tuple[re.Pattern[str], ...] = ALLOWED_FILE_PATTERNS,
        allowed_dirs: frozenset[str] = ALLOWED_DIRS,
        max_dir_entries: int = 1000,
    ) -> None:
        if max_bytes <= 0 or max_dir_entries <= 0:
            raise ValueError("limits must be positive")
        self._max_bytes = max_bytes
        self._allowed = allowed
        self._patterns = patterns
        self._allowed_dirs = allowed_dirs
        self._max_entries = max_dir_entries

    def _allowed_file(self, path: str) -> bool:
        return is_allowed_file(path, self._allowed, self._patterns)

    def read(self, path: str, *, tail: bool = False) -> FileReadResult:
        """Read a file; with ``tail`` the last ``max_bytes`` are returned instead of the first."""
        if not self._allowed_file(path):
            raise FileNotAllowedError(path)
        try:
            real = os.path.realpath(path, strict=True)
        except FileNotFoundError:
            return FileReadResult(path, "missing")
        except PermissionError:
            return FileReadResult(path, "permission_denied")
        except OSError as exc:
            return FileReadResult(path, "error", error=type(exc).__name__)
        if not self._allowed_file(real):
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
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return FileReadResult(path, "not_regular")
            skipped = False
            if tail and info.st_size > self._max_bytes:
                os.lseek(fd, info.st_size - self._max_bytes, os.SEEK_SET)
                skipped = True
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
        truncated = skipped or len(data) > self._max_bytes
        text = data[: self._max_bytes].decode("utf-8", errors="replace")
        return FileReadResult(path, "ok", redact_text(text), truncated)

    def list_dir(self, path: str) -> DirListResult:
        """List entry metadata (lstat, no recursion, no content)."""
        if path not in self._allowed_dirs:
            raise FileNotAllowedError(path)
        try:
            if os.path.realpath(path, strict=True) != path:
                return DirListResult(path, "outside_allow_list", error="directory is a symlink")
            entries: list[DirEntry] = []
            truncated = False
            with os.scandir(path) as it:
                for item in it:
                    if len(entries) >= self._max_entries:
                        truncated = True
                        break
                    try:
                        st = item.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    entries.append(
                        DirEntry(
                            name=redact_text(item.name),
                            kind=_kind(st.st_mode),
                            mode=f"{stat.S_IMODE(st.st_mode):04o}",
                            uid=st.st_uid,
                            gid=st.st_gid,
                            size=st.st_size,
                            mtime=datetime.fromtimestamp(int(st.st_mtime), UTC),
                        )
                    )
        except FileNotFoundError:
            return DirListResult(path, "missing")
        except PermissionError:
            return DirListResult(path, "permission_denied")
        except NotADirectoryError:
            return DirListResult(path, "not_regular")
        except OSError as exc:
            return DirListResult(path, "error", error=type(exc).__name__)
        entries.sort(key=lambda e: e.name)
        return DirListResult(path, "ok", entries, truncated)
