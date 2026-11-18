"""Shared collector types and helpers."""

from __future__ import annotations

from collections.abc import Callable, Container
from dataclasses import dataclass
from datetime import datetime
from typing import Any, TypeVar

from plesk_audit.file_reader import DirListResult, FileReader, FileReadResult
from plesk_audit.models import CollectorResult, CollectorStatus, Evidence
from plesk_audit.safe_exec import CommandExecutor, CommandResult

T = TypeVar("T")
_MAX_REASON = 160


@dataclass(frozen=True, slots=True)
class CollectorContext:
    commands: CommandExecutor
    files: FileReader
    now: Callable[[], datetime]


CollectorFn = Callable[[CollectorContext], CollectorResult]


def aggregate_status(succeeded: int, failed: int) -> CollectorStatus:
    if failed == 0:
        return "ok"
    if succeeded == 0:
        return "error"
    return "partial"


def _first_line(text: str) -> str:
    line = text.strip().splitlines()[0] if text.strip() else ""
    return line[:_MAX_REASON]


class Collection:
    """Accumulates evidence, failures and notes for one collector run."""

    def __init__(self, name: str, ctx: CollectorContext) -> None:
        self.name = name
        self.ctx = ctx
        self.evidence: list[Evidence] = []
        self.failures: list[str] = []
        self.notes: list[str] = []

    def add(self, suffix: str, source: str, data: dict[str, Any]) -> None:
        evidence_id = f"EV-{self.name}-{suffix}"
        self.evidence.append(Evidence(evidence_id, self.name, source, self.ctx.now(), data))

    def fail(self, reason: str) -> None:
        self.failures.append(reason)

    def note(self, reason: str) -> None:
        self.notes.append(reason)

    def command(self, name: str, ok_codes: Container[int] = (0,)) -> CommandResult | None:
        return self.check(self.ctx.commands.run(name), ok_codes)

    def check(self, result: CommandResult, ok_codes: Container[int] = (0,)) -> CommandResult | None:
        """Return the result if usable, otherwise record a failure and return None."""
        name = result.name
        if result.status in ("ok", "nonzero") and result.returncode in ok_codes:
            if result.stdout_truncated:
                self.note(f"{name}: output truncated")
            return result
        detail = _first_line(result.stderr) or result.error or ""
        self.fail(f"{name}: {result.status}" + (f" ({detail})" if detail else ""))
        return None

    def file(
        self, path: str, *, missing_ok: bool = False, tail: bool = False
    ) -> FileReadResult | None:
        result = self.ctx.files.read(path, tail=tail)
        if result.status == "ok":
            return result
        if not (missing_ok and result.status == "missing"):
            self.fail(f"{path}: {result.status}")
        return None

    def directory(self, path: str, *, missing_ok: bool = True) -> DirListResult | None:
        result = self.ctx.files.list_dir(path)
        if result.status == "ok":
            if result.truncated:
                self.note(f"{path}: listing truncated")
            return result
        if not (missing_ok and result.status == "missing"):
            self.fail(f"{path}: {result.status}")
        return None

    def parse(self, label: str, fn: Callable[[str], T], text: str) -> T | None:
        try:
            return fn(text)
        except (ValueError, IndexError, KeyError):
            self.fail(f"{label}: unparsable")
            return None

    def result(self) -> CollectorResult:
        status = aggregate_status(len(self.evidence), len(self.failures))
        if status == "ok" and self.notes:
            status = "partial"
        message = "; ".join([*self.failures, *self.notes]) or None
        return CollectorResult(self.name, status, self.evidence, message)
