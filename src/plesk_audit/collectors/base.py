"""Shared collector types."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from plesk_audit.file_reader import FileReader
from plesk_audit.models import CollectorResult, CollectorStatus
from plesk_audit.safe_exec import CommandExecutor


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
