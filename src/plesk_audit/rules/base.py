"""Shared rule types. Rules interpret evidence; they never collect."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime

from plesk_audit.models import Evidence, Finding

EvidenceIndex = Mapping[str, Evidence]
Rule = Callable[[EvidenceIndex, datetime], list[Finding]]
