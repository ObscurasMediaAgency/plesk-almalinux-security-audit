"""Collector registry. Only collectors listed here are implemented."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from plesk_audit.collectors import network, system
from plesk_audit.collectors.base import CollectorContext, CollectorFn

IMPLEMENTED: Mapping[str, CollectorFn] = MappingProxyType(
    {
        system.NAME: system.collect,
        network.NAME: network.collect,
    }
)

__all__ = ["IMPLEMENTED", "CollectorContext", "CollectorFn"]
