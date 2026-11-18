"""Collector registry. Only collectors listed here are implemented."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from plesk_audit.collectors import accounts, network, packages, services, system
from plesk_audit.collectors.base import CollectorContext, CollectorFn

IMPLEMENTED: Mapping[str, CollectorFn] = MappingProxyType(
    {
        system.NAME: system.collect,
        packages.NAME: packages.collect,
        services.NAME: services.collect,
        network.NAME: network.collect,
        accounts.NAME: accounts.collect,
    }
)

__all__ = ["IMPLEMENTED", "CollectorContext", "CollectorFn"]
