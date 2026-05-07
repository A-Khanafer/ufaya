"""Pluggable factory for vendor drivers.

Built-in drivers are registered as ``"module.path:ClassName"`` strings so
they are only imported on first use. Out-of-tree drivers can register
themselves at runtime with :func:`register_driver`, or via the
``ufaya.drivers`` entry-point group in their ``pyproject.toml``::

    [project.entry-points."ufaya.drivers"]
    my_vendor = "my_pkg.driver:MyVendorDriver"
"""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points
from typing import Any, cast

from ufaya.firewall.base import FirewallReader

DriverSpec = type[FirewallReader] | str

_BUILTIN_DRIVERS: dict[str, DriverSpec] = {
    "juniper_srx": "ufaya.drivers.juniper:JuniperSRXDriver",
}

_USER_DRIVERS: dict[str, DriverSpec] = {}

_ENTRY_POINT_GROUP = "ufaya.drivers"


def register_driver(vendor: str, driver: DriverSpec) -> None:
    """Register a driver for ``vendor``.

    ``driver`` may be either a :class:`FirewallReader` subclass or a
    ``"module.path:ClassName"`` string for lazy import. User registrations
    take precedence over the built-in registry.
    """
    _USER_DRIVERS[vendor] = driver


def unregister_driver(vendor: str) -> None:
    """Remove a previously user-registered driver. No-op if not registered."""
    _USER_DRIVERS.pop(vendor, None)


def available_vendors() -> list[str]:
    """Return all known vendor keys (built-in + user + entry-points)."""
    vendors = set(_BUILTIN_DRIVERS) | set(_USER_DRIVERS)
    for ep in entry_points(group=_ENTRY_POINT_GROUP):
        vendors.add(ep.name)
    return sorted(vendors)


def get_firewall_driver(vendor: str, **kwargs: Any) -> FirewallReader:
    """Return an initialised driver for the given vendor.

    Resolution order: user-registered drivers, built-in registry, then the
    ``ufaya.drivers`` entry-point group.

    Raises:
        ValueError: If *vendor* is not registered anywhere.
    """
    spec = _resolve(vendor)
    if spec is None:
        supported = ", ".join(available_vendors()) or "(none)"
        raise ValueError(
            f"Unsupported vendor '{vendor}'. Choose from: {supported}"
        )

    cls = _load_class(spec)
    return cls(**kwargs)


def _resolve(vendor: str) -> DriverSpec | None:
    if vendor in _USER_DRIVERS:
        return _USER_DRIVERS[vendor]
    if vendor in _BUILTIN_DRIVERS:
        return _BUILTIN_DRIVERS[vendor]
    for ep in entry_points(group=_ENTRY_POINT_GROUP):
        if ep.name == vendor:
            return cast(DriverSpec, ep.load())
    return None


def _load_class(spec: DriverSpec) -> type[FirewallReader]:
    if isinstance(spec, type):
        return _validate_driver_class(spec)
    module_path, _, class_name = spec.partition(":")
    if not class_name:
        raise ValueError(
            f"Invalid driver spec '{spec}'. Expected 'module.path:ClassName'."
        )
    module = importlib.import_module(module_path)
    return _validate_driver_class(getattr(module, class_name))


def _validate_driver_class(obj: Any) -> type[FirewallReader]:
    if not isinstance(obj, type) or not issubclass(obj, FirewallReader):
        raise TypeError(
            f"Registered driver {obj!r} is not a FirewallReader subclass."
        )
    return obj
