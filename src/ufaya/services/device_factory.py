from __future__ import annotations

from ufaya.drivers.cisco import CiscoDriver
from ufaya.drivers.fortinet import FortinetDriver
from ufaya.drivers.juniper_srx import JuniperSRXDriver
from ufaya.drivers.paloalto import PaloAltoDriver
from ufaya.firewall.base import FirewallDriver

_DRIVERS: dict[str, type[FirewallDriver]] = {
    "paloalto": PaloAltoDriver,
    "fortinet": FortinetDriver,
    "cisco": CiscoDriver,
    "juniper_srx": JuniperSRXDriver,
}


def get_firewall_driver(vendor: str, **kwargs: str) -> FirewallDriver:
    """Return an initialised driver for the given vendor.

    Args:
        vendor: One of ``paloalto``, ``fortinet``, ``cisco``, ``juniper_srx``.
        **kwargs: Passed directly to the driver constructor (host, username, password).

    Raises:
        ValueError: If *vendor* is not supported.
    """
    try:
        return _DRIVERS[vendor](**kwargs)
    except KeyError:
        supported = ", ".join(_DRIVERS)
        raise ValueError(f"Unsupported vendor '{vendor}'. Choose from: {supported}")
