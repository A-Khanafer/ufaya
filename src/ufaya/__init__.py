"""ufaya — Unified Firewall Abstraction Layer for Automation."""

from ufaya._version import version as __version__
from ufaya.firewall.base import FirewallDriver
from ufaya.models.firewall_rule import FirewallRule, ServiceDetail
from ufaya.services.device_factory import get_firewall_driver

__all__ = [
    "FirewallRule",
    "ServiceDetail",
    "FirewallDriver",
    "get_firewall_driver",
    "__version__",
]
