"""ufaya — Unified Firewall Abstraction Layer for Automation."""

from ufaya.models.firewall_rule import FirewallRule
from ufaya.firewall.base import FirewallDriver
from ufaya.services.device_factory import get_firewall_driver
from ufaya._version import version as __version__

__all__ = ["FirewallRule", "FirewallDriver", "get_firewall_driver", "__version__"]
__version__ = "0.1.0"