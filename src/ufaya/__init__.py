"""ufaya — Unified Firewall Abstraction Layer for Automation."""

from ufaya._version import version as __version__
from ufaya.firewall.base import FirewallReader, FirewallWriter, NatReader
from ufaya.models.firewall_rule import (
    FirewallRule,
    FirewallRuleDebug,
    FirewallRuleRecord,
    FirewallRuleTrace,
    RuleContext,
    ServiceDetail,
)
from ufaya.models.nat_rule import (
    NatConditions,
    NatMapping,
    NatMappingSide,
    NatRewrite,
    NatRule,
    NatRuleContext,
    NatRuleDebug,
    NatRuleRecord,
)
from ufaya.services.device_factory import (
    available_vendors,
    get_firewall_driver,
    register_driver,
    unregister_driver,
)

__all__ = [
    "FirewallRule",
    "FirewallRuleDebug",
    "FirewallRuleRecord",
    "FirewallRuleTrace",
    "RuleContext",
    "ServiceDetail",
    "NatConditions",
    "NatMapping",
    "NatMappingSide",
    "NatRewrite",
    "NatRule",
    "NatRuleContext",
    "NatRuleDebug",
    "NatRuleRecord",
    "FirewallReader",
    "FirewallWriter",
    "NatReader",
    "get_firewall_driver",
    "register_driver",
    "unregister_driver",
    "available_vendors",
    "__version__",
]
