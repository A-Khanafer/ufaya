"""ufaya — Unified Firewall Abstraction Layer for Automation."""

from ufaya._version import version as __version__
from ufaya.firewall.base import FirewallDriver
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
from ufaya.services.device_factory import get_firewall_driver

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
    "FirewallDriver",
    "get_firewall_driver",
    "__version__",
]
