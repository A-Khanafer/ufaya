"""Firewall abstractions."""

from ufaya.models.firewall_rule import FirewallRule

from ..services.device_factory import get_firewall_driver
from .base import FirewallDriver


def get_rules(vendor: str, **kwargs: str) -> list[FirewallRule]:
    driver = get_firewall_driver(vendor, **kwargs)
    return driver.get_rules()


__all__ = ["FirewallDriver", "get_rules"]
