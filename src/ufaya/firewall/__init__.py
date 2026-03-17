"""Firewall abstractions."""

from .base import FirewallDriver
from ..services.device_factory import get_firewall_driver


def get_rules(vendor: str, **kwargs):
	driver = get_firewall_driver(vendor, **kwargs)
	return driver.get_rules()


__all__ = ["FirewallDriver", "get_rules"]
