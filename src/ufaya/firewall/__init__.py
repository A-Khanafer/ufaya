"""Firewall capability interfaces."""

from ufaya.firewall.base import FirewallReader, FirewallWriter, NatReader

__all__ = ["FirewallReader", "FirewallWriter", "NatReader"]
