"""Service layer for ufaya."""

from .device_factory import get_firewall_driver

__all__ = ["get_firewall_driver"]
