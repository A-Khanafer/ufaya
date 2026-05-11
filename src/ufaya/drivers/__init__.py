"""Vendor-specific firewall driver implementations.

Drivers are not eagerly imported here. Use
:func:`ufaya.get_firewall_driver` for runtime lookup, or import a driver
directly (e.g. ``from ufaya.drivers.juniper import JuniperSRXDriver``).
"""
