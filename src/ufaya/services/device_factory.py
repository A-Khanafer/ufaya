from ufaya.drivers.fortinet import FortinetDriver
from ufaya.drivers.paloalto import PaloAltoDriver


def get_firewall_driver(vendor, **kwargs):

    if vendor == "paloalto":
        return PaloAltoDriver(**kwargs)

    if vendor == "fortinet":
        return FortinetDriver(**kwargs)

    raise ValueError("Unsupported vendor")
