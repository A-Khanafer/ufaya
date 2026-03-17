"""Tests for the device factory."""

import pytest

from ufaya.drivers.cisco import CiscoDriver
from ufaya.drivers.fortinet import FortinetDriver
from ufaya.drivers.juniper_srx import JuniperSRXDriver
from ufaya.drivers.paloalto import PaloAltoDriver
from ufaya.services.device_factory import get_firewall_driver


@pytest.mark.parametrize("vendor,expected_cls", [
    ("paloalto", PaloAltoDriver),
    ("fortinet", FortinetDriver),
    ("cisco", CiscoDriver),
    ("juniper_srx", JuniperSRXDriver),
])
def test_factory_returns_correct_driver(vendor, expected_cls):
    driver = get_firewall_driver(
        vendor, host="1.2.3.4", username="admin", password="secret"
    )
    assert isinstance(driver, expected_cls)


def test_factory_raises_on_unknown_vendor():
    with pytest.raises(ValueError, match="Unsupported vendor"):
        get_firewall_driver(
            "unknown_vendor", host="1.2.3.4", username="u", password="p"
        )
