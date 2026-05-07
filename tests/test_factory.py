"""Tests for the device factory."""

import pytest

from ufaya.drivers.juniper import JuniperSRXDriver
from ufaya.firewall.base import FirewallReader
from ufaya.services.device_factory import (
    available_vendors,
    get_firewall_driver,
    register_driver,
    unregister_driver,
)


def test_factory_returns_juniper_driver():
    driver = get_firewall_driver(
        "juniper_srx", host="1.2.3.4", username="admin", password="secret"
    )
    assert isinstance(driver, JuniperSRXDriver)


def test_factory_raises_on_unknown_vendor():
    with pytest.raises(ValueError, match="Unsupported vendor"):
        get_firewall_driver(
            "unknown_vendor", host="1.2.3.4", username="u", password="p"
        )


def test_unknown_vendor_message_lists_known_vendors():
    with pytest.raises(ValueError) as excinfo:
        get_firewall_driver("nope", host="x", username="u", password="p")
    assert "juniper_srx" in str(excinfo.value)


def test_built_in_vendors_appear_in_available_vendors():
    assert "juniper_srx" in available_vendors()


def test_register_driver_with_class():
    class FakeDriver(FirewallReader):
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def get_rules(self):
            return []

    register_driver("fake_vendor", FakeDriver)
    try:
        assert "fake_vendor" in available_vendors()
        d = get_firewall_driver("fake_vendor", host="1.2.3.4")
        assert isinstance(d, FakeDriver)
        assert d.kwargs == {"host": "1.2.3.4"}
    finally:
        unregister_driver("fake_vendor")
    assert "fake_vendor" not in available_vendors()


def test_register_driver_with_dotted_path():
    register_driver("juniper_alias", "ufaya.drivers.juniper:JuniperSRXDriver")
    try:
        d = get_firewall_driver(
            "juniper_alias", host="1.2.3.4", username="u", password="p"
        )
        assert isinstance(d, JuniperSRXDriver)
    finally:
        unregister_driver("juniper_alias")


def test_register_driver_overrides_built_in():
    class OverrideDriver(FirewallReader):
        def __init__(self, **kwargs):
            pass

        def get_rules(self):
            return []

    register_driver("juniper_srx", OverrideDriver)
    try:
        d = get_firewall_driver("juniper_srx")
        assert isinstance(d, OverrideDriver)
    finally:
        unregister_driver("juniper_srx")
    # Built-in still works after unregister.
    d = get_firewall_driver(
        "juniper_srx", host="1.2.3.4", username="u", password="p"
    )
    assert isinstance(d, JuniperSRXDriver)


def test_register_driver_rejects_non_reader():
    class NotADriver:
        pass

    register_driver("bad", NotADriver)  # type: ignore[arg-type]
    try:
        with pytest.raises(TypeError, match="not a FirewallReader"):
            get_firewall_driver("bad")
    finally:
        unregister_driver("bad")
