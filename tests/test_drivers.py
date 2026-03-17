"""Tests for vendor driver skeletons."""
import pytest
from ufaya.drivers.paloalto import PaloAltoDriver
from ufaya.drivers.fortinet import FortinetDriver
from ufaya.drivers.cisco import CiscoDriver
from ufaya.drivers.juniper_srx import JuniperSRXDriver
from ufaya.models.firewall_rule import FirewallRule


DRIVER_CLASSES = [PaloAltoDriver, FortinetDriver, CiscoDriver, JuniperSRXDriver]

SAMPLE_RULE = FirewallRule(
    vendor="paloalto",
    device="fw-01",
    name="test-rule",
    source=["192.168.1.0/24"],
    destination=["any"],
    service=["tcp/443"],
    action="allow",
)


@pytest.mark.parametrize("cls", DRIVER_CLASSES)
def test_driver_instantiation(cls):
    driver = cls(host="1.2.3.4", username="admin", password="secret")
    assert driver.host == "1.2.3.4"


@pytest.mark.parametrize("cls", DRIVER_CLASSES)
def test_get_rules_returns_list(cls):
    driver = cls(host="1.2.3.4", username="admin", password="secret")
    result = driver.get_rules()
    assert isinstance(result, list)


@pytest.mark.parametrize("cls", DRIVER_CLASSES)
def test_create_rule_does_not_raise(cls):
    driver = cls(host="1.2.3.4", username="admin", password="secret")
    driver.create_rule(SAMPLE_RULE)  # should not raise


@pytest.mark.parametrize("cls", DRIVER_CLASSES)
def test_delete_rule_does_not_raise(cls):
    driver = cls(host="1.2.3.4", username="admin", password="secret")
    driver.delete_rule("rule-1")  # should not raise


@pytest.mark.parametrize("cls", DRIVER_CLASSES)
def test_commit_does_not_raise(cls):
    driver = cls(host="1.2.3.4", username="admin", password="secret")
    driver.commit()  # should not raise
