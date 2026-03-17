"""Tests for the FirewallRule model."""
import pytest
from ufaya.models.firewall_rule import FirewallRule


def make_rule(**overrides):
    defaults = dict(
        vendor="paloalto",
        device="fw-01",
        name="allow-http",
        source=["10.0.0.0/8"],
        destination=["any"],
        service=["tcp/80"],
        action="allow",
    )
    defaults.update(overrides)
    return FirewallRule(**defaults)


def test_rule_defaults():
    rule = make_rule()
    assert rule.enabled is True
    assert rule.id is None


def test_rule_with_id():
    rule = make_rule(id="rule-1")
    assert rule.id == "rule-1"


def test_rule_requires_action():
    with pytest.raises(Exception):
        make_rule(action=None)


def test_rule_serialisation():
    rule = make_rule(id="42")
    data = rule.model_dump()
    assert data["name"] == "allow-http"
    assert data["action"] == "allow"
