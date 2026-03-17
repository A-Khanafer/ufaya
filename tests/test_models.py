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


# --- Extended field tests ---


def test_new_fields_default_to_none():
    """New optional fields default to None / False."""
    rule = make_rule()
    assert rule.sequence is None
    assert rule.source_zones is None
    assert rule.destination_zones is None
    assert rule.source_refs is None
    assert rule.destination_refs is None
    assert rule.service_refs is None
    assert rule.description is None
    assert rule.log_events is False
    assert rule.raw is None


def test_new_fields_can_be_set():
    rule = make_rule(
        sequence=1,
        source_zones=["trust"],
        destination_zones=["untrust"],
        source_refs=["web-server"],
        destination_refs=["any"],
        service_refs=["junos-http"],
        description="test desc",
        log_events=True,
        raw={"name": "allow-http"},
    )
    assert rule.sequence == 1
    assert rule.source_zones == ["trust"]
    assert rule.destination_zones == ["untrust"]
    assert rule.source_refs == ["web-server"]
    assert rule.destination_refs == ["any"]
    assert rule.service_refs == ["junos-http"]
    assert rule.description == "test desc"
    assert rule.log_events is True
    assert rule.raw == {"name": "allow-http"}


def test_extended_fields_serialisation():
    rule = make_rule(
        sequence=5,
        source_zones=["trust"],
        description="desc",
        raw={"key": "val"},
    )
    data = rule.model_dump()
    assert data["sequence"] == 5
    assert data["source_zones"] == ["trust"]
    assert data["description"] == "desc"
    assert data["raw"] == {"key": "val"}
    # Unset optional fields
    assert data["destination_zones"] is None
