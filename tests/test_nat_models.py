"""Tests for NAT data models."""

import pytest

from ufaya.models.nat_rule import (
    NatConditions,
    NatMapping,
    NatMappingSide,
    NatRewrite,
    NatRule,
    NatRuleContext,
    NatRuleDebug,
    NatRuleRecord,
)


def make_rule(**overrides):
    defaults = dict(
        vendor="juniper_srx",
        device="srx-01",
        nat_type="source",
        name="snat-pool",
        conditions=NatConditions(
            source=["10.0.0.0/24"],
            destination=["any"],
            source_refs=["client-net"],
            destination_refs=["any"],
        ),
        mapping=NatMapping(
            forward=NatRewrite(
                summary="source 10.0.0.0/24 -> 198.51.100.10/32",
                original=NatMappingSide(
                    field="source",
                    addresses=["10.0.0.0/24"],
                ),
                translated=NatMappingSide(
                    field="source",
                    addresses=["198.51.100.10/32"],
                    ref="internet-snat",
                ),
                mapping_kind="pool",
                determinism="exact",
                resolution_status="resolved",
            ),
        ),
        action="translate",
    )
    defaults.update(overrides)
    return NatRule(**defaults)


def make_context(**overrides):
    defaults = dict(
        context_id="source:trust-to-untrust",
        nat_type="source",
        priority_rank=3,
        context_order=1,
        rulebase="security_nat",
        rule_set="trust-to-untrust",
        from_zones=["trust"],
        to_zones=["untrust"],
    )
    defaults.update(overrides)
    return NatRuleContext(**defaults)


def make_record(**overrides):
    defaults = dict(
        rule=make_rule(sequence=3, vendor_rule_id="snat-pool"),
        context=make_context(),
        debug=NatRuleDebug(raw={"name": "snat-pool"}),
    )
    defaults.update(overrides)
    return NatRuleRecord(**defaults)


def test_nat_rule_defaults():
    rule = make_rule()
    assert rule.enabled is True
    assert rule.vendor_rule_id is None
    assert rule.sequence is None
    assert rule.description is None


def test_nat_rule_requires_action():
    with pytest.raises(Exception):
        make_rule(action=None)


def test_nat_context_captures_direction_metadata():
    context = make_context(
        nat_type="destination",
        priority_rank=2,
        context_id="destination:public-services",
        rule_set="public-services",
        from_zones=["untrust"],
        to_zones=None,
    )
    assert context.nat_type == "destination"
    assert context.priority_rank == 2
    assert context.from_zones == ["untrust"]
    assert context.to_zones is None


def test_nat_record_minimal_export_is_canonical_only():
    record = make_record()
    data = record.export_rule(
        "minimal",
        include_vendor=False,
        include_device=False,
    )

    assert data == {
        "nat_type": "source",
        "name": "snat-pool",
        "conditions": {
            "source": ["10.0.0.0/24"],
            "destination": ["any"],
        },
        "action": "translate",
        "enabled": True,
        "mapping": {
            "forward": {
                "summary": "source 10.0.0.0/24 -> 198.51.100.10/32",
                "original": {
                    "field": "source",
                    "addresses": ["10.0.0.0/24"],
                },
                "translated": {
                    "field": "source",
                    "addresses": ["198.51.100.10/32"],
                    "ref": "internet-snat",
                },
                "mapping_kind": "pool",
                "determinism": "exact",
                "resolution_status": "resolved",
            },
        },
        "vendor_rule_id": "snat-pool",
        "sequence": 3,
    }


def test_nat_record_minimal_export_strips_condition_refs():
    record = make_record()
    data = record.export_rule("minimal")

    conditions = data["conditions"]
    assert "source_refs" not in conditions
    assert "destination_refs" not in conditions


def test_nat_record_enriched_export_includes_condition_refs():
    record = make_record()
    data = record.export_rule("enriched", include_context=True)

    assert data["vendor"] == "juniper_srx"
    assert data["device"] == "srx-01"
    assert data["context"]["context_id"] == "source:trust-to-untrust"
    assert data["conditions"]["source_refs"] == ["client-net"]
    assert data["conditions"]["destination_refs"] == ["any"]
    assert data["mapping"]["forward"]["translated"]["ref"] == "internet-snat"
    assert "raw" not in data


def test_nat_record_debug_export_includes_raw_debug_payload():
    record = make_record()
    data = record.export_rule("debug")

    assert data["raw"] == {"name": "snat-pool"}
    assert data["conditions"]["source_refs"] == ["client-net"]
    assert data["mapping"]["forward"]["translated"]["ref"] == "internet-snat"


def test_nat_record_export_omits_none_values():
    record = make_record(
        rule=make_rule(
            vendor_rule_id=None,
            sequence=None,
            description=None,
            mapping=NatMapping(
                forward=NatRewrite(
                    summary="source 10.0.0.0/24 -> interface_address",
                    original=NatMappingSide(
                        field="source",
                        addresses=["10.0.0.0/24"],
                    ),
                    translated=NatMappingSide(
                        field="source",
                        address_source="interface_address",
                    ),
                    mapping_kind="interface_address",
                    determinism="dynamic",
                    resolution_status="resolved",
                ),
            ),
        ),
        debug=None,
    )
    data = record.export_rule("minimal")

    assert "vendor_rule_id" not in data
    assert "sequence" not in data
    assert "description" not in data
    assert data["mapping"]["forward"]["mapping_kind"] == "interface_address"
    assert data["mapping"]["forward"]["determinism"] == "dynamic"


def test_invalid_nat_export_mode_raises():
    record = make_record()
    with pytest.raises(ValueError, match="Unsupported export mode"):
        record.export_rule("verbose")
