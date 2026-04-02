"""Tests for NAT data models."""

import pytest

from ufaya.models.nat_rule import (
    NatMatch,
    NatRule,
    NatRuleContext,
    NatRuleDebug,
    NatRuleRecord,
    NatRuleTrace,
    NatTranslation,
    NatTranslationTarget,
)


def make_rule(**overrides):
    defaults = dict(
        vendor="juniper_srx",
        device="srx-01",
        nat_type="source",
        name="snat-pool",
        match=NatMatch(
            source=["10.0.0.0/24"],
            destination=["any"],
        ),
        translation=NatTranslation(
            source=NatTranslationTarget(
                mode="pool",
                addresses=["198.51.100.10/32"],
            )
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
        trace=NatRuleTrace(
            source_refs=["client-net"],
            destination_refs=["any"],
            translation_source_ref="internet-snat",
        ),
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
        "match": {
            "source": ["10.0.0.0/24"],
            "destination": ["any"],
        },
        "action": "translate",
        "enabled": True,
        "translation": {
            "source": {
                "mode": "pool",
                "addresses": ["198.51.100.10/32"],
            },
            "bidirectional": False,
        },
        "vendor_rule_id": "snat-pool",
        "sequence": 3,
    }


def test_nat_record_enriched_export_includes_traceability():
    record = make_record()
    data = record.export_rule("enriched", include_context=True)

    assert data["vendor"] == "juniper_srx"
    assert data["device"] == "srx-01"
    assert data["context"]["context_id"] == "source:trust-to-untrust"
    assert data["source_refs"] == ["client-net"]
    assert data["translation_source_ref"] == "internet-snat"
    assert "raw" not in data


def test_nat_record_debug_export_includes_raw_debug_payload():
    record = make_record()
    data = record.export_rule("debug")

    assert data["raw"] == {"name": "snat-pool"}
    assert data["translation_source_ref"] == "internet-snat"


def test_nat_record_export_omits_none_values():
    record = make_record(
        rule=make_rule(
            vendor_rule_id=None,
            sequence=None,
            description=None,
            translation=NatTranslation(
                source=NatTranslationTarget(mode="interface_address")
            ),
        ),
        trace=NatRuleTrace(),
        debug=None,
    )
    data = record.export_rule("minimal")

    assert "vendor_rule_id" not in data
    assert "sequence" not in data
    assert "description" not in data
    assert data["translation"] == {
        "source": {"mode": "interface_address"},
        "bidirectional": False,
    }


def test_invalid_nat_export_mode_raises():
    record = make_record()
    with pytest.raises(ValueError, match="Unsupported export mode"):
        record.export_rule("verbose")
