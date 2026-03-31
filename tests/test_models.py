"""Tests for firewall rule data models."""

import pytest

from ufaya.models.firewall_rule import (
    FirewallRule,
    FirewallRuleDebug,
    FirewallRuleRecord,
    FirewallRuleTrace,
    RuleContext,
    ServiceDetail,
)


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


def make_context(**overrides):
    defaults = dict(
        context_id="inter_zone:trust->untrust",
        scope="inter_zone",
        priority_rank=2,
        context_order=1,
        rulebase="security_policies",
        from_zone="trust",
        to_zone="untrust",
    )
    defaults.update(overrides)
    return RuleContext(**defaults)


def make_record(**overrides):
    defaults = dict(
        rule=make_rule(sequence=3, vendor_rule_id="rule-3"),
        context=make_context(),
        trace=FirewallRuleTrace(
            source_refs=["web-server"],
            destination_refs=["any"],
            service_refs=["junos-http"],
            service_details=[
                ServiceDetail(
                    label="junos-http",
                    protocol="tcp",
                    destination_ports=["80"],
                    resolved=False,
                )
            ],
        ),
        debug=FirewallRuleDebug(raw={"name": "allow-http"}),
    )
    defaults.update(overrides)
    return FirewallRuleRecord(**defaults)


def test_rule_defaults():
    rule = make_rule()
    assert rule.enabled is True
    assert rule.vendor_rule_id is None
    assert rule.sequence is None
    assert rule.hit_count is None
    assert rule.description is None
    assert rule.log_actions is None


def test_rule_requires_action():
    with pytest.raises(Exception):
        make_rule(action=None)


def test_context_can_capture_priority_metadata():
    context = make_context(
        scope="global",
        priority_rank=3,
        context_order=1,
        context_id="global",
        section="global",
        from_zone=None,
        to_zone=None,
    )
    assert context.scope == "global"
    assert context.priority_rank == 3
    assert context.section == "global"
    assert context.from_zone is None
    assert context.to_zone is None


def test_record_minimal_export_is_canonical_only():
    record = make_record()
    data = record.export_rule(
        "minimal",
        include_vendor=False,
        include_device=False,
    )

    assert data == {
        "vendor_rule_id": "rule-3",
        "name": "allow-http",
        "source": ["10.0.0.0/8"],
        "destination": ["any"],
        "service": ["tcp/80"],
        "action": "allow",
        "enabled": True,
        "sequence": 3,
        "hit_count": None,
    }


def test_record_enriched_export_includes_traceability():
    record = make_record()
    data = record.export_rule("enriched", include_context=True)

    assert data["vendor"] == "paloalto"
    assert data["device"] == "fw-01"
    assert data["context"]["context_id"] == "inter_zone:trust->untrust"
    assert data["source_refs"] == ["web-server"]
    assert data["service_details"] == [
        {
            "label": "junos-http",
            "protocol": "tcp",
            "destination_ports": ["80"],
            "resolved": False,
        }
    ]
    assert "raw" not in data


def test_record_debug_export_includes_raw_debug_payload():
    record = make_record()
    data = record.export_rule("debug")

    assert data["raw"] == {"name": "allow-http"}
    assert data["service_refs"] == ["junos-http"]


def test_record_export_preserves_numeric_hit_count():
    record = make_record(rule=make_rule(hit_count=42))
    data = record.export_rule("minimal")

    assert data["hit_count"] == 42


def test_record_export_omits_none_values():
    record = make_record(
        rule=make_rule(
            vendor_rule_id=None,
            sequence=None,
            description=None,
            log_actions=None,
        ),
        trace=FirewallRuleTrace(),
        debug=None,
    )
    data = record.export_rule("minimal")

    assert "vendor_rule_id" not in data
    assert "sequence" not in data
    assert data["hit_count"] is None
    assert "description" not in data
    assert "log_actions" not in data


def test_invalid_export_mode_raises():
    record = make_record()
    with pytest.raises(ValueError, match="Unsupported export mode"):
        record.export_rule("verbose")
