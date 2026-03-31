"""Comprehensive tests for the Juniper SRX driver."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from ufaya.drivers.juniper import JuniperSRXDriver
from ufaya.models.firewall_rule import FirewallRule

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> Path:
    return FIXTURES / name


def _write_xml(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _names(records):
    return [record.rule.name for record in records]


def _context_ids(records):
    return [record.context.context_id for record in records]


def _read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)


def _payload_context_ids(data: dict) -> list[str]:
    return [entry["context"]["context_id"] for entry in data["contexts"]]


def _reload_juniper_driver_module():
    import importlib  # noqa: I001
    import ufaya.drivers.juniper.driver as mod

    importlib.reload(mod)
    return mod


def _repeat_name_config_xml() -> str:
    return """\
<configuration>
    <security>
        <zones>
            <security-zone>
                <name>trust</name>
            </security-zone>
            <security-zone>
                <name>untrust</name>
            </security-zone>
            <security-zone>
                <name>dmz</name>
            </security-zone>
        </zones>
        <policies>
            <policy>
                <from-zone-name>trust</from-zone-name>
                <to-zone-name>untrust</to-zone-name>
                <policy>
                    <name>shared-policy</name>
                    <match>
                        <source-address>any</source-address>
                        <destination-address>any</destination-address>
                        <application>any</application>
                    </match>
                    <then>
                        <permit/>
                    </then>
                </policy>
            </policy>
            <policy>
                <from-zone-name>trust</from-zone-name>
                <to-zone-name>dmz</to-zone-name>
                <policy>
                    <name>shared-policy</name>
                    <match>
                        <source-address>any</source-address>
                        <destination-address>any</destination-address>
                        <application>any</application>
                    </match>
                    <then>
                        <deny/>
                    </then>
                </policy>
            </policy>
            <global>
                <policy>
                    <name>shared-policy</name>
                    <match>
                        <source-address>any</source-address>
                        <destination-address>any</destination-address>
                        <application>any</application>
                    </match>
                    <then>
                        <reject/>
                    </then>
                </policy>
            </global>
        </policies>
    </security>
</configuration>
"""


def _repeat_name_hit_count_xml() -> str:
    return """\
<rpc-reply>
    <security-policies-hit-count-information>
        <policy-information>
            <from-zone>trust</from-zone>
            <to-zone>untrust</to-zone>
            <policy-name>shared-policy</policy-name>
            <policy-count>11</policy-count>
        </policy-information>
        <policy-information>
            <from-zone>trust</from-zone>
            <to-zone>dmz</to-zone>
            <policy-name>shared-policy</policy-name>
            <policy-count>22</policy-count>
        </policy-information>
        <policy-information>
            <from-zone>junos-global</from-zone>
            <to-zone>junos-global</to-zone>
            <policy-name>shared-policy</policy-name>
            <policy-count>33</policy-count>
        </policy-information>
        <number-of-policy>3</number-of-policy>
    </security-policies-hit-count-information>
</rpc-reply>
"""


# =====================================================================
# Constructor validation
# =====================================================================


class TestConstructorValidation:
    def test_missing_source_raises(self):
        with pytest.raises(ValueError, match="exactly one source"):
            JuniperSRXDriver()

    def test_conflicting_live_and_file_raises(self):
        with pytest.raises(ValueError, match="conflicting source"):
            JuniperSRXDriver(
                host="1.2.3.4",
                username="admin",
                password="s",
                config_path="/tmp/x.xml",
            )

    def test_removed_config_xml_argument_raises_type_error(self):
        with pytest.raises(TypeError, match="config_xml"):
            JuniperSRXDriver(config_xml="<configuration/>")

    def test_live_mode_requires_username(self):
        with pytest.raises(ValueError, match="username"):
            JuniperSRXDriver(host="1.2.3.4", username="", password="s")

    def test_live_mode_requires_password(self):
        with pytest.raises(ValueError, match="password"):
            JuniperSRXDriver(host="1.2.3.4", username="admin", password="")

    def test_live_mode_accepted(self):
        d = JuniperSRXDriver(
            host="1.2.3.4", username="admin", password="secret"
        )
        assert d._mode == "live"
        assert d._device_name == "1.2.3.4"

    def test_file_mode_accepted(self):
        d = JuniperSRXDriver(config_path="/tmp/test.xml")
        assert d._mode == "file"

    def test_custom_device_name(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="fw-lab",
        )
        assert d._device_name == "fw-lab"

    def test_default_device_name_offline(self):
        d = JuniperSRXDriver(config_path=_fixture("juniper_actions.xml"))
        assert d._device_name == "juniper_srx"


# =====================================================================
# Read-only enforcement
# =====================================================================


class TestReadOnly:
    def test_create_rule_raises(self):
        d = JuniperSRXDriver(config_path=_fixture("juniper_actions.xml"))
        with pytest.raises(NotImplementedError, match="read-only"):
            d.create_rule(
                FirewallRule(
                    vendor="juniper_srx",
                    device="x",
                    name="r",
                    source=["any"],
                    destination=["any"],
                    service=["any"],
                    action="allow",
                )
            )

    def test_delete_rule_raises(self):
        d = JuniperSRXDriver(config_path=_fixture("juniper_actions.xml"))
        with pytest.raises(NotImplementedError, match="read-only"):
            d.delete_rule("id-1")

    def test_commit_raises(self):
        d = JuniperSRXDriver(config_path=_fixture("juniper_actions.xml"))
        with pytest.raises(NotImplementedError, match="read-only"):
            d.commit()


# =====================================================================
# XML parsing – full fixture
# =====================================================================


class TestFullPolicy:
    @pytest.fixture()
    def records(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx-lab",
        )
        return d.get_rules()

    def test_rule_count(self, records):
        assert len(records) == 6

    def test_priority_order_flattening(self, records):
        assert _names(records) == [
            "allow-dns",
            "allow-web",
            "deny-all",
            "allow-inbound-web",
            "reject-rest",
            "global-deny",
        ]

    def test_context_ids_and_per_context_sequences(self, records):
        assert _context_ids(records) == [
            "inter_zone:trust->untrust",
            "inter_zone:trust->untrust",
            "inter_zone:trust->untrust",
            "inter_zone:untrust->dmz",
            "inter_zone:untrust->dmz",
            "global",
        ]
        assert [record.rule.sequence for record in records] == [1, 2, 3, 1, 2, 1]

    def test_context_metadata(self, records):
        first = records[0].context
        assert first.scope == "inter_zone"
        assert first.priority_rank == 2
        assert first.context_order == 1
        assert first.rulebase == "security_policies"
        assert first.from_zone == "trust"
        assert first.to_zone == "untrust"

        second_context = records[3].context
        assert second_context.scope == "inter_zone"
        assert second_context.context_order == 2

        global_context = records[-1].context
        assert global_context.context_id == "global"
        assert global_context.scope == "global"
        assert global_context.priority_rank == 3
        assert global_context.context_order == 1
        assert global_context.section == "global"
        assert global_context.from_zone is None
        assert global_context.to_zone is None

    def test_description(self, records):
        assert records[0].rule.description == "Allow DNS to external servers"
        assert records[1].rule.description is None

    def test_logging(self, records):
        assert records[0].rule.log_actions == ["session-init"]
        assert records[1].rule.log_actions is None
        assert records[2].rule.log_actions == ["session-init"]

    def test_vendor_device_and_native_id(self, records):
        for record in records:
            assert record.rule.vendor == "juniper_srx"
            assert record.rule.device == "srx-lab"
            assert record.rule.vendor_rule_id == record.rule.name

    def test_debug_raw_dict_present(self, records):
        for record in records:
            assert record.debug is not None
            assert isinstance(record.debug.raw, dict)
            assert "name" in record.debug.raw


# =====================================================================
# Address resolution
# =====================================================================


class TestAddressResolution:
    def test_address_set_expanded(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        allow_web = records[1]
        assert allow_web.trace is not None
        assert allow_web.trace.source_refs == ["servers"]
        assert set(allow_web.rule.source) == {"10.0.1.10/32", "10.0.1.20/32"}

    def test_recursive_address_set(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_recursive_sets.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        record = records[0]
        assert record.trace is not None
        assert record.trace.source_refs == ["set-outer"]
        assert set(record.rule.source) == {
            "10.1.0.0/16",
            "10.2.0.0/16",
            "10.3.0.0/16",
        }

    def test_global_address_book(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_global_addressbook.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        record = records[0]
        assert record.trace is not None
        assert record.trace.source_refs == ["global-group"]
        assert set(record.rule.source) == {"192.168.100.1/32", "192.168.200.0/24"}

    def test_unresolved_addresses_kept(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_unresolved.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        record = records[0]
        assert record.rule.source == ["mystery-host"]
        assert record.rule.destination == ["unknown-net"]
        assert record.rule.service == ["custom-undefined"]
        assert record.trace is not None
        assert record.trace.service_details is not None
        assert len(record.trace.service_details) == 1
        assert record.trace.service_details[0].label == "custom-undefined"
        assert record.trace.service_details[0].resolved is False


# =====================================================================
# Application resolution
# =====================================================================


class TestApplicationResolution:
    def test_application_set_expanded(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        record = records[3]
        assert record.trace is not None
        assert record.trace.service_refs == ["web-apps"]
        assert "tcp/8080" in record.rule.service
        assert "junos-http" in record.rule.service
        assert "junos-https" in record.rule.service
        assert record.trace.service_details is not None
        assert len(record.trace.service_details) == 3
        detail_by_label = {
            detail.label: detail for detail in record.trace.service_details
        }
        assert detail_by_label["junos-http"].resolved is False
        assert detail_by_label["junos-https"].resolved is False
        assert detail_by_label["custom-app"].protocol == "tcp"
        assert detail_by_label["custom-app"].destination_ports == ["8080"]

    def test_custom_app_resolved(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        record = records[3]
        assert "tcp/8080" in record.rule.service
        assert record.trace is not None
        assert record.trace.service_details is not None
        assert any(
            detail.protocol == "tcp" and detail.destination_ports == ["8080"]
            for detail in record.trace.service_details
        )


class TestStructuredServiceResolution:
    @pytest.fixture()
    def records(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_service_details.xml"),
            device_name="srx",
        )
        return d.get_rules()

    def test_any_rules_stay_simple(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        record = records[0]
        assert record.rule.service == ["any"]
        assert record.trace is not None
        assert record.trace.service_details is not None
        assert len(record.trace.service_details) == 1
        assert record.trace.service_details[0].label == "any"
        assert record.trace.service_details[0].resolved is True

    def test_real_shape_tcp_443(self, records):
        record = records[0]
        assert record.rule.service == ["tcp/443"]
        assert record.rule.log_actions == ["session-init"]
        assert record.trace is not None
        assert record.trace.service_details is not None
        assert len(record.trace.service_details) == 1
        detail = record.trace.service_details[0]
        assert detail.label == "tcp-443"
        assert detail.protocol == "tcp"
        assert detail.destination_ports == ["443"]
        assert detail.resolved is True

    def test_real_shape_multiple_tcp_refs(self, records):
        record = records[1]
        assert record.rule.service == ["tcp/23", "tcp/22"]
        assert record.rule.log_actions == ["session-init"]
        assert record.trace is not None
        assert record.trace.service_details is not None
        destinations = [
            detail.destination_ports for detail in record.trace.service_details
        ]
        assert destinations == [["23"], ["22"]]

    def test_real_shape_icmp_dedup_and_detail_preservation(self, records):
        record = records[2]
        assert record.rule.service == ["tcp/53", "udp/53", "icmp", "udp/33434-33534"]
        assert record.rule.log_actions == ["session-init"]
        assert record.trace is not None
        assert record.trace.service_refs == ["tcp-53", "udp-53", "icmpv4"]
        assert record.trace.service_details is not None
        assert len(record.trace.service_details) == 5

        icmp_details = [
            detail
            for detail in record.trace.service_details
            if detail.protocol == "icmp"
        ]
        assert len(icmp_details) == 2
        assert {(detail.icmp_type, detail.icmp_code) for detail in icmp_details} == {
            (8, 0),
            (3, None),
        }

        traceroute_details = [
            detail
            for detail in record.trace.service_details
            if detail.protocol == "udp"
            and detail.destination_ports == ["33434-33534"]
        ]
        assert len(traceroute_details) == 1

    def test_richer_term_fields_preserved(self, records):
        record = records[3]
        assert record.rule.service == ["tcp/1024-65535->111"]
        assert record.trace is not None
        assert record.trace.service_details is not None
        assert len(record.trace.service_details) == 1
        detail = record.trace.service_details[0]
        assert detail.protocol == "tcp"
        assert detail.source_ports == ["1024-65535"]
        assert detail.destination_ports == ["111"]
        assert detail.application_protocol == "sunrpc"
        assert detail.rpc_program_number == "100000"
        assert detail.inactivity_timeout == "300"


class TestLogActions:
    def test_session_init_and_close_preserved(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_log_actions.xml"),
            device_name="srx",
        )
        records = d.get_rules()

        assert records[0].rule.log_actions == ["session-init"]
        assert records[1].rule.log_actions == ["session-init", "session-close"]
        assert records[2].rule.log_actions is None


# =====================================================================
# Action normalisation
# =====================================================================


class TestActionNormalization:
    def test_permit_deny_reject(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        assert records[0].rule.action == "allow"
        assert records[1].rule.action == "deny"
        assert records[2].rule.action == "reject"


# =====================================================================
# Inactive policies
# =====================================================================


class TestInactivePolicies:
    def test_inactive_flag(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_inactive.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        assert len(records) == 2
        assert records[0].rule.enabled is True
        assert records[0].rule.name == "active-rule"
        assert records[1].rule.enabled is False
        assert records[1].rule.name == "disabled-rule"


# =====================================================================
# RPC-reply wrapper
# =====================================================================


class TestRpcReplyWrapper:
    def test_rpc_reply_unwrapped(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_rpc_reply.xml"),
            device_name="srx",
        )
        records = d.get_rules()
        assert len(records) == 1
        assert records[0].rule.name == "simple-permit"
        assert records[0].rule.action == "allow"


# =====================================================================
# Error handling
# =====================================================================


class TestErrorHandling:
    def test_malformed_xml(self, tmp_path):
        config_path = _write_xml(tmp_path, "bad.xml", "<not-valid-xml")
        d = JuniperSRXDriver(config_path=config_path, device_name="bad")
        with pytest.raises(ValueError, match="Malformed XML"):
            d.get_rules()

    def test_missing_file(self):
        d = JuniperSRXDriver(config_path="/nonexistent/path.xml")
        with pytest.raises(OSError, match="Failed to read"):
            d.get_rules()

    def test_empty_config_returns_empty(self, tmp_path):
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        d = JuniperSRXDriver(config_path=config_path)
        assert d.get_rules() == []


# =====================================================================
# Live fetch (mocked Netmiko)
# =====================================================================


class TestLiveFetch:
    def test_live_fetch_command(self):
        xml = _fixture("juniper_actions.xml").read_text()
        hit_counts_xml = """\
<rpc-reply>
    <security-policies-hit-count-information>
        <policy-information>
            <from-zone>trust</from-zone>
            <to-zone>untrust</to-zone>
            <policy-name>permit-rule</policy-name>
            <policy-count>5</policy-count>
        </policy-information>
        <policy-information>
            <from-zone>trust</from-zone>
            <to-zone>untrust</to-zone>
            <policy-name>deny-rule</policy-name>
            <policy-count>6</policy-count>
        </policy-information>
        <policy-information>
            <from-zone>trust</from-zone>
            <to-zone>untrust</to-zone>
            <policy-name>reject-rule</policy-name>
            <policy-count>7</policy-count>
        </policy-information>
        <number-of-policy>3</number-of-policy>
    </security-policies-hit-count-information>
</rpc-reply>
"""
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [xml, hit_counts_xml]
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        mock_handler_cls = MagicMock(return_value=mock_conn)

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            mod = _reload_juniper_driver_module()
            d2 = mod.JuniperSRXDriver(
                host="10.0.0.1", username="admin", password="secret"
            )
            records = d2.get_rules()

        mock_handler_cls.assert_called_once_with(
            device_type="juniper_junos",
            host="10.0.0.1",
            username="admin",
            password="secret",
        )
        assert mock_conn.send_command.call_args_list == [
            call("show configuration | display xml | no-more"),
            call("show security policies hit-count | display xml | no-more"),
        ]
        assert len(records) == 3
        assert [record.rule.hit_count for record in records] == [5, 6, 7]

    def test_live_fetch_failure_propagates(self):
        mock_handler_cls = MagicMock(side_effect=Exception("Connection refused"))

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            mod = _reload_juniper_driver_module()
            d2 = mod.JuniperSRXDriver(
                host="10.0.0.1", username="admin", password="secret"
            )
            with pytest.raises(ConnectionError, match="Failed to fetch"):
                d2.get_rules()


# =====================================================================
# JSON export
# =====================================================================


class TestJSONExport:
    def test_export_creates_directory(self, tmp_path):
        out = tmp_path / "subdir" / "nested"
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="fw-01",
        )
        result = d.export_rules_json(out)
        assert result.exists()
        assert result.parent == out

    def test_export_fails_on_non_directory(self, tmp_path):
        file_path = tmp_path / "afile.txt"
        file_path.write_text("not a dir")
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        d = JuniperSRXDriver(config_path=config_path, device_name="x")
        with pytest.raises(ValueError, match="not a directory"):
            d.export_rules_json(file_path)

    def test_export_rejects_unknown_mode(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        with pytest.raises(ValueError, match="Unsupported export mode"):
            d.export_rules_json(tmp_path, mode="verbose")

    def test_deterministic_filename(self, tmp_path):
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        d = JuniperSRXDriver(
            config_path=config_path,
            device_name="srx-lab.corp",
        )
        result = d.export_rules_json(tmp_path)
        assert result.name == "srx-lab.corp.firewall_rules.json"

    def test_sanitized_filename(self, tmp_path):
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        d = JuniperSRXDriver(
            config_path=config_path,
            device_name="fw 01/test",
        )
        result = d.export_rules_json(tmp_path)
        assert result.name == "fw_01_test.firewall_rules.json"

    def test_json_payload_shape(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx-test",
        )
        data = _read_json(d.export_rules_json(tmp_path))

        assert data["vendor"] == "juniper_srx"
        assert data["device"] == "srx-test"
        assert "hit_counts_collected_at" not in data
        assert data["schema_version"] == 3
        assert data["mode"] == "enriched"
        assert data["rule_count"] == 3
        assert data["evaluation_model"] == {
            "context_selection_order": [
                "intra_zone",
                "inter_zone",
                "global",
                "implicit_default_deny",
            ],
            "rule_order_within_context": "top_down_first_match",
            "default_action": "deny",
        }
        assert len(data["contexts"]) == 1
        context = data["contexts"][0]
        assert context["context"] == {
            "context_id": "inter_zone:trust->untrust",
            "scope": "inter_zone",
            "priority_rank": 2,
            "context_order": 1,
            "rulebase": "security_policies",
            "from_zone": "trust",
            "to_zone": "untrust",
        }
        assert context["rule_count"] == 3
        assert [rule["name"] for rule in context["rules"]] == [
            "permit-rule",
            "deny-rule",
            "reject-rule",
        ]
        assert [rule["hit_count"] for rule in context["rules"]] == [
            None,
            None,
            None,
        ]

    def test_enriched_mode_includes_traceability_but_not_raw(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_service_details.xml"),
            device_name="srx-test",
        )
        data = _read_json(d.export_rules_json(tmp_path))

        first_rule = data["contexts"][0]["rules"][0]
        assert first_rule["hit_count"] is None
        assert first_rule["service"] == ["tcp/443"]
        assert first_rule["log_actions"] == ["session-init"]
        assert first_rule["service_refs"] == ["tcp-443"]
        assert first_rule["service_details"] == [
            {
                "label": "tcp-443",
                "protocol": "tcp",
                "destination_ports": ["443"],
                "resolved": True,
            }
        ]
        assert "raw" not in first_rule
        assert "vendor" not in first_rule
        assert "device" not in first_rule

    def test_minimal_mode_excludes_traceability_and_debug(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_service_details.xml"),
            device_name="srx-test",
        )
        data = _read_json(d.export_rules_json(tmp_path, mode="minimal"))

        first_rule = data["contexts"][0]["rules"][0]
        assert first_rule["hit_count"] is None
        assert first_rule["service"] == ["tcp/443"]
        assert first_rule["log_actions"] == ["session-init"]
        assert "service_refs" not in first_rule
        assert "service_details" not in first_rule
        assert "source_refs" not in first_rule
        assert "destination_refs" not in first_rule
        assert "raw" not in first_rule
        assert "vendor" not in first_rule
        assert "device" not in first_rule

    def test_debug_mode_includes_raw(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx-test",
        )
        data = _read_json(d.export_rules_json(tmp_path, mode="debug"))

        first_rule = data["contexts"][0]["rules"][0]
        assert first_rule["hit_count"] is None
        assert first_rule["raw"]["name"] == "permit-rule"

    def test_priority_ordered_contexts(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_priority_order.xml"),
            device_name="srx",
        )

        records = d.get_rules()
        assert _names(records) == [
            "intra-allow",
            "inter-allow",
            "inter-deny",
            "global-deny",
        ]
        assert _context_ids(records) == [
            "intra_zone:trust",
            "inter_zone:trust->dmz",
            "inter_zone:trust->dmz",
            "global",
        ]

        data = _read_json(d.export_rules_json(tmp_path))
        assert _payload_context_ids(data) == [
            "intra_zone:trust",
            "inter_zone:trust->dmz",
            "global",
        ]
        assert [rule["name"] for rule in data["contexts"][0]["rules"]] == [
            "intra-allow"
        ]
        assert [rule["name"] for rule in data["contexts"][1]["rules"]] == [
            "inter-allow",
            "inter-deny",
        ]
        assert [rule["name"] for rule in data["contexts"][2]["rules"]] == [
            "global-deny"
        ]

    def test_rule_order_within_context_is_top_down(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        data = _read_json(d.export_rules_json(tmp_path))

        assert _payload_context_ids(data) == [
            "inter_zone:trust->untrust",
            "inter_zone:untrust->dmz",
            "global",
        ]
        assert [rule["sequence"] for rule in data["contexts"][0]["rules"]] == [1, 2, 3]
        assert [rule["name"] for rule in data["contexts"][0]["rules"]] == [
            "allow-dns",
            "allow-web",
            "deny-all",
        ]
        assert [rule["sequence"] for rule in data["contexts"][1]["rules"]] == [1, 2]
        assert [rule["sequence"] for rule in data["contexts"][2]["rules"]] == [1]

    def test_export_returns_path(self, tmp_path):
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        d = JuniperSRXDriver(config_path=config_path, device_name="x")
        result = d.export_rules_json(tmp_path)
        assert isinstance(result, Path)

    def test_rerun_replaces_file(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        path1 = d.export_rules_json(tmp_path)
        path2 = d.export_rules_json(tmp_path)
        assert path1 == path2
        assert path2.exists()

        data = _read_json(path2)
        assert data["rule_count"] == 3
        assert len(list(tmp_path.glob("*.json"))) == 1

    def test_overwrite_is_atomic(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        path1 = d.export_rules_json(tmp_path)
        data1 = _read_json(path1)

        path2 = d.export_rules_json(tmp_path)
        data2 = _read_json(path2)

        assert data2["rule_count"] == data1["rule_count"]
        assert len(list(tmp_path.glob(".*"))) == 0

    def test_live_export_includes_hit_counts_and_timestamp(self, tmp_path):
        config_xml = _repeat_name_config_xml()
        hit_counts_xml = _repeat_name_hit_count_xml()
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [config_xml, hit_counts_xml]
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_handler_cls = MagicMock(return_value=mock_conn)

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            mod = _reload_juniper_driver_module()
            with patch.object(
                mod.JuniperSRXDriver,
                "_utc_now",
                return_value="2026-03-31T12:34:56Z",
            ):
                driver = mod.JuniperSRXDriver(
                    host="10.0.0.1",
                    username="admin",
                    password="secret",
                    device_name="srx-live",
                )
                data = _read_json(driver.export_rules_json(tmp_path))

        assert data["hit_counts_collected_at"] == "2026-03-31T12:34:56Z"
        assert _payload_context_ids(data) == [
            "inter_zone:trust->untrust",
            "inter_zone:trust->dmz",
            "global",
        ]
        assert [rule["hit_count"] for rule in data["contexts"][0]["rules"]] == [11]
        assert [rule["hit_count"] for rule in data["contexts"][1]["rules"]] == [22]
        assert [rule["hit_count"] for rule in data["contexts"][2]["rules"]] == [33]

    def test_live_export_falls_back_when_hit_count_fetch_fails(self, tmp_path):
        config_xml = _fixture("juniper_actions.xml").read_text()
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [
            config_xml,
            RuntimeError("hit count RPC unavailable"),
        ]
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_handler_cls = MagicMock(return_value=mock_conn)

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            mod = _reload_juniper_driver_module()
            driver = mod.JuniperSRXDriver(
                host="10.0.0.1",
                username="admin",
                password="secret",
                device_name="srx-live",
            )
            data = _read_json(driver.export_rules_json(tmp_path))

        assert "hit_counts_collected_at" not in data
        assert [rule["hit_count"] for rule in data["contexts"][0]["rules"]] == [
            None,
            None,
            None,
        ]

    def test_live_export_falls_back_when_hit_count_xml_is_unparseable(
        self, tmp_path
    ):
        config_xml = _fixture("juniper_actions.xml").read_text()
        mock_conn = MagicMock()
        mock_conn.send_command.side_effect = [
            config_xml,
            "<rpc-reply><unexpected/></rpc-reply>",
        ]
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_handler_cls = MagicMock(return_value=mock_conn)

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            mod = _reload_juniper_driver_module()
            driver = mod.JuniperSRXDriver(
                host="10.0.0.1",
                username="admin",
                password="secret",
                device_name="srx-live",
            )
            data = _read_json(driver.export_rules_json(tmp_path))

        assert "hit_counts_collected_at" not in data
        assert [rule["hit_count"] for rule in data["contexts"][0]["rules"]] == [
            None,
            None,
            None,
        ]
