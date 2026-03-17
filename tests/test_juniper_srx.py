"""Comprehensive tests for the Juniper SRX driver."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    def rules(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx-lab",
        )
        return d.get_rules()

    def test_rule_count(self, rules):
        # trust->untrust: 3, untrust->dmz: 2, global: 1
        assert len(rules) == 6

    def test_device_evaluation_order(self, rules):
        names = [r.name for r in rules]
        assert names == [
            "allow-dns",
            "allow-web",
            "deny-all",
            "allow-inbound-web",
            "reject-rest",
            "global-deny",
        ]

    def test_sequence_numbers_are_consecutive(self, rules):
        seqs = [r.sequence for r in rules]
        assert seqs == list(range(1, len(rules) + 1))

    def test_zones(self, rules):
        r = rules[0]  # allow-dns: trust->untrust
        assert r.source_zones == ["trust"]
        assert r.destination_zones == ["untrust"]

    def test_global_policy_zone(self, rules):
        r = rules[-1]  # global-deny
        assert r.source_zones == ["global"]
        assert r.destination_zones == ["global"]

    def test_description(self, rules):
        r = rules[0]
        assert r.description == "Allow DNS to external servers"

    def test_no_description(self, rules):
        r = rules[1]  # allow-web has no description
        assert r.description is None

    def test_logging(self, rules):
        assert rules[0].log_events is True   # allow-dns
        assert rules[0].log_actions == ["session-init"]
        assert rules[1].log_events is False   # allow-web
        assert rules[1].log_actions is None
        assert rules[2].log_events is True    # deny-all
        assert rules[2].log_actions == ["session-init"]

    def test_vendor_and_device(self, rules):
        for r in rules:
            assert r.vendor == "juniper_srx"
            assert r.device == "srx-lab"

    def test_raw_dict_present(self, rules):
        for r in rules:
            assert isinstance(r.raw, dict)
            assert "name" in r.raw

    def test_id_format(self, rules):
        r = rules[0]
        assert r.id == "trust/untrust/allow-dns"


# =====================================================================
# Address resolution
# =====================================================================


class TestAddressResolution:
    def test_address_set_expanded(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        allow_web = rules[1]  # source-address=servers
        assert allow_web.source_refs == ["servers"]
        # servers = {web-server, db-server}
        assert set(allow_web.source) == {"10.0.1.10/32", "10.0.1.20/32"}

    def test_recursive_address_set(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_recursive_sets.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        r = rules[0]
        assert r.source_refs == ["set-outer"]
        # set-outer = addr-c + set-inner(addr-a, addr-b)
        assert set(r.source) == {"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"}

    def test_global_address_book(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_global_addressbook.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        r = rules[0]
        assert r.source_refs == ["global-group"]
        assert set(r.source) == {"192.168.100.1/32", "192.168.200.0/24"}

    def test_unresolved_addresses_kept(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_unresolved.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        r = rules[0]
        assert r.source == ["mystery-host"]
        assert r.destination == ["unknown-net"]
        assert r.service == ["custom-undefined"]
        assert r.service_details is not None
        assert len(r.service_details) == 1
        assert r.service_details[0].label == "custom-undefined"
        assert r.service_details[0].resolved is False


# =====================================================================
# Application resolution
# =====================================================================


class TestApplicationResolution:
    def test_application_set_expanded(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        # allow-inbound-web uses web-apps set
        r = rules[3]
        assert r.service_refs == ["web-apps"]
        # web-apps = {junos-http, junos-https, custom-app(tcp/8080)}
        assert "tcp/8080" in r.service
        # junos-http and junos-https are built-in, kept as-is
        assert "junos-http" in r.service
        assert "junos-https" in r.service
        assert r.service_details is not None
        assert len(r.service_details) == 3
        detail_by_label = {detail.label: detail for detail in r.service_details}
        assert detail_by_label["junos-http"].resolved is False
        assert detail_by_label["junos-https"].resolved is False
        assert detail_by_label["custom-app"].protocol == "tcp"
        assert detail_by_label["custom-app"].destination_ports == ["8080"]

    def test_custom_app_resolved(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        # allow-inbound-web -> web-apps -> custom-app -> tcp/8080
        r = rules[3]
        assert "tcp/8080" in r.service
        assert r.service_details is not None
        assert any(
            detail.protocol == "tcp" and detail.destination_ports == ["8080"]
            for detail in r.service_details
        )


class TestStructuredServiceResolution:
    @pytest.fixture()
    def rules(self):
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
        rules = d.get_rules()
        r = rules[0]
        assert r.service == ["any"]
        assert r.service_details is not None
        assert len(r.service_details) == 1
        assert r.service_details[0].label == "any"
        assert r.service_details[0].resolved is True

    def test_real_shape_tcp_443(self, rules):
        r = rules[0]
        assert r.service == ["tcp/443"]
        assert r.log_actions == ["session-init"]
        assert r.service_details is not None
        assert len(r.service_details) == 1
        detail = r.service_details[0]
        assert detail.label == "tcp-443"
        assert detail.protocol == "tcp"
        assert detail.destination_ports == ["443"]
        assert detail.resolved is True

    def test_real_shape_multiple_tcp_refs(self, rules):
        r = rules[1]
        assert r.service == ["tcp/23", "tcp/22"]
        assert r.log_actions == ["session-init"]
        assert r.service_details is not None
        assert [detail.destination_ports for detail in r.service_details] == [
            ["23"],
            ["22"],
        ]

    def test_real_shape_icmp_dedup_and_detail_preservation(self, rules):
        r = rules[2]
        assert r.service == ["tcp/53", "udp/53", "icmp", "udp/33434-33534"]
        assert r.log_actions == ["session-init"]
        assert r.service_refs == ["tcp-53", "udp-53", "icmpv4"]
        assert r.service_details is not None
        assert len(r.service_details) == 5

        icmp_details = [
            detail for detail in r.service_details if detail.protocol == "icmp"
        ]
        assert len(icmp_details) == 2
        assert {(detail.icmp_type, detail.icmp_code) for detail in icmp_details} == {
            (8, 0),
            (3, None),
        }

        traceroute_details = [
            detail
            for detail in r.service_details
            if detail.protocol == "udp"
            and detail.destination_ports == ["33434-33534"]
        ]
        assert len(traceroute_details) == 1

    def test_richer_term_fields_preserved(self, rules):
        r = rules[3]
        assert r.service == ["tcp/1024-65535->111"]
        assert r.service_details is not None
        assert len(r.service_details) == 1
        detail = r.service_details[0]
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
        rules = d.get_rules()

        assert rules[0].log_events is True
        assert rules[0].log_actions == ["session-init"]
        assert rules[1].log_events is True
        assert rules[1].log_actions == ["session-init", "session-close"]
        assert rules[2].log_events is False
        assert rules[2].log_actions is None


# =====================================================================
# Action normalisation
# =====================================================================


class TestActionNormalization:
    def test_permit_deny_reject(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        assert rules[0].action == "allow"
        assert rules[1].action == "deny"
        assert rules[2].action == "reject"


# =====================================================================
# Inactive policies
# =====================================================================


class TestInactivePolicies:
    def test_inactive_flag(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_inactive.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        assert len(rules) == 2
        assert rules[0].enabled is True
        assert rules[0].name == "active-rule"
        assert rules[1].enabled is False
        assert rules[1].name == "disabled-rule"


# =====================================================================
# RPC-reply wrapper
# =====================================================================


class TestRpcReplyWrapper:
    def test_rpc_reply_unwrapped(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_rpc_reply.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        assert len(rules) == 1
        assert rules[0].name == "simple-permit"
        assert rules[0].action == "allow"


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
        mock_conn = MagicMock()
        mock_conn.send_command.return_value = xml
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        mock_handler_cls = MagicMock(return_value=mock_conn)

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            import importlib  # noqa: I001
            import ufaya.drivers.juniper.driver as mod
            importlib.reload(mod)
            d2 = mod.JuniperSRXDriver(
                host="10.0.0.1", username="admin", password="secret"
            )
            rules = d2.get_rules()

        mock_handler_cls.assert_called_once_with(
            device_type="juniper_junos",
            host="10.0.0.1",
            username="admin",
            password="secret",
        )
        mock_conn.send_command.assert_called_once_with(
            "show configuration | display xml | no-more"
        )
        assert len(rules) == 3

    def test_live_fetch_failure_propagates(self):
        mock_handler_cls = MagicMock(side_effect=Exception("Connection refused"))

        with patch.dict(
            "sys.modules",
            {"netmiko": MagicMock(ConnectHandler=mock_handler_cls)},
        ):
            import importlib  # noqa: I001
            import ufaya.drivers.juniper.driver as mod
            importlib.reload(mod)
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
        result = d.export_rules_json(tmp_path)
        with open(result) as fp:
            data = json.load(fp)

        assert data["vendor"] == "juniper_srx"
        assert data["device"] == "srx-test"
        assert data["rule_count"] == 3
        assert data["order"] == "device_evaluation"
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) == 3

    def test_json_payload_includes_service_details_and_log_actions(
        self, tmp_path
    ):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_service_details.xml"),
            device_name="srx-test",
        )
        result = d.export_rules_json(tmp_path)
        with open(result) as fp:
            data = json.load(fp)

        first_rule = data["rules"][0]
        assert first_rule["service"] == ["tcp/443"]
        assert first_rule["log_actions"] == ["session-init"]
        assert first_rule["service_details"] == [
            {
                "label": "tcp-443",
                "protocol": "tcp",
                "source_ports": None,
                "destination_ports": ["443"],
                "application_protocol": None,
                "icmp_type": None,
                "icmp_code": None,
                "icmp6_type": None,
                "icmp6_code": None,
                "rpc_program_number": None,
                "inactivity_timeout": None,
                "resolved": True,
            }
        ]

    def test_rule_order_matches_device_evaluation(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        result = d.export_rules_json(tmp_path)
        with open(result) as fp:
            data = json.load(fp)
        names = [r["name"] for r in data["rules"]]
        assert names == [
            "allow-dns",
            "allow-web",
            "deny-all",
            "allow-inbound-web",
            "reject-rest",
            "global-deny",
        ]

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

        # Export again — should overwrite, not duplicate
        path2 = d.export_rules_json(tmp_path)
        assert path1 == path2
        assert path2.exists()

        with open(path2) as fp:
            data = json.load(fp)
        assert data["rule_count"] == 3

        # Only one JSON file should exist
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1

    def test_overwrite_is_atomic(self, tmp_path):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_actions.xml"),
            device_name="srx",
        )
        path1 = d.export_rules_json(tmp_path)

        # Write known content, then overwrite
        with open(path1) as fp:
            data1 = json.load(fp)

        path2 = d.export_rules_json(tmp_path)

        with open(path2) as fp:
            data2 = json.load(fp)

        # File should be valid JSON (not partial/corrupt)
        assert data2["rule_count"] == data1["rule_count"]
        # No temp files left behind
        tmp_files = list(tmp_path.glob(".*"))
        assert len(tmp_files) == 0
