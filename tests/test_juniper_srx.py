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

    def test_conflicting_live_and_raw_raises(self):
        with pytest.raises(ValueError, match="conflicting source"):
            JuniperSRXDriver(
                host="1.2.3.4",
                username="admin",
                password="s",
                config_xml="<configuration/>",
            )

    def test_conflicting_file_and_raw_raises(self):
        with pytest.raises(ValueError, match="conflicting source"):
            JuniperSRXDriver(
                config_path="/tmp/x.xml",
                config_xml="<configuration/>",
            )

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

    def test_raw_mode_accepted(self):
        d = JuniperSRXDriver(config_xml="<configuration/>")
        assert d._mode == "raw"

    def test_custom_device_name(self):
        d = JuniperSRXDriver(config_xml="<configuration/>", device_name="fw-lab")
        assert d._device_name == "fw-lab"

    def test_default_device_name_offline(self):
        d = JuniperSRXDriver(config_xml="<configuration/>")
        assert d._device_name == "juniper_srx"


# =====================================================================
# Read-only enforcement
# =====================================================================


class TestReadOnly:
    def test_create_rule_raises(self):
        d = JuniperSRXDriver(config_xml="<configuration/>")
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
        d = JuniperSRXDriver(config_xml="<configuration/>")
        with pytest.raises(NotImplementedError, match="read-only"):
            d.delete_rule("id-1")

    def test_commit_raises(self):
        d = JuniperSRXDriver(config_xml="<configuration/>")
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
        assert rules[1].log_events is False   # allow-web
        assert rules[2].log_events is True    # deny-all

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

    def test_custom_app_resolved(self):
        d = JuniperSRXDriver(
            config_path=_fixture("juniper_full.xml"),
            device_name="srx",
        )
        rules = d.get_rules()
        # allow-inbound-web -> web-apps -> custom-app -> tcp/8080
        r = rules[3]
        assert "tcp/8080" in r.service


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
# Raw XML mode
# =====================================================================


class TestRawXMLMode:
    def test_raw_xml_string(self):
        xml = _fixture("juniper_actions.xml").read_text()
        d = JuniperSRXDriver(config_xml=xml, device_name="raw-test")
        rules = d.get_rules()
        assert len(rules) == 3
        assert rules[0].device == "raw-test"


# =====================================================================
# Error handling
# =====================================================================


class TestErrorHandling:
    def test_malformed_xml(self):
        d = JuniperSRXDriver(config_xml="<not-valid-xml", device_name="bad")
        with pytest.raises(ValueError, match="Malformed XML"):
            d.get_rules()

    def test_missing_file(self):
        d = JuniperSRXDriver(config_path="/nonexistent/path.xml")
        with pytest.raises(OSError, match="Failed to read"):
            d.get_rules()

    def test_empty_config_returns_empty(self):
        d = JuniperSRXDriver(config_xml="<configuration/>")
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
        d = JuniperSRXDriver(config_xml="<configuration/>", device_name="x")
        with pytest.raises(ValueError, match="not a directory"):
            d.export_rules_json(file_path)

    def test_deterministic_filename(self, tmp_path):
        d = JuniperSRXDriver(
            config_xml="<configuration/>",
            device_name="srx-lab.corp",
        )
        result = d.export_rules_json(tmp_path)
        assert result.name == "srx-lab.corp.firewall_rules.json"

    def test_sanitized_filename(self, tmp_path):
        d = JuniperSRXDriver(
            config_xml="<configuration/>",
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
        d = JuniperSRXDriver(config_xml="<configuration/>", device_name="x")
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
