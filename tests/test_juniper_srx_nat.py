"""Tests for Juniper SRX NAT export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ufaya.drivers.juniper import JuniperSRXDriver

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> Path:
    return FIXTURES / name


def _write_xml(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def _read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)


def _nat_names(records):
    return [record.rule.name for record in records]


def _nat_context_ids(records):
    return [record.context.context_id for record in records]


def _payload_context_ids(data: dict) -> list[str]:
    return [entry["context"]["context_id"] for entry in data["contexts"]]


class TestNatExtraction:
    def test_get_nat_rules_orders_by_nat_precedence_and_sequence(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()

        assert _nat_names(records) == [
            "static-web",
            "static-admin",
            "dnat-web",
            "snat-pool",
            "snat-interface",
            "snat-off",
        ]
        assert _nat_context_ids(records) == [
            "static:static-public",
            "static:static-public",
            "destination:public-services",
            "source:trust-to-untrust",
            "source:trust-to-untrust",
            "source:trust-to-untrust",
        ]

        static_web = records[0]
        assert static_web.rule.mapping is not None
        assert static_web.rule.mapping.forward is not None
        assert static_web.rule.mapping.reverse is not None
        assert static_web.rule.mapping.forward.translated.addresses == [
            "10.10.10.10/32"
        ]
        assert static_web.rule.mapping.forward.translated.ports == ["9443"]
        assert static_web.rule.mapping.forward.translated.ref == "internal-web"
        assert static_web.rule.mapping.forward.mapping_kind == "fixed"
        assert static_web.rule.mapping.forward.determinism == "exact"
        assert static_web.rule.mapping.forward.resolution_status == "resolved"

        snat_off = records[-1]
        assert snat_off.rule.action == "no_translate"
        assert snat_off.rule.enabled is False
        assert snat_off.rule.conditions.destination == ["172.16.0.0/24"]
        assert snat_off.rule.mapping is None

    def test_static_nat_exports_forward_and_reverse_mappings(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        static_web = records[0]

        fwd = static_web.rule.mapping.forward
        assert fwd.original.field == "destination"
        assert fwd.translated.field == "destination"
        assert fwd.translated.addresses == ["10.10.10.10/32"]
        assert fwd.translated.ports == ["9443"]
        assert fwd.translated.ref == "internal-web"

        rev = static_web.rule.mapping.reverse
        assert rev.original.field == "source"
        assert rev.original.addresses == ["10.10.10.10/32"]
        assert rev.translated.field == "source"
        assert rev.mapping_kind == "fixed"
        assert rev.determinism == "exact"

    def test_source_nat_pool_mapping(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        snat_pool = [r for r in records if r.rule.name == "snat-pool"][0]
        fwd = snat_pool.rule.mapping.forward

        assert fwd.original.field == "source"
        assert fwd.translated.field == "source"
        assert fwd.translated.addresses == ["198.51.100.10/32"]
        assert fwd.translated.ref == "internet-snat"
        assert fwd.mapping_kind == "pool"
        assert fwd.determinism == "exact"
        assert fwd.resolution_status == "resolved"
        assert snat_pool.rule.mapping.reverse is None

    def test_source_nat_interface_mapping(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        snat_iface = [r for r in records if r.rule.name == "snat-interface"][0]
        fwd = snat_iface.rule.mapping.forward

        assert fwd.original.field == "source"
        assert fwd.translated.field == "source"
        assert fwd.translated.address_source == "interface_address"
        assert fwd.translated.addresses is None
        assert fwd.mapping_kind == "interface_address"
        assert fwd.determinism == "dynamic"
        assert fwd.resolution_status == "resolved"
        assert snat_iface.rule.mapping.reverse is None

    def test_destination_nat_pool_with_port_mapping(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        dnat = [r for r in records if r.rule.name == "dnat-web"][0]
        fwd = dnat.rule.mapping.forward

        assert fwd.original.field == "destination"
        assert fwd.original.addresses == ["203.0.113.10/32"]
        assert fwd.original.ports == ["443"]
        assert fwd.translated.field == "destination"
        assert fwd.translated.addresses == ["10.10.10.10/32"]
        assert fwd.translated.ports == ["8443"]
        assert fwd.translated.ref == "web-dnat"
        assert fwd.mapping_kind == "pool"
        assert fwd.determinism == "exact"
        assert fwd.resolution_status == "resolved"
        assert dnat.rule.mapping.reverse is None

    def test_static_nat_unresolved_prefix_name(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        # static-web uses prefix-name "internal-web" which resolves via address-book
        static_web = records[0]
        assert static_web.rule.mapping.forward.resolution_status == "resolved"

        # static-admin uses inline prefix "10.10.10.11/32" (always resolved)
        static_admin = records[1]
        assert static_admin.rule.mapping.forward.resolution_status == "resolved"
        assert static_admin.rule.mapping.forward.translated.addresses == [
            "10.10.10.11/32"
        ]

    def test_no_translate_rule_has_no_mapping(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        snat_off = [r for r in records if r.rule.name == "snat-off"][0]

        assert snat_off.rule.action == "no_translate"
        assert snat_off.rule.mapping is None

    def test_summary_text_present_on_all_translate_rules(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        for record in records:
            if record.rule.action == "translate" and record.rule.mapping:
                assert record.rule.mapping.forward.summary
                assert "->" in record.rule.mapping.forward.summary

    def test_conditions_refs_present_on_records(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        snat_pool = [r for r in records if r.rule.name == "snat-pool"][0]
        assert snat_pool.rule.conditions.source_refs == ["client-net"]
        assert snat_pool.rule.conditions.destination_refs == ["any"]

    def test_get_nat_rules_defaults_unconstrained_matches_and_resolves_apps(
        self,
    ):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_resolved.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        rule_map = {record.rule.name: record for record in records}

        assert rule_map["snat-any"].rule.conditions.model_dump(exclude_none=True) == {
            "source": ["any"],
            "destination": ["any"],
        }
        assert rule_map["snat-source-only"].rule.conditions.model_dump(
            exclude_none=True
        ) == {
            "source": ["10.0.0.0/24"],
            "destination": ["any"],
            "source_refs": ["client-net"],
        }
        assert rule_map["snat-app"].rule.conditions.model_dump(
            exclude_none=True
        ) == {
            "source": ["10.0.0.0/24"],
            "destination": ["any"],
            "destination_ports": ["8080"],
            "protocols": ["tcp"],
            "applications": ["tcp-8080"],
            "source_refs": ["client-net"],
        }
        assert rule_map["snat-mixed"].rule.conditions.model_dump(
            exclude_none=True
        ) == {
            "source": ["any"],
            "destination": ["172.16.0.0/24"],
            "source_ports": ["1024-65535"],
            "destination_ports": ["53", "111"],
            "protocols": ["udp", "tcp"],
            "applications": ["rpc-app"],
            "destination_refs": ["partner-net"],
        }

    def test_pool_range_determinism_is_set_based(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_resolved.xml"),
            device_name="srx-nat",
        )

        records = driver.get_nat_rules()
        rule_map = {record.rule.name: record for record in records}

        # DNAT with range pool should be set_based
        dnat = rule_map["dnat-app-only"]
        assert dnat.rule.mapping.forward.determinism == "set_based"
        assert dnat.rule.mapping.forward.translated.addresses == [
            "10.10.10.10/32-10.10.10.12/32"
        ]


class TestNatJSONExport:
    def test_export_creates_directory(self, tmp_path):
        out = tmp_path / "subdir" / "nested"
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="fw-01",
        )

        result = driver.export_nat_json(out)

        assert result.exists()
        assert result.parent == out

    def test_export_fails_on_non_directory(self, tmp_path):
        file_path = tmp_path / "afile.txt"
        file_path.write_text("not a dir")
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        driver = JuniperSRXDriver(config_path=config_path, device_name="x")

        with pytest.raises(ValueError, match="not a directory"):
            driver.export_nat_json(file_path)

    def test_export_rejects_unknown_mode(self, tmp_path):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx",
        )

        with pytest.raises(ValueError, match="Unsupported export mode"):
            driver.export_nat_json(tmp_path, mode="verbose")

    def test_deterministic_filename(self, tmp_path):
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        driver = JuniperSRXDriver(
            config_path=config_path,
            device_name="srx-lab.corp",
        )

        result = driver.export_nat_json(tmp_path)

        assert result.name == "srx-lab.corp.nat_rules.json"

    def test_json_payload_shape_and_context_order(self, tmp_path):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path))

        assert data["vendor"] == "juniper_srx"
        assert data["device"] == "srx-test"
        assert data["schema_version"] == 2
        assert data["mode"] == "enriched"
        assert data["nat_rule_count"] == 6
        assert data["evaluation_model"] == {
            "nat_type_precedence": ["static", "destination", "source"],
            "rule_order_within_context": "top_down_first_match",
        }
        assert _payload_context_ids(data) == [
            "static:static-public",
            "destination:public-services",
            "source:trust-to-untrust",
        ]

        static_context = data["contexts"][0]
        assert static_context["context"] == {
            "context_id": "static:static-public",
            "nat_type": "static",
            "priority_rank": 1,
            "context_order": 1,
            "rulebase": "security_nat",
            "rule_set": "static-public",
            "from_zones": ["untrust"],
        }
        assert static_context["rule_count"] == 2
        assert [rule["name"] for rule in static_context["rules"]] == [
            "static-web",
            "static-admin",
        ]

        source_context = data["contexts"][2]
        assert [rule["sequence"] for rule in source_context["rules"]] == [1, 2, 3]
        assert [rule["name"] for rule in source_context["rules"]] == [
            "snat-pool",
            "snat-interface",
            "snat-off",
        ]

    def test_enriched_mode_includes_mapping_and_supporting_objects(
        self, tmp_path
    ):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path))

        dnat_rule = data["contexts"][1]["rules"][0]
        assert dnat_rule["conditions"]["source"] == ["any"]
        assert dnat_rule["conditions"]["destination"] == ["203.0.113.10/32"]
        assert dnat_rule["conditions"]["destination_ports"] == ["443"]
        assert dnat_rule["conditions"]["protocols"] == ["tcp"]

        fwd = dnat_rule["mapping"]["forward"]
        assert fwd["original"]["field"] == "destination"
        assert fwd["original"]["addresses"] == ["203.0.113.10/32"]
        assert fwd["original"]["ports"] == ["443"]
        assert fwd["translated"]["field"] == "destination"
        assert fwd["translated"]["addresses"] == ["10.10.10.10/32"]
        assert fwd["translated"]["ports"] == ["8443"]
        assert fwd["translated"]["ref"] == "web-dnat"
        assert fwd["mapping_kind"] == "pool"
        assert fwd["determinism"] == "exact"
        assert fwd["resolution_status"] == "resolved"
        assert "raw" not in dnat_rule
        assert "vendor" not in dnat_rule
        assert "device" not in dnat_rule

        snat_rule = data["contexts"][2]["rules"][0]
        assert snat_rule["conditions"]["source_refs"] == ["client-net"]
        assert snat_rule["conditions"]["destination_refs"] == ["any"]
        snat_fwd = snat_rule["mapping"]["forward"]
        assert snat_fwd["translated"]["ref"] == "internet-snat"
        assert snat_fwd["translated"]["addresses"] == ["198.51.100.10/32"]
        assert snat_fwd["mapping_kind"] == "pool"

        assert data["supporting_objects"]["translation_pools"] == [
            {
                "name": "web-dnat",
                "nat_type": "destination",
                "addresses": ["10.10.10.10/32"],
                "ports": ["8443"],
                "description": "Forward public HTTPS to internal web server",
            },
            {
                "name": "internet-snat",
                "nat_type": "source",
                "addresses": ["198.51.100.10/32"],
                "description": "SNAT pool for internet egress",
            },
        ]

    def test_static_nat_json_has_forward_and_reverse(self, tmp_path):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path))
        static_rule = data["contexts"][0]["rules"][0]
        mapping = static_rule["mapping"]

        assert "forward" in mapping
        assert "reverse" in mapping
        assert mapping["forward"]["original"]["field"] == "destination"
        assert mapping["forward"]["translated"]["field"] == "destination"
        assert mapping["reverse"]["original"]["field"] == "source"
        assert mapping["reverse"]["translated"]["field"] == "source"

    def test_export_resolves_application_matches_and_pool_ranges(
        self, tmp_path
    ):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_resolved.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path))
        source_rules = data["contexts"][1]["rules"]
        source_rule_map = {rule["name"]: rule for rule in source_rules}

        assert source_rule_map["snat-any"]["conditions"]["source"] == ["any"]
        assert source_rule_map["snat-any"]["conditions"]["destination"] == ["any"]
        assert source_rule_map["snat-source-only"]["conditions"]["source"] == [
            "10.0.0.0/24"
        ]
        assert source_rule_map["snat-source-only"]["conditions"]["destination"] == [
            "any"
        ]
        assert source_rule_map["snat-app"]["conditions"]["protocols"] == ["tcp"]
        assert source_rule_map["snat-app"]["conditions"]["applications"] == [
            "tcp-8080"
        ]
        assert source_rule_map["snat-mixed"]["conditions"]["protocols"] == [
            "udp",
            "tcp",
        ]

        dnat_rule = data["contexts"][0]["rules"][0]
        dnat_fwd = dnat_rule["mapping"]["forward"]
        assert dnat_fwd["translated"]["addresses"] == [
            "10.10.10.10/32-10.10.10.12/32"
        ]
        assert dnat_fwd["translated"]["ports"] == ["8443"]
        assert dnat_fwd["determinism"] == "set_based"

        assert data["supporting_objects"]["translation_pools"] == [
            {
                "name": "web-dnat-range",
                "nat_type": "destination",
                "addresses": ["10.10.10.10/32-10.10.10.12/32"],
                "ports": ["8443"],
                "description": "DNAT address range",
            },
            {
                "name": "range-snat",
                "nat_type": "source",
                "addresses": ["198.51.100.20/32-198.51.100.30/32"],
                "description": "SNAT address range",
            },
        ]

    def test_minimal_mode_excludes_refs_debug_and_supporting_objects(
        self, tmp_path
    ):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path, mode="minimal"))
        first_rule = data["contexts"][2]["rules"][0]

        assert "source_refs" not in first_rule.get("conditions", {})
        assert "destination_refs" not in first_rule.get("conditions", {})
        assert "raw" not in first_rule
        assert "vendor" not in first_rule
        assert "device" not in first_rule
        assert "supporting_objects" not in data

        # mapping structure still present in minimal
        assert first_rule["mapping"]["forward"]["mapping_kind"] == "pool"

    def test_debug_mode_includes_raw_for_rules_and_pools(self, tmp_path):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path, mode="debug"))

        first_rule = data["contexts"][0]["rules"][0]
        assert first_rule["raw"]["name"] == "static-web"
        assert data["supporting_objects"]["translation_pools"][0]["raw"]["name"] == (
            "web-dnat"
        )

    def test_overwrite_is_atomic(self, tmp_path):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx",
        )

        path1 = driver.export_nat_json(tmp_path)
        data1 = _read_json(path1)
        path2 = driver.export_nat_json(tmp_path)
        data2 = _read_json(path2)

        assert path1 == path2
        assert data2["nat_rule_count"] == data1["nat_rule_count"]
        assert len(list(tmp_path.glob(".*"))) == 0

    def test_empty_config_exports_empty_nat_inventory(self, tmp_path):
        config_path = _write_xml(tmp_path, "empty.xml", "<configuration/>")
        driver = JuniperSRXDriver(config_path=config_path, device_name="empty")

        data = _read_json(driver.export_nat_json(tmp_path))

        assert data["nat_rule_count"] == 0
        assert data["contexts"] == []
        assert data["supporting_objects"] == {"translation_pools": []}


class TestNatRealXmlTags:
    """Verify parsing when XML uses real Junos NAT match tag names.

    Real ``show configuration | display xml`` output uses
    ``<src-nat-rule-match>``, ``<dest-nat-rule-match>``, and
    ``<static-nat-rule-match>`` instead of the generic ``<match>``.
    """

    def test_source_nat_conditions_parsed_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        snat_pool = [r for r in records if r.rule.name == "snat-pool"][0]

        assert snat_pool.rule.conditions.source == ["10.0.0.0/24"]
        assert snat_pool.rule.conditions.source_refs == ["client-net"]
        assert snat_pool.rule.conditions.destination == ["any"]
        assert snat_pool.rule.conditions.destination_refs == ["any"]

    def test_source_nat_interface_conditions_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        snat_iface = [r for r in records if r.rule.name == "snat-interface"][0]

        assert snat_iface.rule.conditions.source == ["10.1.0.0/24"]
        assert snat_iface.rule.conditions.source_refs == ["guest-net"]
        assert snat_iface.rule.conditions.protocols == ["tcp"]

    def test_source_nat_any_still_defaults_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        snat_any = [r for r in records if r.rule.name == "snat-any"][0]

        assert snat_any.rule.conditions.source == ["any"]
        assert snat_any.rule.conditions.destination == ["any"]

    def test_source_nat_off_conditions_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        snat_off = [r for r in records if r.rule.name == "snat-off"][0]

        assert snat_off.rule.action == "no_translate"
        assert snat_off.rule.conditions.destination == ["172.16.0.0/24"]
        assert snat_off.rule.conditions.destination_refs == ["partner-net"]

    def test_destination_nat_conditions_parsed_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        dnat = [r for r in records if r.rule.name == "dnat-web"][0]

        assert dnat.rule.conditions.destination == ["203.0.113.10/32"]
        assert dnat.rule.conditions.destination_refs == ["203.0.113.10/32"]
        assert dnat.rule.conditions.destination_ports == ["443"]
        assert dnat.rule.conditions.protocols == ["tcp"]

    def test_static_nat_conditions_parsed_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        static_web = [r for r in records if r.rule.name == "static-web"][0]

        assert static_web.rule.conditions.destination == ["198.51.100.200/32"]
        assert static_web.rule.conditions.destination_refs == [
            "198.51.100.200/32"
        ]
        assert static_web.rule.mapping.forward.translated.addresses == [
            "10.10.10.10/32"
        ]

    def test_source_nat_pool_mapping_with_real_tags(self):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat_real_tags.xml"),
            device_name="srx-real",
        )

        records = driver.get_nat_rules()
        snat_pool = [r for r in records if r.rule.name == "snat-pool"][0]
        fwd = snat_pool.rule.mapping.forward

        assert fwd.original.field == "source"
        assert fwd.original.addresses == ["10.0.0.0/24"]
        assert fwd.translated.addresses == ["198.51.100.10/32"]
        assert fwd.translated.ref == "internet-snat"
        assert fwd.mapping_kind == "pool"
