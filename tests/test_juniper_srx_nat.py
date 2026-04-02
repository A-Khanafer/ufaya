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
        assert static_web.rule.translation is not None
        assert static_web.rule.translation.bidirectional is True
        assert static_web.rule.translation.destination is not None
        assert static_web.rule.translation.destination.addresses == [
            "10.10.10.10/32"
        ]
        assert static_web.rule.translation.destination.ports == ["9443"]
        assert static_web.trace.translation_destination_ref == "internal-web"

        snat_off = records[-1]
        assert snat_off.rule.action == "no_translate"
        assert snat_off.rule.enabled is False
        assert snat_off.rule.match.destination == ["172.16.0.0/24"]


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
        assert data["schema_version"] == 1
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

    def test_enriched_mode_includes_traceability_and_supporting_objects(
        self, tmp_path
    ):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path))

        dnat_rule = data["contexts"][1]["rules"][0]
        assert dnat_rule["match"] == {
            "destination": ["203.0.113.10/32"],
            "destination_ports": ["443"],
            "protocols": ["tcp"],
        }
        assert dnat_rule["translation"] == {
            "destination": {
                "mode": "pool",
                "addresses": ["10.10.10.10/32"],
                "ports": ["8443"],
            },
            "bidirectional": False,
        }
        assert dnat_rule["translation_destination_ref"] == "web-dnat"
        assert "raw" not in dnat_rule
        assert "vendor" not in dnat_rule
        assert "device" not in dnat_rule

        snat_rule = data["contexts"][2]["rules"][0]
        assert snat_rule["source_refs"] == ["client-net"]
        assert snat_rule["destination_refs"] == ["any"]
        assert snat_rule["translation_source_ref"] == "internet-snat"
        assert snat_rule["translation"] == {
            "source": {
                "mode": "pool",
                "addresses": ["198.51.100.10/32"],
            },
            "bidirectional": False,
        }

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

    def test_minimal_mode_excludes_traceability_debug_and_supporting_objects(
        self, tmp_path
    ):
        driver = JuniperSRXDriver(
            config_path=_fixture("juniper_nat.xml"),
            device_name="srx-test",
        )

        data = _read_json(driver.export_nat_json(tmp_path, mode="minimal"))
        first_rule = data["contexts"][2]["rules"][0]

        assert first_rule["translation"] == {
            "source": {
                "mode": "pool",
                "addresses": ["198.51.100.10/32"],
            },
            "bidirectional": False,
        }
        assert "source_refs" not in first_rule
        assert "destination_refs" not in first_rule
        assert "translation_source_ref" not in first_rule
        assert "raw" not in first_rule
        assert "vendor" not in first_rule
        assert "device" not in first_rule
        assert "supporting_objects" not in data

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
