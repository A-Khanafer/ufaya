"""Tests for the public UFAYA command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ufaya.cli import main
from ufaya.firewall.base import FirewallReader
from ufaya.services.device_factory import register_driver, unregister_driver

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("resource", "mode", "fixture", "suffix", "count_field"),
    [
        (
            "rules",
            "minimal",
            "juniper_full.xml",
            ".firewall_rules.json",
            "rule_count",
        ),
        (
            "rules",
            "enriched",
            "juniper_full.xml",
            ".firewall_rules.json",
            "rule_count",
        ),
        (
            "rules",
            "debug",
            "juniper_full.xml",
            ".firewall_rules.json",
            "rule_count",
        ),
        ("nat", "minimal", "juniper_nat.xml", ".nat_rules.json", "nat_rule_count"),
        (
            "nat",
            "enriched",
            "juniper_nat.xml",
            ".nat_rules.json",
            "nat_rule_count",
        ),
        ("nat", "debug", "juniper_nat.xml", ".nat_rules.json", "nat_rule_count"),
    ],
)
def test_export_commands_write_json_for_every_mode(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    resource: str,
    mode: str,
    fixture: str,
    suffix: str,
    count_field: str,
) -> None:
    output_dir = tmp_path / "exports"

    result = main(
        [
            "export",
            resource,
            "--vendor",
            "juniper_srx",
            "--config",
            str(FIXTURES / fixture),
            "--out",
            str(output_dir),
            "--mode",
            mode,
        ]
    )

    assert result == 0
    output_path = Path(capsys.readouterr().out.strip())
    assert output_path.parent == output_dir
    assert output_path.name.endswith(suffix)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["vendor"] == "juniper_srx"
    assert payload["mode"] == mode
    assert payload[count_field] > 0


def test_export_mode_defaults_to_enriched(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "export",
                "rules",
                "--vendor",
                "juniper_srx",
                "--config",
                str(FIXTURES / "juniper_full.xml"),
                "--out",
                str(tmp_path),
            ]
        )
        == 0
    )

    output_path = Path(capsys.readouterr().out.strip())
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["mode"] == "enriched"


def test_unknown_vendor_exits_with_useful_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "export",
                "rules",
                "--vendor",
                "unknown",
                "--config",
                str(FIXTURES / "juniper_full.xml"),
                "--out",
                str(tmp_path),
            ]
        )

    assert excinfo.value.code == 1
    error = capsys.readouterr().err
    assert "Unsupported vendor 'unknown'" in error
    assert "juniper_srx" in error


def test_missing_config_exits_without_creating_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output_dir = tmp_path / "exports"

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "export",
                "rules",
                "--vendor",
                "juniper_srx",
                "--config",
                str(tmp_path / "missing.xml"),
                "--out",
                str(output_dir),
            ]
        )

    assert excinfo.value.code == 1
    assert "Configuration file does not exist" in capsys.readouterr().err
    assert not output_dir.exists()


def test_malformed_config_exits_with_useful_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "malformed.xml"
    config.write_text("<configuration>", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "export",
                "nat",
                "--vendor",
                "juniper_srx",
                "--config",
                str(config),
                "--out",
                str(tmp_path / "exports"),
            ]
        )

    assert excinfo.value.code == 1
    assert "Malformed XML configuration" in capsys.readouterr().err


def test_invalid_mode_is_rejected_by_argument_parser(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "export",
                "rules",
                "--vendor",
                "juniper_srx",
                "--config",
                str(FIXTURES / "juniper_full.xml"),
                "--out",
                str(tmp_path),
                "--mode",
                "verbose",
            ]
        )

    assert excinfo.value.code == 2
    error = capsys.readouterr().err
    assert "invalid choice: 'verbose'" in error
    assert "minimal" in error
    assert "enriched" in error
    assert "debug" in error


def test_nat_export_rejects_driver_without_nat_capability(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class RulesOnlyDriver(FirewallReader):
        def __init__(self, **kwargs: object) -> None:
            pass

        def get_rules(self) -> list:
            return []

    register_driver("rules_only", RulesOnlyDriver)
    try:
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "export",
                    "nat",
                    "--vendor",
                    "rules_only",
                    "--config",
                    str(FIXTURES / "juniper_full.xml"),
                    "--out",
                    str(tmp_path),
                ]
            )
    finally:
        unregister_driver("rules_only")

    assert excinfo.value.code == 1
    assert "does not support NAT reads" in capsys.readouterr().err
