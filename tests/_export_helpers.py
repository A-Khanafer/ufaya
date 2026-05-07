"""Shared helpers for the export schema + snapshot test suites."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

EXPORT_MODES = ("minimal", "enriched", "debug")
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"
SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"

ALL_FIXTURES: list[str] = sorted(p.stem for p in FIXTURES_DIR.glob("*.xml"))


def export_rules(fixture: str, mode: str) -> dict[str, Any]:
    """Run a firewall_rules export against the given fixture and return the payload."""
    from ufaya import get_firewall_driver

    driver = get_firewall_driver(
        "juniper_srx",
        config_path=str(FIXTURES_DIR / f"{fixture}.xml"),
        device_name="fw-snapshot",
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = driver.export_rules_json(tmp, mode=mode)
        return _load(path)


def export_nat(fixture: str, mode: str) -> dict[str, Any]:
    """Run a nat_rules export against the given fixture and return the payload."""
    from ufaya import get_firewall_driver

    driver = get_firewall_driver(
        "juniper_srx",
        config_path=str(FIXTURES_DIR / f"{fixture}.xml"),
        device_name="fw-snapshot",
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = driver.export_nat_json(tmp, mode=mode)
        return _load(path)


def load_schema(name: str) -> dict[str, Any]:
    """Load a JSON Schema by filename (e.g. ``firewall_rules.v3.schema.json``)."""
    return _load(SCHEMAS_DIR / name)


def _load(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fp:
        return json.load(fp)
