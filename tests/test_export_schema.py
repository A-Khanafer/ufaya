"""Validate every fixture × mode export against the public JSON Schemas.

These tests prove that the wire format conforms to the documented
contract. Snapshot tests (test_export_snapshots.py) are the complementary
"did anything change?" check.
"""

from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator

from tests._export_helpers import (
    ALL_FIXTURES,
    EXPORT_MODES,
    export_nat,
    export_rules,
    load_schema,
)

RULES_SCHEMA = load_schema("firewall_rules.v3.schema.json")
NAT_SCHEMA = load_schema("nat_rules.v2.schema.json")

_RULES_VALIDATOR = Draft202012Validator(RULES_SCHEMA)
_NAT_VALIDATOR = Draft202012Validator(NAT_SCHEMA)


def test_rules_schema_itself_is_valid():
    """The firewall_rules schema must itself be a valid JSON Schema."""
    Draft202012Validator.check_schema(RULES_SCHEMA)


def test_nat_schema_itself_is_valid():
    """The nat_rules schema must itself be a valid JSON Schema."""
    Draft202012Validator.check_schema(NAT_SCHEMA)


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
@pytest.mark.parametrize("mode", EXPORT_MODES)
def test_rules_export_matches_schema(fixture: str, mode: str):
    payload = export_rules(fixture, mode)
    errors = sorted(_RULES_VALIDATOR.iter_errors(payload), key=lambda e: e.path)
    if errors:
        pytest.fail(_format_errors(fixture, mode, "firewall_rules", errors))


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
@pytest.mark.parametrize("mode", EXPORT_MODES)
def test_nat_export_matches_schema(fixture: str, mode: str):
    payload = export_nat(fixture, mode)
    errors = sorted(_NAT_VALIDATOR.iter_errors(payload), key=lambda e: e.path)
    if errors:
        pytest.fail(_format_errors(fixture, mode, "nat_rules", errors))


def _format_errors(fixture: str, mode: str, kind: str, errors) -> str:
    lines = [f"{kind} export for {fixture!r} ({mode}) violated the schema:"]
    for err in errors:
        path = "/".join(str(p) for p in err.absolute_path) or "<root>"
        lines.append(f"  - at {path}: {err.message}")
    return "\n".join(lines)
