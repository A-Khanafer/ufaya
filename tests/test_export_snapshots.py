"""Snapshot regression tests for every fixture × export-mode combination.

Snapshot tests catch ANY change in export output, intentional or not.
When a change is intentional, run::

    UPDATE_SNAPSHOTS=1 pytest tests/test_export_snapshots.py

then inspect the resulting diff (it lives in ``tests/snapshots/``) before
committing. Reviewers see exactly what JSON consumers will see.

The complementary test suite (test_export_schema.py) verifies that the
output still conforms to the documented JSON Schema contract.
"""

from __future__ import annotations

import pytest

from tests._export_helpers import (
    ALL_FIXTURES,
    EXPORT_MODES,
    SNAPSHOTS_DIR,
    export_nat,
    export_rules,
)
from tests._snapshot import assert_matches_snapshot


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
@pytest.mark.parametrize("mode", EXPORT_MODES)
def test_rules_export_snapshot(fixture: str, mode: str):
    payload = export_rules(fixture, mode)
    assert_matches_snapshot(
        payload, SNAPSHOTS_DIR / "rules" / f"{fixture}.{mode}.json"
    )


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
@pytest.mark.parametrize("mode", EXPORT_MODES)
def test_nat_export_snapshot(fixture: str, mode: str):
    payload = export_nat(fixture, mode)
    assert_matches_snapshot(
        payload, SNAPSHOTS_DIR / "nat" / f"{fixture}.{mode}.json"
    )
