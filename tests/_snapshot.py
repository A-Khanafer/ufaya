"""Tiny pytest-friendly JSON snapshot helper.

Snapshots live as plain ``.json`` files under ``tests/snapshots/``, so
diffs render naturally in code review and consumers can read them as
documentation of the wire format.

Usage::

    from tests._snapshot import assert_matches_snapshot

    def test_something():
        assert_matches_snapshot(
            payload, snapshot_dir / "expected.json"
        )

Set ``UPDATE_SNAPSHOTS=1`` to (re)generate snapshots in place::

    UPDATE_SNAPSHOTS=1 pytest tests/test_export_snapshots.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

UPDATE_FLAG = "UPDATE_SNAPSHOTS"


def is_update_run() -> bool:
    return os.environ.get(UPDATE_FLAG, "").lower() in {"1", "true", "yes"}


def assert_matches_snapshot(payload: Any, path: Path) -> None:
    """Assert that *payload* (any JSON-serializable value) matches the file at *path*.

    If the file does not exist or ``UPDATE_SNAPSHOTS=1`` is set, the
    snapshot is (re)written and the test is reported as passing. CI runs
    must NOT set ``UPDATE_SNAPSHOTS``; without it, a missing snapshot file
    is a hard failure.
    """
    serialized = _dump(payload)

    if is_update_run() or not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(serialized + "\n", encoding="utf-8")
        if not is_update_run():
            raise AssertionError(
                f"Snapshot at {path} did not exist. Created it from the current "
                f"output. Re-run the test, and commit the snapshot if it looks right."
            )
        return

    expected = path.read_text(encoding="utf-8").rstrip("\n")
    if serialized != expected:
        raise AssertionError(
            f"Snapshot mismatch at {path}.\n"
            f"Run `UPDATE_SNAPSHOTS=1 pytest {path.parent}` to regenerate, "
            f"then review the diff before committing.\n"
            f"--- expected\n{expected}\n--- actual\n{serialized}"
        )


def _dump(payload: Any) -> str:
    """Stable, deterministic JSON serialization used for both write and compare."""
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)
