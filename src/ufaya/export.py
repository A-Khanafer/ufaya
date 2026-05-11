"""JSON export utilities shared across vendor drivers.

This module owns three concerns that are not vendor-specific:

1. Validating and normalizing export modes.
2. Building the canonical context-grouped payload structure.
3. Atomically writing the JSON payload to disk.

Drivers gather records and call the helpers here rather than reimplementing
the tempfile + ``os.replace`` dance per vendor.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from ufaya.models.firewall_rule import FirewallRuleRecord
    from ufaya.models.nat_rule import NatRuleRecord

ExportMode = Literal["minimal", "enriched", "debug"]
VALID_EXPORT_MODES: tuple[ExportMode, ...] = ("minimal", "enriched", "debug")
_EXPORT_MODE_LOOKUP: dict[str, ExportMode] = {
    "minimal": "minimal",
    "enriched": "enriched",
    "debug": "debug",
}


def normalize_export_mode(mode: str) -> ExportMode:
    """Validate and normalize an export mode string."""
    export_mode = _EXPORT_MODE_LOOKUP.get(mode)
    if export_mode is None:
        supported = ", ".join(VALID_EXPORT_MODES)
        raise ValueError(
            f"Unsupported export mode '{mode}'. Choose from: {supported}"
        )
    return export_mode


def write_json_atomic(
    payload: Mapping[str, Any], path: Path, *, prefix: str | None = None
) -> Path:
    """Atomically write *payload* as pretty-printed JSON to *path*.

    Writes to a sibling tempfile and ``os.replace``s into place so readers
    never observe a partial file. Cleans up the tempfile on failure.
    """
    out_dir = path.parent
    fd, tmp_path = tempfile.mkstemp(
        dir=str(out_dir),
        prefix=prefix or f".{path.stem}_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2, ensure_ascii=False)
            fp.write("\n")
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return path


def _group_by_context(
    records: list[FirewallRuleRecord] | list[NatRuleRecord],
    mode: ExportMode,
) -> list[dict[str, Any]]:
    """Group records by ``context.context_id`` preserving insertion order."""
    contexts: list[dict[str, Any]] = []
    grouped: dict[str, dict[str, Any]] = {}

    for record in records:
        context_id = record.context.context_id
        if context_id not in grouped:
            grouped[context_id] = {
                "context": record.context.dump_for_export(),
                "rule_count": 0,
                "rules": [],
            }
            contexts.append(grouped[context_id])

        entry = grouped[context_id]
        entry["rules"].append(
            record.export_rule(
                mode,
                include_vendor=False,
                include_device=False,
            )
        )
        entry["rule_count"] += 1

    return contexts


def build_rules_payload(
    records: list[FirewallRuleRecord],
    *,
    vendor: str,
    device: str,
    mode: ExportMode,
    schema_version: int,
    evaluation_model: Mapping[str, Any],
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical firewall-rules export payload.

    ``extra`` is merged after the canonical fields (e.g. for
    ``hit_counts_collected_at`` on Juniper) and lives at the document root.
    """
    payload: dict[str, Any] = {"vendor": vendor, "device": device}
    if extra:
        payload.update(extra)
    payload.update(
        {
            "schema_version": schema_version,
            "mode": mode,
            "rule_count": len(records),
            "evaluation_model": dict(evaluation_model),
            "contexts": _group_by_context(records, mode),
        }
    )
    return payload


def build_nat_payload(
    records: list[NatRuleRecord],
    *,
    vendor: str,
    device: str,
    mode: ExportMode,
    schema_version: int,
    evaluation_model: Mapping[str, Any],
    supporting_objects: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the canonical NAT-rules export payload."""
    payload: dict[str, Any] = {
        "vendor": vendor,
        "device": device,
        "schema_version": schema_version,
        "mode": mode,
        "nat_rule_count": len(records),
        "evaluation_model": dict(evaluation_model),
        "contexts": _group_by_context(records, mode),
    }
    if supporting_objects:
        payload["supporting_objects"] = dict(supporting_objects)
    return payload
