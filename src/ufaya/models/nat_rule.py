from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ufaya.export import normalize_export_mode

NatType = Literal["source", "destination", "static"]
NatAction = Literal["translate", "no_translate"]
MappingKind = Literal["fixed", "pool", "interface_address"]
Determinism = Literal["exact", "set_based", "dynamic"]
ResolutionStatus = Literal["resolved", "unresolved"]

_CONDITIONS_REF_FIELDS = {"source_refs", "destination_refs"}


class NatConditions(BaseModel):
    """Traffic-match conditions that select which packets a NAT rule applies to."""

    source: list[str] | None = None
    destination: list[str] | None = None
    source_ports: list[str] | None = None
    destination_ports: list[str] | None = None
    protocols: list[str] | None = None
    applications: list[str] | None = None
    source_refs: list[str] | None = None
    destination_refs: list[str] | None = None


class NatMappingSide(BaseModel):
    """One side (original or translated) of a NAT rewrite step."""

    field: str
    addresses: list[str] | None = None
    ports: list[str] | None = None
    ref: str | None = None
    address_source: str | None = None


class NatRewrite(BaseModel):
    """A single directional rewrite: what was the original value and what it becomes."""

    summary: str
    original: NatMappingSide
    translated: NatMappingSide
    mapping_kind: MappingKind
    determinism: Determinism
    resolution_status: ResolutionStatus


class NatMapping(BaseModel):
    """Forward and optional reverse rewrite steps for a NAT rule."""

    forward: NatRewrite
    reverse: NatRewrite | None = None


class NatRuleContext(BaseModel):
    """Context in which a vendor evaluates a NAT rule.

    ``rule_set`` is a Junos grouping concept and may not exist on every
    vendor; vendors without an analogous concept should leave it ``None``
    and use ``vendor_context`` for any extra scoping data.
    """

    context_id: str
    nat_type: NatType
    priority_rank: int
    context_order: int
    rulebase: str
    rule_set: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    from_interfaces: list[str] | None = None
    to_interfaces: list[str] | None = None
    from_routing_instances: list[str] | None = None
    to_routing_instances: list[str] | None = None
    vendor_context: dict[str, Any] = Field(default_factory=dict)

    def dump_for_export(self) -> dict[str, Any]:
        """Dump the context, omitting None fields and empty ``vendor_context``."""
        data = self.model_dump(exclude_none=True)
        if not data.get("vendor_context"):
            data.pop("vendor_context", None)
        return data


class NatRule(BaseModel):
    """Canonical representation of a NAT rule across all vendors."""

    vendor: str
    device: str
    nat_type: NatType
    name: str
    conditions: NatConditions
    action: NatAction
    enabled: bool = True

    mapping: NatMapping | None = None
    vendor_rule_id: str | None = None
    sequence: int | None = None
    description: str | None = None


class NatRuleDebug(BaseModel):
    """Optional debug payload for lossless vendor troubleshooting."""

    raw: dict[str, Any]


class NatRuleRecord(BaseModel):
    """Context-aware wrapper around canonical NAT rule data."""

    rule: NatRule
    context: NatRuleContext
    debug: NatRuleDebug | None = None

    def export_rule(
        self,
        mode: str,
        *,
        include_vendor: bool = True,
        include_device: bool = True,
        include_context: bool = False,
    ) -> dict[str, Any]:
        """Flatten this record into a mode-aware export payload."""
        export_mode = normalize_export_mode(mode)

        payload = self.rule.model_dump(exclude_none=True)
        if not include_vendor:
            payload.pop("vendor", None)
        if not include_device:
            payload.pop("device", None)
        if include_context:
            payload["context"] = self.context.dump_for_export()

        if export_mode == "minimal":
            conditions = payload.get("conditions", {})
            for ref_field in _CONDITIONS_REF_FIELDS:
                conditions.pop(ref_field, None)

        if export_mode == "debug" and self.debug is not None:
            payload.update(self.debug.model_dump(exclude_none=True))

        return payload
