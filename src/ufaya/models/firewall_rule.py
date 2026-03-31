from __future__ import annotations

from typing import Any, Literal, cast

from pydantic import BaseModel

ExportMode = Literal["minimal", "enriched", "debug"]
VALID_EXPORT_MODES: tuple[ExportMode, ...] = ("minimal", "enriched", "debug")


class ServiceDetail(BaseModel):
    """Normalized service match semantics shared across vendors."""

    label: str | None = None
    protocol: str | None = None
    source_ports: list[str] | None = None
    destination_ports: list[str] | None = None
    application_protocol: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp6_type: int | None = None
    icmp6_code: int | None = None
    rpc_program_number: str | None = None
    inactivity_timeout: str | None = None
    resolved: bool = False


class RuleContext(BaseModel):
    """Context in which a vendor evaluates a firewall rule."""

    context_id: str
    scope: str
    priority_rank: int
    context_order: int
    rulebase: str
    section: str | None = None
    from_zone: str | None = None
    to_zone: str | None = None
    package: str | None = None
    vsys: str | None = None
    vdom: str | None = None


class FirewallRule(BaseModel):
    """Canonical representation of a firewall rule across all vendors."""

    vendor: str
    device: str
    vendor_rule_id: str | None = None
    name: str
    source: list[str]
    destination: list[str]
    service: list[str]
    action: str
    enabled: bool = True

    sequence: int | None = None
    hit_count: int | None = None
    description: str | None = None
    log_actions: list[str] | None = None


class FirewallRuleTrace(BaseModel):
    """Traceability fields that preserve vendor-specific policy intent."""

    source_refs: list[str] | None = None
    destination_refs: list[str] | None = None
    service_refs: list[str] | None = None
    service_details: list[ServiceDetail] | None = None


class FirewallRuleDebug(BaseModel):
    """Optional debug payload for lossless vendor troubleshooting."""

    raw: dict[str, Any]


class FirewallRuleRecord(BaseModel):
    """Context-aware wrapper around canonical rule data."""

    rule: FirewallRule
    context: RuleContext
    trace: FirewallRuleTrace | None = None
    debug: FirewallRuleDebug | None = None

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
        payload["hit_count"] = self.rule.hit_count
        if not include_vendor:
            payload.pop("vendor", None)
        if not include_device:
            payload.pop("device", None)
        if include_context:
            payload["context"] = self.context.model_dump(exclude_none=True)

        if export_mode in {"enriched", "debug"} and self.trace is not None:
            payload.update(self.trace.model_dump(exclude_none=True))
        if export_mode == "debug" and self.debug is not None:
            payload.update(self.debug.model_dump(exclude_none=True))

        return payload


def normalize_export_mode(mode: str) -> ExportMode:
    """Validate and normalize an export mode string."""
    if mode not in VALID_EXPORT_MODES:
        supported = ", ".join(VALID_EXPORT_MODES)
        raise ValueError(
            f"Unsupported export mode '{mode}'. Choose from: {supported}"
        )
    return cast(ExportMode, mode)
