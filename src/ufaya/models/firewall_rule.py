from __future__ import annotations

from typing import Any

from pydantic import BaseModel


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


class FirewallRule(BaseModel):
    """Canonical representation of a firewall rule across all vendors."""

    id: str | None = None
    vendor: str
    device: str
    name: str
    source: list[str]
    destination: list[str]
    service: list[str]
    action: str
    enabled: bool = True

    # Optional fields common across zone-based firewall vendors.
    # Drivers populate whichever fields the vendor supports;
    # callers should treat None as "not provided by this vendor."
    sequence: int | None = None
    source_zones: list[str] | None = None
    destination_zones: list[str] | None = None
    source_refs: list[str] | None = None
    destination_refs: list[str] | None = None
    service_refs: list[str] | None = None
    service_details: list[ServiceDetail] | None = None
    description: str | None = None
    log_events: bool = False
    log_actions: list[str] | None = None
    raw: dict[str, Any] | None = None
