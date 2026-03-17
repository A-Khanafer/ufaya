from __future__ import annotations

from pydantic import BaseModel


class FirewallRule(BaseModel):
    id: str | None = None
    vendor: str
    device: str
    name: str
    source: list[str]
    destination: list[str]
    service: list[str]
    action: str
    enabled: bool = True
