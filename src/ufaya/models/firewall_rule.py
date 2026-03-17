from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class FirewallRule(BaseModel):
    id: Optional[str] = None
    vendor: str
    device: str
    name: str
    source: list[str]
    destination: list[str]
    service: list[str]
    action: str
    enabled: bool = True
