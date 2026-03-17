from pydantic import BaseModel
from typing import List, Optional


class FirewallRule(BaseModel):
    id: Optional[str]
    vendor: str
    device: str
    name: str
    source: List[str]
    destination: List[str]
    service: List[str]
    action: str
    enabled: bool = True
