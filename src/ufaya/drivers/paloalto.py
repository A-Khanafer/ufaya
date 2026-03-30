from __future__ import annotations

from ufaya.firewall.base import FirewallDriver
from ufaya.models.firewall_rule import FirewallRule, FirewallRuleRecord


class PaloAltoDriver(FirewallDriver):
    """Driver for Palo Alto Networks devices."""

    def __init__(self, host: str, username: str, password: str) -> None:
        self.host = host
        self.username = username
        self.password = password

    def get_rules(self) -> list[FirewallRuleRecord]:
        return []

    def create_rule(self, rule: FirewallRule) -> None:
        pass

    def delete_rule(self, rule_id: str) -> None:
        pass

    def commit(self) -> None:
        pass
