from __future__ import annotations

from abc import ABC, abstractmethod

from ufaya.models.firewall_rule import FirewallRule


class FirewallDriver(ABC):
    """Abstract base class for all firewall vendor drivers."""

    @abstractmethod
    def get_rules(self) -> list[FirewallRule]:
        """Return all firewall rules from the device."""

    @abstractmethod
    def create_rule(self, rule: FirewallRule) -> None:
        """Push a new firewall rule to the device."""

    @abstractmethod
    def delete_rule(self, rule_id: str) -> None:
        """Remove a firewall rule by its ID."""

    @abstractmethod
    def commit(self) -> None:
        """Commit pending changes to the device."""
