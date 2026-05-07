"""Capability interfaces for firewall drivers.

Each ABC in this module describes a single capability. Drivers implement
the capabilities they actually provide:

* :class:`FirewallReader` — read security policies (the minimum capability).
* :class:`NatReader` — read NAT rules.
* :class:`FirewallWriter` — push, remove, and commit rule changes.

Use ``isinstance(driver, NatReader)`` to ask "does this driver support
NAT?" rather than calling and catching :class:`NotImplementedError`.

All readers also act as context managers so that callers can reuse a
single device session across multiple operations::

    with get_firewall_driver("juniper_srx", host=...) as driver:
        rules = driver.get_rules()
        nats = driver.get_nat_rules()  # reuses the same SSH session
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # `Self` lives in `typing` from 3.11+; we still support 3.10, so use the
    # backport. typing_extensions is a transitive dep of pydantic, so it's
    # always available without an extra direct dependency.
    from typing_extensions import Self

from ufaya.models.firewall_rule import FirewallRule, FirewallRuleRecord
from ufaya.models.nat_rule import NatRuleRecord


class FirewallReader(ABC):
    """Read-only access to firewall security policies.

    Subclasses MUST implement :meth:`get_rules`. The default
    :meth:`open` and :meth:`close` are no-ops; drivers that hold a
    network connection should override them to manage that connection.
    """

    @abstractmethod
    def get_rules(self) -> list[FirewallRuleRecord]:
        """Return all firewall rules from the device."""

    def open(self) -> None:
        """Open any underlying connection. Default no-op for offline drivers."""

    def close(self) -> None:
        """Close any underlying connection. Default no-op for offline drivers."""

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class NatReader(ABC):
    """Read-only access to NAT rules. Optional capability."""

    @abstractmethod
    def get_nat_rules(self) -> list[NatRuleRecord]:
        """Return all NAT rules from the device."""


class FirewallWriter(ABC):
    """Push and commit firewall rule changes. Optional capability."""

    @abstractmethod
    def create_rule(self, rule: FirewallRule) -> None:
        """Push a new firewall rule to the device."""

    @abstractmethod
    def delete_rule(self, rule_id: str) -> None:
        """Remove a firewall rule by its ID."""

    @abstractmethod
    def commit(self) -> None:
        """Commit pending changes to the device."""
