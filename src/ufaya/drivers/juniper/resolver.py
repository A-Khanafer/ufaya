"""Junos address-book, application, and action resolution.

The :class:`Resolver` class parses ``<security>`` address-books (zone-scoped
and global) and ``<applications>`` blocks, then expands references found in
security-policy match clauses into concrete values (IP prefixes, protocol/port
strings, etc.).  Recursive address-set and application-set expansion is
cycle-safe.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ufaya.drivers.juniper.xml_helpers import find, findall, text

# ---------------------------------------------------------------------------
# Action normalisation
# ---------------------------------------------------------------------------

ACTION_MAP: dict[str, str] = {
    "permit": "allow",
    "deny": "deny",
    "reject": "reject",
}


def normalize_action(policy_el: ET.Element) -> str:
    """Return the normalised action string for a ``<policy>`` element."""
    then = find(policy_el, "then")
    if then is None:
        return "deny"
    for child in then:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        tag_lower = tag.lower()
        if tag_lower in ACTION_MAP:
            return ACTION_MAP[tag_lower]
    return "deny"


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class Resolver:
    """Resolves Junos address-book entries and application references."""

    def __init__(self, config_root: ET.Element) -> None:
        self._zone_addresses: dict[str, dict[str, list[str]]] = {}
        self._global_addresses: dict[str, list[str]] = {}
        self._applications: dict[str, list[str]] = {}
        self._zone_address_sets: dict[str, dict[str, list[str]]] = {}
        self._global_address_sets: dict[str, list[str]] = {}
        self._application_sets: dict[str, list[str]] = {}

        self._parse_address_books(config_root)
        self._parse_applications(config_root)

    # ---- address books --------------------------------------------------

    def _parse_address_books(self, root: ET.Element) -> None:
        security = self.find_security(root)
        if security is None:
            return

        zones_el = find(security, "zones")
        if zones_el is not None:
            for zone in findall(zones_el, "security-zone"):
                zone_name = text(find(zone, "name")) or ""
                ab = find(zone, "address-book")
                if ab is not None:
                    addrs, sets = self._parse_ab(ab)
                    self._zone_addresses[zone_name] = addrs
                    self._zone_address_sets[zone_name] = sets

        for ab in findall(security, "address-book"):
            ab_name = text(find(ab, "name"))
            if ab_name == "global" or ab_name is None:
                addrs, sets = self._parse_ab(ab)
                self._global_addresses.update(addrs)
                self._global_address_sets.update(sets)

    @staticmethod
    def _parse_ab(
        ab: ET.Element,
    ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        addrs: dict[str, list[str]] = {}
        sets: dict[str, list[str]] = {}

        for addr in findall(ab, "address"):
            name = text(find(addr, "name"))
            if name is None:
                continue
            prefix = text(find(addr, "ip-prefix"))
            dns = text(find(addr, "dns-name"))
            if prefix:
                addrs[name] = [prefix]
            elif dns:
                if isinstance(dns, ET.Element):
                    dns_name = text(find(dns, "name"))
                else:
                    dns_name = dns
                addrs[name] = [str(dns_name)]
            else:
                addrs[name] = [name]

        for aset in findall(ab, "address-set"):
            set_name = text(find(aset, "name"))
            if set_name is None:
                continue
            members: list[str] = []
            for a in findall(aset, "address"):
                n = text(find(a, "name"))
                if n:
                    members.append(n)
            for a in findall(aset, "address-set"):
                n = text(find(a, "name"))
                if n:
                    members.append(n)
            sets[set_name] = members
        return addrs, sets

    def resolve_addresses(
        self, names: list[str], zones: list[str]
    ) -> list[str]:
        """Resolve address names to concrete values.

        Falls back from zone books → global → keeps vendor name.
        """
        resolved: list[str] = []
        for name in names:
            if name == "any":
                resolved.append("any")
                continue
            expanded = self._expand_address(name, zones, set())
            resolved.extend(expanded)
        return resolved

    def _expand_address(
        self, name: str, zones: list[str], seen: set[str]
    ) -> list[str]:
        if name in seen:
            return [name]
        seen = seen | {name}

        for z in zones:
            if z in self._zone_addresses and name in self._zone_addresses[z]:
                return self._zone_addresses[z][name]
            if (
                z in self._zone_address_sets
                and name in self._zone_address_sets[z]
            ):
                out: list[str] = []
                for member in self._zone_address_sets[z][name]:
                    out.extend(self._expand_address(member, zones, seen))
                return out

        if name in self._global_addresses:
            return self._global_addresses[name]
        if name in self._global_address_sets:
            out = []
            for member in self._global_address_sets[name]:
                out.extend(self._expand_address(member, zones, seen))
            return out

        return [name]

    # ---- applications ---------------------------------------------------

    def _parse_applications(self, root: ET.Element) -> None:
        applications_el = find(root, "applications")
        if applications_el is None:
            cfg = find(root, "configuration")
            if cfg is not None:
                applications_el = find(cfg, "applications")
        if applications_el is None:
            return

        for app in findall(applications_el, "application"):
            name = text(find(app, "name"))
            if name is None:
                continue
            proto = text(find(app, "protocol"))
            dst_port = text(find(app, "destination-port"))
            if proto and dst_port:
                self._applications[name] = [f"{proto}/{dst_port}"]
            elif proto:
                self._applications[name] = [proto]
            else:
                self._applications[name] = [name]

        for app_set in findall(applications_el, "application-set"):
            set_name = text(find(app_set, "name"))
            if set_name is None:
                continue
            members: list[str] = []
            for a in findall(app_set, "application"):
                n = text(find(a, "name"))
                if n:
                    members.append(n)
            for a in findall(app_set, "application-set"):
                n = text(find(a, "name"))
                if n:
                    members.append(n)
            self._application_sets[set_name] = members

    def resolve_applications(self, names: list[str]) -> list[str]:
        """Resolve application names to protocol/port values."""
        resolved: list[str] = []
        for name in names:
            if name == "any":
                resolved.append("any")
                continue
            expanded = self._expand_application(name, set())
            resolved.extend(expanded)
        return resolved

    def _expand_application(self, name: str, seen: set[str]) -> list[str]:
        if name in seen:
            return [name]
        seen = seen | {name}

        if name in self._applications:
            return self._applications[name]
        if name in self._application_sets:
            out: list[str] = []
            for member in self._application_sets[name]:
                out.extend(self._expand_application(member, seen))
            return out
        return [name]

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def find_security(root: ET.Element) -> ET.Element | None:
        """Locate the ``<security>`` element in bare or wrapped XML."""
        sec = find(root, "security")
        if sec is not None:
            return sec
        cfg = find(root, "configuration")
        if cfg is not None:
            return find(cfg, "security")
        return None
