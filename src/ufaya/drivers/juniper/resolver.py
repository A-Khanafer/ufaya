"""Junos address-book, application, and action resolution.

The :class:`Resolver` class parses ``<security>`` address-books (zone-scoped
and global) and ``<applications>`` blocks, then expands references found in
security-policy match clauses into concrete values (IP prefixes, protocol/port
strings, etc.).  Recursive address-set and application-set expansion is
cycle-safe.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from ufaya.drivers.juniper.xml_helpers import find, findall, text
from ufaya.models.firewall_rule import ServiceDetail

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


@dataclass(frozen=True, slots=True)
class _ResolvedServiceTerm:
    label: str | None = None
    protocol: str | None = None
    source_ports: tuple[str, ...] = ()
    destination_ports: tuple[str, ...] = ()
    application_protocol: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp6_type: int | None = None
    icmp6_code: int | None = None
    rpc_program_number: str | None = None
    inactivity_timeout: str | None = None
    resolved: bool = False

    def has_semantics(self) -> bool:
        return any(
            (
                self.protocol is not None,
                bool(self.source_ports),
                bool(self.destination_ports),
                self.application_protocol is not None,
                self.icmp_type is not None,
                self.icmp_code is not None,
                self.icmp6_type is not None,
                self.icmp6_code is not None,
                self.rpc_program_number is not None,
                self.inactivity_timeout is not None,
            )
        )

    def fingerprint(self) -> tuple[object, ...]:
        base = (
            self.protocol,
            self.source_ports,
            self.destination_ports,
            self.application_protocol,
            self.icmp_type,
            self.icmp_code,
            self.icmp6_type,
            self.icmp6_code,
            self.rpc_program_number,
            self.inactivity_timeout,
            self.resolved,
        )
        if self.resolved:
            return base
        return base + (self.label,)


class Resolver:
    """Resolves Junos address-book entries and application references."""

    def __init__(self, config_root: ET.Element) -> None:
        self._zone_addresses: dict[str, dict[str, list[str]]] = {}
        self._global_addresses: dict[str, list[str]] = {}
        self._applications: dict[str, list[_ResolvedServiceTerm]] = {}
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
            name = self._clean_text(find(app, "name"))
            if name is None:
                continue
            app_defaults = self._build_service_term(
                app,
                label=name,
                resolved=True,
            )
            terms = findall(app, "term")
            if terms:
                resolved_terms: list[_ResolvedServiceTerm] = []
                for term in terms:
                    term_name = self._clean_text(find(term, "name"))
                    term_label = f"{name}:{term_name}" if term_name else name
                    resolved_terms.append(
                        self._build_service_term(
                            term,
                            label=term_label,
                            resolved=True,
                            defaults=app_defaults,
                        )
                    )
                self._applications[name] = resolved_terms
            else:
                self._applications[name] = [app_defaults]

        for app_set in findall(applications_el, "application-set"):
            set_name = self._clean_text(find(app_set, "name"))
            if set_name is None:
                continue
            members: list[str] = []
            for a in findall(app_set, "application"):
                n = self._clean_text(find(a, "name"))
                if n:
                    members.append(n)
            for a in findall(app_set, "application-set"):
                n = self._clean_text(find(a, "name"))
                if n:
                    members.append(n)
            self._application_sets[set_name] = members

    def resolve_applications(
        self, names: list[str]
    ) -> tuple[list[str], list[ServiceDetail]]:
        """Resolve application names to summary strings and structured details."""
        resolved: list[_ResolvedServiceTerm] = []
        for name in names:
            expanded = self._expand_application(name, set())
            resolved.extend(expanded)

        unique_terms: list[_ResolvedServiceTerm] = []
        seen_terms: set[tuple[object, ...]] = set()
        for term in resolved:
            fingerprint = term.fingerprint()
            if fingerprint in seen_terms:
                continue
            seen_terms.add(fingerprint)
            unique_terms.append(term)

        summaries: list[str] = []
        seen_summaries: set[str] = set()
        for term in unique_terms:
            summary = self._summarize_term(term)
            if summary in seen_summaries:
                continue
            seen_summaries.add(summary)
            summaries.append(summary)

        details = [self._to_service_detail(term) for term in unique_terms]
        return summaries, details

    def _expand_application(
        self, name: str, seen: set[str]
    ) -> list[_ResolvedServiceTerm]:
        if name == "any":
            return [_ResolvedServiceTerm(label="any", resolved=True)]
        if name in seen:
            return [_ResolvedServiceTerm(label=name, resolved=False)]
        seen = seen | {name}

        if name in self._applications:
            return self._applications[name]
        if name in self._application_sets:
            out: list[_ResolvedServiceTerm] = []
            for member in self._application_sets[name]:
                out.extend(self._expand_application(member, seen))
            return out
        return [_ResolvedServiceTerm(label=name, resolved=False)]

    @staticmethod
    def _clean_text(element: ET.Element | None) -> str | None:
        value = text(element)
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        return stripped

    @classmethod
    def _texts(cls, element: ET.Element, tag: str) -> tuple[str, ...]:
        values: list[str] = []
        for child in findall(element, tag):
            value = cls._clean_text(child)
            if value is None or value in values:
                continue
            values.append(value)
        return tuple(values)

    @staticmethod
    def _normalize_token(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not normalized:
            return None
        return normalized

    @staticmethod
    def _parse_int(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @classmethod
    def _build_service_term(
        cls,
        element: ET.Element,
        *,
        label: str,
        resolved: bool,
        defaults: _ResolvedServiceTerm | None = None,
    ) -> _ResolvedServiceTerm:
        protocol = cls._normalize_token(cls._clean_text(find(element, "protocol")))
        if protocol is None and defaults is not None:
            protocol = defaults.protocol

        source_ports = cls._texts(element, "source-port")
        if not source_ports and defaults is not None:
            source_ports = defaults.source_ports

        destination_ports = cls._texts(element, "destination-port")
        if not destination_ports and defaults is not None:
            destination_ports = defaults.destination_ports

        application_protocol = cls._normalize_token(
            cls._clean_text(find(element, "application-protocol"))
        )
        if application_protocol is None:
            application_protocol = cls._normalize_token(
                cls._clean_text(find(element, "alg"))
            )
        if application_protocol is None and defaults is not None:
            application_protocol = defaults.application_protocol

        icmp_type = cls._parse_int(cls._clean_text(find(element, "icmp-type")))
        if icmp_type is None and defaults is not None:
            icmp_type = defaults.icmp_type

        icmp_code = cls._parse_int(cls._clean_text(find(element, "icmp-code")))
        if icmp_code is None and defaults is not None:
            icmp_code = defaults.icmp_code

        icmp6_type = cls._parse_int(cls._clean_text(find(element, "icmp6-type")))
        if icmp6_type is None and defaults is not None:
            icmp6_type = defaults.icmp6_type

        icmp6_code = cls._parse_int(cls._clean_text(find(element, "icmp6-code")))
        if icmp6_code is None and defaults is not None:
            icmp6_code = defaults.icmp6_code

        rpc_program_number = cls._clean_text(find(element, "rpc-program-number"))
        if rpc_program_number is None and defaults is not None:
            rpc_program_number = defaults.rpc_program_number

        inactivity_timeout = cls._clean_text(find(element, "inactivity-timeout"))
        if inactivity_timeout is None and defaults is not None:
            inactivity_timeout = defaults.inactivity_timeout

        term = _ResolvedServiceTerm(
            label=label,
            protocol=protocol,
            source_ports=source_ports,
            destination_ports=destination_ports,
            application_protocol=application_protocol,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp6_type=icmp6_type,
            icmp6_code=icmp6_code,
            rpc_program_number=rpc_program_number,
            inactivity_timeout=inactivity_timeout,
            resolved=resolved,
        )
        if label == "any":
            return term
        if term.has_semantics():
            return term
        return _ResolvedServiceTerm(label=label, resolved=False)

    @staticmethod
    def _format_ports(ports: tuple[str, ...]) -> str:
        return ",".join(ports)

    @classmethod
    def _summarize_term(cls, term: _ResolvedServiceTerm) -> str:
        if term.label == "any":
            return "any"

        if term.protocol == "icmp":
            return "icmp"
        if term.protocol in {"icmp6", "icmpv6", "ipv6-icmp"}:
            return "icmp6"

        if term.protocol is not None and term.destination_ports:
            destination = cls._format_ports(term.destination_ports)
            if term.source_ports:
                source = cls._format_ports(term.source_ports)
                return f"{term.protocol}/{source}->{destination}"
            return f"{term.protocol}/{destination}"

        if term.protocol is not None and term.source_ports:
            source = cls._format_ports(term.source_ports)
            return f"{term.protocol}/{source}->any"

        if term.protocol is not None:
            return term.protocol

        if term.label is not None:
            return term.label

        return "unknown"

    @staticmethod
    def _to_service_detail(term: _ResolvedServiceTerm) -> ServiceDetail:
        return ServiceDetail(
            label=term.label,
            protocol=term.protocol,
            source_ports=list(term.source_ports) or None,
            destination_ports=list(term.destination_ports) or None,
            application_protocol=term.application_protocol,
            icmp_type=term.icmp_type,
            icmp_code=term.icmp_code,
            icmp6_type=term.icmp6_type,
            icmp6_code=term.icmp6_code,
            rpc_program_number=term.rpc_program_number,
            inactivity_timeout=term.inactivity_timeout,
            resolved=term.resolved,
        )

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
