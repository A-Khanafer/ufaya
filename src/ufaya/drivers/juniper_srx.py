"""Juniper SRX security-policy driver.

Supports three source modes:

* **live** — connects to a device via Netmiko and fetches the full
  configuration as XML.
* **offline file** — reads XML from a local file path.
* **offline raw** — accepts XML as a string.

The driver exposes :meth:`get_rules` (returning ``list[FirewallRule]`` in
device evaluation order) and :meth:`export_rules_json` (writing one
deterministic JSON file per device).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from ufaya.firewall.base import FirewallDriver
from ufaya.models.firewall_rule import FirewallRule

# ---------------------------------------------------------------------------
# Junos XML namespace
# ---------------------------------------------------------------------------
_JUNOS_NS = "http://xml.juniper.net/xnm/1.1/xnm"

# We accept elements with or without namespace.
_NS_MAP = {"junos": _JUNOS_NS}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEVICE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_device_name(name: str) -> str:
    """Return a filesystem-safe device name."""
    return _DEVICE_NAME_RE.sub("_", name)


def _findall(element: ET.Element, path: str) -> list[ET.Element]:
    """Find children by local tag name, ignoring namespaces."""
    results: list[ET.Element] = []
    for child in element:
        tag = child.tag
        # strip namespace
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        if tag == path:
            results.append(child)
    return results


def _find(element: ET.Element, path: str) -> ET.Element | None:
    """Find first child by local tag name, ignoring namespaces."""
    hits = _findall(element, path)
    return hits[0] if hits else None


def _find_recursive(element: ET.Element, tag: str) -> list[ET.Element]:
    """Recursively find all descendants matching *tag* (namespace-agnostic)."""
    results: list[ET.Element] = []
    for child in element.iter():
        local = child.tag
        if "}" in local:
            local = local.split("}", 1)[1]
        if local == tag:
            results.append(child)
    return results


def _text(element: ET.Element | None) -> str | None:
    if element is None:
        return None
    return element.text


def _elem_to_dict(elem: ET.Element) -> dict[str, Any]:
    """Simple recursive conversion of an XML element to a dict for *raw*."""
    result: dict[str, Any] = {}
    for child in elem:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        child_dict = _elem_to_dict(child)
        value: Any = child_dict if child_dict else (child.text or "")
        if tag in result:
            existing = result[tag]
            if isinstance(existing, list):
                existing.append(value)
            else:
                result[tag] = [existing, value]
        else:
            result[tag] = value
    return result


# ---------------------------------------------------------------------------
# Address / application resolution
# ---------------------------------------------------------------------------


class _Resolver:
    """Resolves Junos address-book entries and application references."""

    def __init__(self, config_root: ET.Element) -> None:
        # address-book entries: zone_name -> {entry_name -> list[value]}
        self._zone_addresses: dict[str, dict[str, list[str]]] = {}
        # global address-book: {entry_name -> list[value]}
        self._global_addresses: dict[str, list[str]] = {}
        # applications: {name -> list[str]}
        self._applications: dict[str, list[str]] = {}
        # address-set membership for cycle-safe expansion
        self._zone_address_sets: dict[str, dict[str, list[str]]] = {}
        self._global_address_sets: dict[str, list[str]] = {}
        # application-set membership
        self._application_sets: dict[str, list[str]] = {}

        self._parse_address_books(config_root)
        self._parse_applications(config_root)

    # ---- address books --------------------------------------------------

    def _parse_address_books(self, root: ET.Element) -> None:
        security = self._find_security(root)
        if security is None:
            return

        # Zone-scoped address books
        zones_el = _find(security, "zones")
        if zones_el is not None:
            for zone in _findall(zones_el, "security-zone"):
                zone_name = _text(_find(zone, "name")) or ""
                ab = _find(zone, "address-book")
                if ab is not None:
                    addrs, sets = self._parse_ab(ab)
                    self._zone_addresses[zone_name] = addrs
                    self._zone_address_sets[zone_name] = sets

        # Global address books (Junos 12.1+)
        for ab in _findall(security, "address-book"):
            ab_name = _text(_find(ab, "name"))
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

        for addr in _findall(ab, "address"):
            name = _text(_find(addr, "name"))
            if name is None:
                continue
            prefix = _text(_find(addr, "ip-prefix"))
            dns = _text(_find(addr, "dns-name"))
            if prefix:
                addrs[name] = [prefix]
            elif dns:
                if isinstance(dns, ET.Element):
                    dns_name = _text(_find(dns, "name"))
                else:
                    dns_name = dns
                addrs[name] = [str(dns_name)]
            else:
                # Wildcard or other – keep the name as-is
                addrs[name] = [name]

        for aset in _findall(ab, "address-set"):
            set_name = _text(_find(aset, "name"))
            if set_name is None:
                continue
            members: list[str] = []
            for a in _findall(aset, "address"):
                n = _text(_find(a, "name"))
                if n:
                    members.append(n)
            for a in _findall(aset, "address-set"):  # nested set refs
                n = _text(_find(a, "name"))
                if n:
                    members.append(n)
            sets[set_name] = members
        return addrs, sets

    def resolve_addresses(
        self, names: list[str], zones: list[str]
    ) -> list[str]:
        """Resolve a list of address names to their values.

        Falls back to zone address books, then global, then keeps the
        original vendor name.
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
            return [name]  # cycle – keep ref
        seen = seen | {name}

        # Check zone books first
        for z in zones:
            if z in self._zone_addresses and name in self._zone_addresses[z]:
                return self._zone_addresses[z][name]
            if z in self._zone_address_sets and name in self._zone_address_sets[z]:
                out: list[str] = []
                for member in self._zone_address_sets[z][name]:
                    out.extend(self._expand_address(member, zones, seen))
                return out

        # Global
        if name in self._global_addresses:
            return self._global_addresses[name]
        if name in self._global_address_sets:
            out = []
            for member in self._global_address_sets[name]:
                out.extend(self._expand_address(member, zones, seen))
            return out

        # Unresolved – keep vendor name
        return [name]

    # ---- applications ---------------------------------------------------

    def _parse_applications(self, root: ET.Element) -> None:
        applications_el = _find(root, "applications")
        if applications_el is None:
            # Try under configuration
            cfg = _find(root, "configuration")
            if cfg is not None:
                applications_el = _find(cfg, "applications")
        if applications_el is None:
            return

        for app in _findall(applications_el, "application"):
            name = _text(_find(app, "name"))
            if name is None:
                continue
            proto = _text(_find(app, "protocol"))
            dst_port = _text(_find(app, "destination-port"))
            if proto and dst_port:
                self._applications[name] = [f"{proto}/{dst_port}"]
            elif proto:
                self._applications[name] = [proto]
            else:
                self._applications[name] = [name]

        for app_set in _findall(applications_el, "application-set"):
            set_name = _text(_find(app_set, "name"))
            if set_name is None:
                continue
            members: list[str] = []
            for a in _findall(app_set, "application"):
                n = _text(_find(a, "name"))
                if n:
                    members.append(n)
            for a in _findall(app_set, "application-set"):
                n = _text(_find(a, "name"))
                if n:
                    members.append(n)
            self._application_sets[set_name] = members

    def resolve_applications(self, names: list[str]) -> list[str]:
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
        # Junos built-in or unresolved – keep as-is
        return [name]

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _find_security(root: ET.Element) -> ET.Element | None:
        sec = _find(root, "security")
        if sec is not None:
            return sec
        cfg = _find(root, "configuration")
        if cfg is not None:
            return _find(cfg, "security")
        return None


# ---------------------------------------------------------------------------
# Action normalisation
# ---------------------------------------------------------------------------

_ACTION_MAP: dict[str, str] = {
    "permit": "allow",
    "deny": "deny",
    "reject": "reject",
}


def _normalize_action(policy_el: ET.Element) -> str:
    then = _find(policy_el, "then")
    if then is None:
        return "deny"
    for child in then:
        tag = child.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]
        tag_lower = tag.lower()
        if tag_lower in _ACTION_MAP:
            return _ACTION_MAP[tag_lower]
    return "deny"


# ---------------------------------------------------------------------------
# JuniperSRXDriver
# ---------------------------------------------------------------------------


class JuniperSRXDriver(FirewallDriver):
    """Driver for Juniper SRX security-policy ingestion.

    Supports three source modes (exactly one must be provided):

    * **live** — ``host``, ``username``, ``password``
    * **offline file** — ``config_path``
    * **offline raw XML** — ``config_xml``

    All modes accept an optional ``device_name`` used in
    :class:`~ufaya.models.firewall_rule.FirewallRule` output and JSON
    filenames (defaults to the host or ``"juniper_srx"``).
    """

    def __init__(
        self,
        *,
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
        config_path: str | Path | None = None,
        config_xml: str | None = None,
        device_name: str | None = None,
    ) -> None:
        live = host is not None
        file_mode = config_path is not None
        raw_mode = config_xml is not None

        mode_count = sum([live, file_mode, raw_mode])
        if mode_count == 0:
            raise ValueError(
                "JuniperSRXDriver requires exactly one source: "
                "provide (host, username, password) for live mode, "
                "config_path for file mode, or config_xml for raw XML mode."
            )
        if mode_count > 1:
            raise ValueError(
                "JuniperSRXDriver received conflicting source arguments. "
                "Provide exactly one of: (host, username, password), "
                "config_path, or config_xml."
            )

        if live:
            if not username or not password:
                raise ValueError(
                    "Live mode requires host, username, and password."
                )
            self._mode = "live"
            self._host = host
            self._username = username
            self._password = password
            self._config_path: Path | None = None
            self._config_xml: str | None = None
        elif file_mode:
            self._mode = "file"
            self._host = None
            self._username = None
            self._password = None
            self._config_path = Path(config_path)  # type: ignore[arg-type]
            self._config_xml = None
        else:
            self._mode = "raw"
            self._host = None
            self._username = None
            self._password = None
            self._config_path = None
            self._config_xml = config_xml

        self._device_name = device_name or (host if host else "juniper_srx")

    # -- FirewallDriver ABC ------------------------------------------------

    def get_rules(self) -> list[FirewallRule]:
        """Return all security-policy rules in device evaluation order."""
        xml_str = self._load_xml()
        root = self._parse_xml(xml_str)
        return self._extract_rules(root)

    def create_rule(self, rule: FirewallRule) -> None:
        raise NotImplementedError(
            "JuniperSRXDriver is read-only in v1. "
            "create_rule() is not supported."
        )

    def delete_rule(self, rule_id: str) -> None:
        raise NotImplementedError(
            "JuniperSRXDriver is read-only in v1. "
            "delete_rule() is not supported."
        )

    def commit(self) -> None:
        raise NotImplementedError(
            "JuniperSRXDriver is read-only in v1. "
            "commit() is not supported."
        )

    # -- JSON export (Juniper-specific) ------------------------------------

    def export_rules_json(self, output_dir: str | Path) -> Path:
        """Export parsed rules to a deterministic JSON file.

        Parameters
        ----------
        output_dir:
            Directory in which to write the JSON file.  Created with
            ``parents=True, exist_ok=True`` if it does not exist.

        Returns
        -------
        Path
            The path to the written JSON file.

        Raises
        ------
        ValueError
            If *output_dir* exists but is not a directory.
        OSError
            On write failures.
        """
        out = Path(output_dir)
        if out.exists() and not out.is_dir():
            raise ValueError(
                f"export_rules_json: '{out}' exists and is not a directory."
            )
        out.mkdir(parents=True, exist_ok=True)

        rules = self.get_rules()
        payload = {
            "vendor": "juniper_srx",
            "device": self._device_name,
            "rule_count": len(rules),
            "order": "device_evaluation",
            "rules": [r.model_dump() for r in rules],
        }

        safe_name = _sanitize_device_name(self._device_name)
        target = out / f"{safe_name}.firewall_rules.json"

        # Atomic write: write to a temp file in the same directory, then
        # replace the target so callers never see a partial file.
        fd, tmp_path = tempfile.mkstemp(
            dir=str(out), prefix=f".{safe_name}_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, indent=2, ensure_ascii=False)
                fp.write("\n")
            os.replace(tmp_path, str(target))
        except BaseException:
            # Clean up the temp file on any failure
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        return target

    # -- Internal helpers --------------------------------------------------

    def _load_xml(self) -> str:
        """Retrieve the raw XML configuration string."""
        if self._mode == "live":
            return self._fetch_live()
        if self._mode == "file":
            return self._read_file()
        # raw
        assert self._config_xml is not None
        return self._config_xml

    def _fetch_live(self) -> str:
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            raise ImportError(
                "netmiko is required for live mode. "
                "Install it with: pip install netmiko"
            ) from exc

        try:
            device = {
                "device_type": "juniper_junos",
                "host": self._host,
                "username": self._username,
                "password": self._password,
            }
            with ConnectHandler(**device) as conn:
                output: str = conn.send_command(
                    "show configuration | display xml | no-more"
                )
            return output
        except Exception as exc:
            raise ConnectionError(
                f"Failed to fetch configuration from {self._host}: {exc}"
            ) from exc

    def _read_file(self) -> str:
        assert self._config_path is not None
        try:
            return self._config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OSError(
                f"Failed to read configuration file '{self._config_path}': {exc}"
            ) from exc

    @staticmethod
    def _parse_xml(xml_str: str) -> ET.Element:
        """Parse XML string into an ElementTree root.

        Handles optional Junos ``<rpc-reply>`` wrappers.
        """
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise ValueError(
                f"Malformed XML configuration: {exc}"
            ) from exc

        # Unwrap <rpc-reply> if present
        local_tag = root.tag
        if "}" in local_tag:
            local_tag = local_tag.split("}", 1)[1]
        if local_tag == "rpc-reply":
            cfg = _find(root, "configuration")
            if cfg is None:
                raise ValueError(
                    "XML contains <rpc-reply> but no <configuration> element."
                )
            return cfg

        return root

    def _extract_rules(self, root: ET.Element) -> list[FirewallRule]:
        """Walk security policies and return rules in evaluation order."""
        resolver = _Resolver(root)

        # Find the <security> element (handles both bare and wrapped XML)
        security = _Resolver._find_security(root)
        if security is None:
            return []

        policies_el = _find(security, "policies")
        if policies_el is None:
            return []

        rules: list[FirewallRule] = []
        seq = 0

        # Zone-to-zone policies
        for pair in _findall(policies_el, "policy"):
            from_zone_el = _find(pair, "from-zone-name")
            to_zone_el = _find(pair, "to-zone-name")
            from_zone = _text(from_zone_el) or "unknown"
            to_zone = _text(to_zone_el) or "unknown"

            for policy in _findall(pair, "policy"):
                seq += 1
                rule = self._policy_to_rule(
                    policy, resolver, seq, [from_zone], [to_zone]
                )
                rules.append(rule)

        # Global policies
        global_el = _find(policies_el, "global")
        if global_el is not None:
            for policy in _findall(global_el, "policy"):
                seq += 1
                rule = self._policy_to_rule(
                    policy, resolver, seq, ["global"], ["global"]
                )
                rules.append(rule)

        return rules

    def _policy_to_rule(
        self,
        policy: ET.Element,
        resolver: _Resolver,
        sequence: int,
        src_zones: list[str],
        dst_zones: list[str],
    ) -> FirewallRule:
        name = _text(_find(policy, "name")) or f"policy-{sequence}"
        description = _text(_find(policy, "description"))

        # Enabled / inactive check
        enabled = True
        inactive_attr = policy.attrib.get("inactive", "")
        junos_inactive = policy.attrib.get(
            f"{{{_JUNOS_NS}}}inactive", ""
        )
        if inactive_attr.lower() == "inactive" or junos_inactive:
            enabled = False

        # Match block
        match = _find(policy, "match")
        src_refs: list[str] = []
        dst_refs: list[str] = []
        svc_refs: list[str] = []

        if match is not None:
            for sa in _findall(match, "source-address"):
                t = sa.text
                if t:
                    src_refs.append(t)
            for da in _findall(match, "destination-address"):
                t = da.text
                if t:
                    dst_refs.append(t)
            for app in _findall(match, "application"):
                t = app.text
                if t:
                    svc_refs.append(t)

        # Resolve
        source = resolver.resolve_addresses(src_refs, src_zones)
        destination = resolver.resolve_addresses(dst_refs, dst_zones)
        service = resolver.resolve_applications(svc_refs)

        # Action
        action = _normalize_action(policy)

        # Logging
        log_events = False
        then = _find(policy, "then")
        if then is not None:
            if _find(then, "log") is not None:
                log_events = True

        raw = _elem_to_dict(policy)

        return FirewallRule(
            id=f"{'-'.join(src_zones)}/{'-'.join(dst_zones)}/{name}",
            vendor="juniper_srx",
            device=self._device_name,
            name=name,
            source=source,
            destination=destination,
            service=service,
            action=action,
            enabled=enabled,
            sequence=sequence,
            source_zones=src_zones,
            destination_zones=dst_zones,
            source_refs=src_refs,
            destination_refs=dst_refs,
            service_refs=svc_refs,
            description=description,
            log_events=log_events,
            raw=raw,
        )
