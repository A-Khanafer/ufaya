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
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from ufaya.drivers.juniper.resolver import Resolver, normalize_action
from ufaya.drivers.juniper.xml_helpers import (
    JUNOS_NS,
    elem_to_dict,
    find,
    findall,
    sanitize_device_name,
    text,
)
from ufaya.firewall.base import FirewallDriver
from ufaya.models.firewall_rule import FirewallRule


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

        self._host: str | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._config_path: Path | None = None
        self._config_xml: str | None = None

        if live:
            if not username or not password:
                raise ValueError(
                    "Live mode requires host, username, and password."
                )
            self._mode = "live"
            self._host = host
            self._username = username
            self._password = password
        elif file_mode:
            self._mode = "file"
            self._config_path = Path(config_path)  # type: ignore[arg-type]
        else:
            self._mode = "raw"
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

        safe_name = sanitize_device_name(self._device_name)
        target = out / f"{safe_name}.firewall_rules.json"

        fd, tmp_path = tempfile.mkstemp(
            dir=str(out), prefix=f".{safe_name}_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, indent=2, ensure_ascii=False)
                fp.write("\n")
            os.replace(tmp_path, str(target))
        except BaseException:
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
        assert self._config_xml is not None
        return self._config_xml

    def _fetch_live(self) -> str:
        try:
            from netmiko import ConnectHandler  # type: ignore[import-untyped]
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
                f"Failed to read configuration file "
                f"'{self._config_path}': {exc}"
            ) from exc

    @staticmethod
    def _parse_xml(xml_str: str) -> ET.Element:
        """Parse XML string, unwrapping ``<rpc-reply>`` if present."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise ValueError(
                f"Malformed XML configuration: {exc}"
            ) from exc

        local_tag = root.tag
        if "}" in local_tag:
            local_tag = local_tag.split("}", 1)[1]
        if local_tag == "rpc-reply":
            cfg = find(root, "configuration")
            if cfg is None:
                raise ValueError(
                    "XML contains <rpc-reply> but no "
                    "<configuration> element."
                )
            return cfg

        return root

    def _extract_rules(self, root: ET.Element) -> list[FirewallRule]:
        """Walk security policies and return rules in evaluation order."""
        resolver = Resolver(root)

        security = Resolver.find_security(root)
        if security is None:
            return []

        policies_el = find(security, "policies")
        if policies_el is None:
            return []

        rules: list[FirewallRule] = []
        seq = 0

        for pair in findall(policies_el, "policy"):
            from_zone = text(find(pair, "from-zone-name")) or "unknown"
            to_zone = text(find(pair, "to-zone-name")) or "unknown"

            for policy in findall(pair, "policy"):
                seq += 1
                rule = self._policy_to_rule(
                    policy, resolver, seq, [from_zone], [to_zone]
                )
                rules.append(rule)

        global_el = find(policies_el, "global")
        if global_el is not None:
            for policy in findall(global_el, "policy"):
                seq += 1
                rule = self._policy_to_rule(
                    policy, resolver, seq, ["global"], ["global"]
                )
                rules.append(rule)

        return rules

    def _policy_to_rule(
        self,
        policy: ET.Element,
        resolver: Resolver,
        sequence: int,
        src_zones: list[str],
        dst_zones: list[str],
    ) -> FirewallRule:
        name = text(find(policy, "name")) or f"policy-{sequence}"
        description = text(find(policy, "description"))

        enabled = True
        inactive_attr = policy.attrib.get("inactive", "")
        junos_inactive = policy.attrib.get(
            f"{{{JUNOS_NS}}}inactive", ""
        )
        if inactive_attr.lower() == "inactive" or junos_inactive:
            enabled = False

        match = find(policy, "match")
        src_refs: list[str] = []
        dst_refs: list[str] = []
        svc_refs: list[str] = []

        if match is not None:
            for sa in findall(match, "source-address"):
                t = sa.text
                if t:
                    src_refs.append(t)
            for da in findall(match, "destination-address"):
                t = da.text
                if t:
                    dst_refs.append(t)
            for app in findall(match, "application"):
                t = app.text
                if t:
                    svc_refs.append(t)

        source = resolver.resolve_addresses(src_refs, src_zones)
        destination = resolver.resolve_addresses(dst_refs, dst_zones)
        service = resolver.resolve_applications(svc_refs)
        action = normalize_action(policy)

        log_events = False
        then = find(policy, "then")
        if then is not None:
            if find(then, "log") is not None:
                log_events = True

        raw = elem_to_dict(policy)

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
