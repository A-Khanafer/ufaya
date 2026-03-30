"""Juniper SRX security-policy driver.

Supports two source modes:

* **live** — connects to a device via Netmiko and fetches the full
  configuration as XML.
* **offline file** — reads XML from a local file path.

The driver exposes :meth:`get_rules` (returning
``list[FirewallRuleRecord]`` ordered by policy-context priority and then
top-down rule order within each context) and :meth:`export_rules_json`
(writing one deterministic JSON file per device).
"""

from __future__ import annotations

import json
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

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
from ufaya.models.firewall_rule import (
    FirewallRule,
    FirewallRuleDebug,
    FirewallRuleRecord,
    FirewallRuleTrace,
    RuleContext,
    normalize_export_mode,
)

_CONTEXT_PRIORITY = {
    "intra_zone": 1,
    "inter_zone": 2,
    "global": 3,
}

_EVALUATION_MODEL = {
    "context_selection_order": [
        "intra_zone",
        "inter_zone",
        "global",
        "implicit_default_deny",
    ],
    "rule_order_within_context": "top_down_first_match",
    "default_action": "deny",
}


class JuniperSRXDriver(FirewallDriver):
    """Driver for Juniper SRX security-policy ingestion.

    Supports two source modes (exactly one must be provided):

    * **live** — ``host``, ``username``, ``password``
    * **offline file** — ``config_path``

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
        device_name: str | None = None,
    ) -> None:
        live = host is not None
        file_mode = config_path is not None

        mode_count = sum([live, file_mode])
        if mode_count == 0:
            raise ValueError(
                "JuniperSRXDriver requires exactly one source: "
                "provide (host, username, password) for live mode, "
                "or config_path for file mode."
            )
        if mode_count > 1:
            raise ValueError(
                "JuniperSRXDriver received conflicting source arguments. "
                "Provide exactly one of: (host, username, password) "
                "or config_path."
            )

        self._host: str | None = None
        self._username: str | None = None
        self._password: str | None = None
        self._config_path: Path | None = None

        if live:
            if not username or not password:
                raise ValueError(
                    "Live mode requires host, username, and password."
                )
            self._mode = "live"
            self._host = host
            self._username = username
            self._password = password
        else:
            self._mode = "file"
            self._config_path = Path(config_path)  # type: ignore[arg-type]

        self._device_name = device_name or (host if host else "juniper_srx")

    # -- FirewallDriver ABC ------------------------------------------------

    def get_rules(self) -> list[FirewallRuleRecord]:
        """Return all security-policy rules with evaluation context."""
        xml_str = self._load_xml()
        root = self._parse_xml(xml_str)
        rules = self._extract_rules(root)
        return sorted(
            rules,
            key=lambda record: (
                record.context.priority_rank,
                record.context.context_order,
                record.rule.sequence or 0,
            ),
        )

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

    def export_rules_json(
        self, output_dir: str | Path, mode: str = "enriched"
    ) -> Path:
        """Export parsed rules to a deterministic JSON file.

        Parameters
        ----------
        output_dir:
            Directory in which to write the JSON file.  Created with
            ``parents=True, exist_ok=True`` if it does not exist.
        mode:
            One of ``minimal``, ``enriched``, or ``debug``.

        Returns
        -------
        Path
            The path to the written JSON file.

        Raises
        ------
        ValueError
            If *output_dir* exists but is not a directory, or *mode* is
            unsupported.
        OSError
            On write failures.
        """
        export_mode = normalize_export_mode(mode)
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
            "schema_version": 2,
            "mode": export_mode,
            "rule_count": len(rules),
            "evaluation_model": _EVALUATION_MODEL,
            "contexts": self._serialize_contexts(rules, export_mode),
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
        return self._read_file()

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

    def _extract_rules(self, root: ET.Element) -> list[FirewallRuleRecord]:
        """Walk security policies and return context-aware rules."""
        resolver = Resolver(root)

        security = Resolver.find_security(root)
        if security is None:
            return []

        policies_el = find(security, "policies")
        if policies_el is None:
            return []

        rules: list[FirewallRuleRecord] = []
        context_counts = {
            "intra_zone": 0,
            "inter_zone": 0,
            "global": 0,
        }

        for pair in findall(policies_el, "policy"):
            from_zone = text(find(pair, "from-zone-name")) or "unknown"
            to_zone = text(find(pair, "to-zone-name")) or "unknown"
            scope = "intra_zone" if from_zone == to_zone else "inter_zone"
            context_counts[scope] += 1
            context = self._build_context(
                scope=scope,
                context_order=context_counts[scope],
                from_zone=from_zone,
                to_zone=to_zone,
            )

            for sequence, policy in enumerate(findall(pair, "policy"), start=1):
                rules.append(
                    self._policy_to_rule_record(
                        policy,
                        resolver,
                        sequence,
                        context,
                    )
                )

        global_el = find(policies_el, "global")
        if global_el is not None:
            context_counts["global"] += 1
            context = self._build_context(
                scope="global",
                context_order=context_counts["global"],
            )
            for sequence, policy in enumerate(findall(global_el, "policy"), start=1):
                rules.append(
                    self._policy_to_rule_record(
                        policy,
                        resolver,
                        sequence,
                        context,
                    )
                )

        return rules

    @staticmethod
    def _build_context(
        *,
        scope: str,
        context_order: int,
        from_zone: str | None = None,
        to_zone: str | None = None,
    ) -> RuleContext:
        if scope == "global":
            context_id = "global"
            section = "global"
        elif scope == "intra_zone":
            assert from_zone is not None
            context_id = f"intra_zone:{from_zone}"
            section = None
        else:
            assert from_zone is not None
            assert to_zone is not None
            context_id = f"inter_zone:{from_zone}->{to_zone}"
            section = None

        return RuleContext(
            context_id=context_id,
            scope=scope,
            priority_rank=_CONTEXT_PRIORITY[scope],
            context_order=context_order,
            rulebase="security_policies",
            section=section,
            from_zone=from_zone,
            to_zone=to_zone,
        )

    def _policy_to_rule_record(
        self,
        policy: ET.Element,
        resolver: Resolver,
        sequence: int,
        context: RuleContext,
    ) -> FirewallRuleRecord:
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

        if context.scope == "global":
            source_zones = ["global"]
            destination_zones = ["global"]
        else:
            assert context.from_zone is not None
            assert context.to_zone is not None
            source_zones = [context.from_zone]
            destination_zones = [context.to_zone]

        source = resolver.resolve_addresses(src_refs, source_zones)
        destination = resolver.resolve_addresses(dst_refs, destination_zones)
        service, service_details = resolver.resolve_applications(svc_refs)
        action = normalize_action(policy)

        log_actions: list[str] | None = None
        then = find(policy, "then")
        if then is not None:
            log = find(then, "log")
            if log is not None:
                log_actions = []
                for child in log:
                    tag = child.tag
                    if "}" in tag:
                        tag = tag.split("}", 1)[1]
                    action_name = tag.lower()
                    if action_name not in log_actions:
                        log_actions.append(action_name)
                if not log_actions:
                    log_actions = ["log"]

        raw = elem_to_dict(policy)

        return FirewallRuleRecord(
            rule=FirewallRule(
                vendor="juniper_srx",
                device=self._device_name,
                vendor_rule_id=name,
                name=name,
                source=source,
                destination=destination,
                service=service,
                action=action,
                enabled=enabled,
                sequence=sequence,
                description=description,
                log_actions=log_actions,
            ),
            context=context,
            trace=FirewallRuleTrace(
                source_refs=src_refs,
                destination_refs=dst_refs,
                service_refs=svc_refs,
                service_details=service_details,
            ),
            debug=FirewallRuleDebug(raw=raw),
        )

    @staticmethod
    def _serialize_contexts(
        rules: list[FirewallRuleRecord], mode: str
    ) -> list[dict[str, Any]]:
        contexts: list[dict[str, Any]] = []
        grouped: dict[str, dict[str, Any]] = {}

        for record in rules:
            context_id = record.context.context_id
            if context_id not in grouped:
                grouped[context_id] = {
                    "context": record.context.model_dump(exclude_none=True),
                    "rule_count": 0,
                    "rules": [],
                }
                contexts.append(grouped[context_id])

            entry = grouped[context_id]
            entry["rules"].append(
                record.export_rule(
                    mode,
                    include_vendor=False,
                    include_device=False,
                )
            )
            entry["rule_count"] += 1

        return contexts
