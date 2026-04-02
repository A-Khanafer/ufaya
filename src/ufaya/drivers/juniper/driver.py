"""Juniper SRX security-policy driver.

Supports two source modes:

* **live** — connects to a device via Netmiko and fetches the full
  configuration as XML.
* **offline file** — reads XML from a local file path.

The driver exposes :meth:`get_rules` (returning
``list[FirewallRuleRecord]`` ordered by policy-context priority and then
top-down rule order within each context) and :meth:`export_rules_json`
(writing one deterministic JSON file per device). It also exposes
``get_nat_rules()`` and ``export_nat_json()`` for XML-first NAT export.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from ufaya.drivers.juniper.resolver import Resolver, normalize_action
from ufaya.drivers.juniper.xml_helpers import (
    JUNOS_NS,
    elem_to_dict,
    find,
    find_recursive,
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
    ServiceDetail,
    normalize_export_mode,
)
from ufaya.models.nat_rule import (
    NatAction,
    NatMatch,
    NatRule,
    NatRuleContext,
    NatRuleDebug,
    NatRuleRecord,
    NatRuleTrace,
    NatTranslation,
    NatTranslationTarget,
    NatType,
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

_NAT_PRIORITY = {
    "static": 1,
    "destination": 2,
    "source": 3,
}

_NAT_EVALUATION_MODEL = {
    "nat_type_precedence": ["static", "destination", "source"],
    "rule_order_within_context": "top_down_first_match",
}

_NAT_SCHEMA_VERSION = 1

_CONFIG_COMMAND = "show configuration | display xml | no-more"
_HIT_COUNT_COMMAND = "show security policies hit-count | display xml | no-more"
_GLOBAL_ZONE_TOKENS = {"global", "junos-global"}
_HIT_COUNT_HEADER_TOKENS = (
    "from zone",
    "to zone",
    "policy count",
)
_HIT_COUNT_ROW_RE = re.compile(
    r"^\s*(?P<index>\d+)\s+"
    r"(?P<from_zone>\S+)\s+"
    r"(?P<to_zone>\S+)\s+"
    r"(?P<policy_name>.+?)\s+"
    r"(?P<count>[\d,]+)"
    r"(?:\s+\S.*)?$"
)

PolicyHitCountKey = tuple[str, str | None, str | None, str]


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
        self._last_hit_counts_collected_at: str | None = None

    # -- FirewallDriver ABC ------------------------------------------------

    def get_rules(self) -> list[FirewallRuleRecord]:
        """Return all security-policy rules with evaluation context."""
        self._last_hit_counts_collected_at = None
        xml_str, hit_count_lookup, collected_at = self._load_rule_data()
        self._last_hit_counts_collected_at = collected_at
        root = self._parse_xml(xml_str, unwrap_configuration=True)
        rules = self._extract_rules(root, hit_count_lookup)
        return sorted(
            rules,
            key=lambda record: (
                record.context.priority_rank,
                record.context.context_order,
                record.rule.sequence or 0,
            ),
        )

    def get_nat_rules(self) -> list[NatRuleRecord]:
        """Return all NAT rules with evaluation context."""
        xml_str = self._load_config_xml()
        root = self._parse_xml(xml_str, unwrap_configuration=True)
        rules, _ = self._extract_nat(root)
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
        payload: dict[str, Any] = {
            "vendor": "juniper_srx",
            "device": self._device_name,
        }
        if self._last_hit_counts_collected_at is not None:
            payload["hit_counts_collected_at"] = self._last_hit_counts_collected_at
        payload.update(
            {
                "schema_version": 3,
                "mode": export_mode,
                "rule_count": len(rules),
                "evaluation_model": _EVALUATION_MODEL,
                "contexts": self._serialize_contexts(rules, export_mode),
            }
        )

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

    def export_nat_json(
        self, output_dir: str | Path, mode: str = "enriched"
    ) -> Path:
        """Export parsed NAT rules to a deterministic JSON file."""
        export_mode = normalize_export_mode(mode)
        out = Path(output_dir)
        if out.exists() and not out.is_dir():
            raise ValueError(
                f"export_nat_json: '{out}' exists and is not a directory."
            )
        out.mkdir(parents=True, exist_ok=True)

        xml_str = self._load_config_xml()
        root = self._parse_xml(xml_str, unwrap_configuration=True)
        rules, pool_inventory = self._extract_nat(root)
        rules = sorted(
            rules,
            key=lambda record: (
                record.context.priority_rank,
                record.context.context_order,
                record.rule.sequence or 0,
            ),
        )

        payload: dict[str, Any] = {
            "vendor": "juniper_srx",
            "device": self._device_name,
            "schema_version": _NAT_SCHEMA_VERSION,
            "mode": export_mode,
            "nat_rule_count": len(rules),
            "evaluation_model": _NAT_EVALUATION_MODEL,
            "contexts": self._serialize_nat_contexts(rules, export_mode),
        }
        if export_mode in {"enriched", "debug"}:
            payload["supporting_objects"] = {
                "translation_pools": self._serialize_translation_pools(
                    pool_inventory, rules, export_mode
                )
            }

        safe_name = sanitize_device_name(self._device_name)
        target = out / f"{safe_name}.nat_rules.json"

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

    def _load_rule_data(
        self,
    ) -> tuple[str, dict[PolicyHitCountKey, int], str | None]:
        """Retrieve the raw configuration plus any live hit-count snapshot."""
        if self._mode == "live":
            return self._fetch_live_data()
        return self._read_file(), {}, None

    def _load_config_xml(self) -> str:
        """Retrieve the raw configuration XML without operational data."""
        if self._mode == "live":
            return self._fetch_config_xml()
        return self._read_file()

    def _fetch_config_xml(self) -> str:
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
                return cast(str, conn.send_command(_CONFIG_COMMAND))
        except Exception as exc:
            raise ConnectionError(
                f"Failed to fetch configuration from {self._host}: {exc}"
            ) from exc

    def _fetch_live_data(
        self,
    ) -> tuple[str, dict[PolicyHitCountKey, int], str | None]:
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
                try:
                    hit_count_output: str | None = conn.send_command(
                        _HIT_COUNT_COMMAND
                    )
                except Exception:
                    hit_count_output = None
                config_output: str = conn.send_command(_CONFIG_COMMAND)
        except Exception as exc:
            raise ConnectionError(
                f"Failed to fetch configuration from {self._host}: {exc}"
            ) from exc

        if not hit_count_output:
            return config_output, {}, None

        hit_count_lookup: dict[PolicyHitCountKey, int]
        parsed: bool
        try:
            hit_count_root = self._parse_xml(
                hit_count_output, unwrap_configuration=False
            )
            hit_count_lookup, parsed = self._parse_hit_count_lookup(
                hit_count_root
            )
        except ValueError:
            hit_count_lookup, parsed = self._parse_hit_count_text(
                hit_count_output
            )

        if not parsed:
            hit_count_lookup, parsed = self._parse_hit_count_text(
                hit_count_output
            )

        if not parsed:
            return config_output, {}, None

        return config_output, hit_count_lookup, self._utc_now()

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
    def _parse_xml(
        xml_str: str, *, unwrap_configuration: bool
    ) -> ET.Element:
        """Parse XML and optionally unwrap ``<configuration>`` from ``<rpc-reply>``."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            raise ValueError(
                f"Malformed XML configuration: {exc}"
            ) from exc

        if not unwrap_configuration:
            return root

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

    def _extract_rules(
        self,
        root: ET.Element,
        hit_count_lookup: dict[PolicyHitCountKey, int],
    ) -> list[FirewallRuleRecord]:
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
                        hit_count_lookup,
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
                        hit_count_lookup,
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
        hit_count_lookup: dict[PolicyHitCountKey, int],
    ) -> FirewallRuleRecord:
        name = text(find(policy, "name")) or f"policy-{sequence}"
        description = text(find(policy, "description"))
        hit_count = hit_count_lookup.get(
            self._policy_hit_count_key(context, name)
        )

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
                hit_count=hit_count,
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

    def _extract_nat(
        self, root: ET.Element
    ) -> tuple[list[NatRuleRecord], dict[tuple[str, str], dict[str, Any]]]:
        resolver = Resolver(root)

        security = Resolver.find_security(root)
        if security is None:
            return [], {}

        nat_el = find(security, "nat")
        if nat_el is None:
            return [], {}

        pool_inventory = self._parse_nat_pool_inventory(nat_el)
        rules: list[NatRuleRecord] = []
        context_counts = {
            "source": 0,
            "destination": 0,
            "static": 0,
        }

        for nat_type in ("source", "destination", "static"):
            family_el = find(nat_el, nat_type)
            if family_el is None:
                continue

            for rule_set in findall(family_el, "rule-set"):
                context_counts[nat_type] += 1
                context = self._build_nat_context(
                    nat_type=nat_type,
                    rule_set=rule_set,
                    context_order=context_counts[nat_type],
                )
                for sequence, rule in enumerate(findall(rule_set, "rule"), start=1):
                    rules.append(
                        self._nat_rule_to_record(
                            rule,
                            resolver,
                            sequence,
                            context,
                            pool_inventory,
                        )
                    )

        return rules, pool_inventory

    @classmethod
    def _parse_nat_pool_inventory(
        cls, nat_el: ET.Element
    ) -> dict[tuple[str, str], dict[str, Any]]:
        inventory: dict[tuple[str, str], dict[str, Any]] = {}

        for nat_type in ("source", "destination"):
            family_el = find(nat_el, nat_type)
            if family_el is None:
                continue

            for pool in findall(family_el, "pool"):
                name = cls._clean_text(find(pool, "name"))
                if name is None:
                    continue

                addresses = cls._collect_nat_pool_addresses(pool)
                ports = cls._collect_texts(pool, "port", "mapped-port")
                entry: dict[str, Any] = {
                    "name": name,
                    "nat_type": nat_type,
                    "addresses": addresses or None,
                    "ports": ports or None,
                    "description": cls._clean_text(find(pool, "description")),
                    "routing_instance": cls._first_text(
                        pool, "routing-instance", recursive=False
                    ),
                    "raw": elem_to_dict(pool),
                }
                inventory[(nat_type, name)] = entry

        return inventory

    @classmethod
    def _build_nat_context(
        cls,
        *,
        nat_type: NatType,
        rule_set: ET.Element,
        context_order: int,
    ) -> NatRuleContext:
        rule_set_name = cls._clean_text(find(rule_set, "name"))
        if rule_set_name is None:
            rule_set_name = f"{nat_type}-rule-set-{context_order}"

        from_scope = cls._parse_nat_direction(find(rule_set, "from"))
        to_scope = cls._parse_nat_direction(find(rule_set, "to"))

        return NatRuleContext(
            context_id=f"{nat_type}:{rule_set_name}",
            nat_type=nat_type,
            priority_rank=_NAT_PRIORITY[nat_type],
            context_order=context_order,
            rulebase="security_nat",
            rule_set=rule_set_name,
            from_zones=from_scope["zones"],
            to_zones=to_scope["zones"],
            from_interfaces=from_scope["interfaces"],
            to_interfaces=to_scope["interfaces"],
            from_routing_instances=from_scope["routing_instances"],
            to_routing_instances=to_scope["routing_instances"],
        )

    def _nat_rule_to_record(
        self,
        rule: ET.Element,
        resolver: Resolver,
        sequence: int,
        context: NatRuleContext,
        pool_inventory: dict[tuple[str, str], dict[str, Any]],
    ) -> NatRuleRecord:
        name = self._clean_text(find(rule, "name")) or f"rule-{sequence}"
        description = self._clean_text(find(rule, "description"))
        enabled = not self._is_inactive(rule)

        source_zones = context.from_zones or []
        destination_zones = context.to_zones or context.from_zones or []
        resolution_zones = self._dedupe([*source_zones, *destination_zones])

        match, source_refs, destination_refs = self._build_nat_match(
            find(rule, "match"),
            resolver,
            source_zones=resolution_zones,
            destination_zones=resolution_zones,
        )
        (
            action,
            translation,
            translation_source_ref,
            translation_destination_ref,
        ) = self._build_nat_translation(
            rule,
            resolver,
            context,
            pool_inventory,
            source_zones=source_zones,
            destination_zones=destination_zones,
        )

        return NatRuleRecord(
            rule=NatRule(
                vendor="juniper_srx",
                device=self._device_name,
                nat_type=context.nat_type,
                vendor_rule_id=name,
                name=name,
                match=match,
                translation=translation,
                action=action,
                enabled=enabled,
                sequence=sequence,
                description=description,
            ),
            context=context,
            trace=NatRuleTrace(
                source_refs=source_refs or None,
                destination_refs=destination_refs or None,
                translation_source_ref=translation_source_ref,
                translation_destination_ref=translation_destination_ref,
            ),
            debug=NatRuleDebug(raw=elem_to_dict(rule)),
        )

    @classmethod
    def _build_nat_match(
        cls,
        match: ET.Element | None,
        resolver: Resolver,
        *,
        source_zones: list[str],
        destination_zones: list[str],
    ) -> tuple[NatMatch, list[str], list[str]]:
        source_refs: list[str] = []
        destination_refs: list[str] = []
        explicit_protocols: list[str] = []
        applications: list[str] = []
        explicit_source_ports: list[str] = []
        explicit_destination_ports: list[str] = []

        if match is not None:
            source_refs = cls._collect_texts(
                match, "source-address", "source-address-name"
            )
            destination_refs = cls._collect_texts(
                match, "destination-address", "destination-address-name"
            )
            explicit_protocols = cls._collect_texts(match, "protocol")
            applications = cls._collect_texts(match, "application")
            explicit_source_ports = cls._collect_texts(match, "source-port")
            explicit_destination_ports = cls._collect_texts(
                match, "destination-port"
            )

        (
            application_protocols,
            application_source_ports,
            application_destination_ports,
        ) = cls._resolve_nat_application_match(
            resolver, applications
        )
        protocols = cls._dedupe(
            [*explicit_protocols, *application_protocols]
        )
        source_ports = cls._dedupe(
            [*explicit_source_ports, *application_source_ports]
        )
        destination_ports = cls._dedupe(
            [*explicit_destination_ports, *application_destination_ports]
        )

        return (
            NatMatch(
                source=(
                    resolver.resolve_addresses(source_refs, source_zones)
                    if source_refs
                    else ["any"]
                ),
                destination=(
                    resolver.resolve_addresses(destination_refs, destination_zones)
                    if destination_refs
                    else ["any"]
                ),
                source_ports=source_ports or None,
                destination_ports=destination_ports or None,
                protocols=protocols or None,
                applications=applications or None,
            ),
            source_refs,
            destination_refs,
        )

    @classmethod
    def _resolve_nat_application_match(
        cls,
        resolver: Resolver,
        application_refs: list[str],
    ) -> tuple[list[str], list[str], list[str]]:
        if not application_refs:
            return [], [], []

        _, service_details = resolver.resolve_applications(application_refs)
        protocols: list[str] = []
        source_ports: list[str] = []
        destination_ports: list[str] = []

        for detail in service_details:
            cls._merge_service_detail_into_nat_match(
                detail,
                protocols=protocols,
                source_ports=source_ports,
                destination_ports=destination_ports,
            )

        return (
            cls._dedupe(protocols),
            cls._dedupe(source_ports),
            cls._dedupe(destination_ports),
        )

    @staticmethod
    def _merge_service_detail_into_nat_match(
        detail: ServiceDetail,
        *,
        protocols: list[str],
        source_ports: list[str],
        destination_ports: list[str],
    ) -> None:
        if detail.protocol is not None:
            protocols.append(detail.protocol)
        if detail.source_ports:
            source_ports.extend(detail.source_ports)
        if detail.destination_ports:
            destination_ports.extend(detail.destination_ports)

    def _build_nat_translation(
        self,
        rule: ET.Element,
        resolver: Resolver,
        context: NatRuleContext,
        pool_inventory: dict[tuple[str, str], dict[str, Any]],
        *,
        source_zones: list[str],
        destination_zones: list[str],
    ) -> tuple[
        NatAction,
        NatTranslation | None,
        str | None,
        str | None,
    ]:
        then = find(rule, "then")
        if then is None:
            return "no_translate", None, None, None

        if context.nat_type == "source":
            source_nat = find(then, "source-nat")
            if source_nat is None:
                return "no_translate", None, None, None
            if find(source_nat, "off") is not None:
                return "no_translate", None, None, None

            pool_name = self._clean_text(find(source_nat, "pool"))
            if pool_name is not None:
                return (
                    "translate",
                    NatTranslation(
                        source=self._pool_target(
                            pool_inventory, "source", pool_name
                        )
                    ),
                    pool_name,
                    None,
                )

            if find(source_nat, "interface") is not None:
                return (
                    "translate",
                    NatTranslation(
                        source=NatTranslationTarget(
                            mode="interface_address"
                        )
                    ),
                    None,
                    None,
                )

            return "translate", None, None, None

        if context.nat_type == "destination":
            destination_nat = find(then, "destination-nat")
            if destination_nat is None:
                return "no_translate", None, None, None
            if find(destination_nat, "off") is not None:
                return "no_translate", None, None, None

            pool_name = self._clean_text(find(destination_nat, "pool"))
            if pool_name is not None:
                return (
                    "translate",
                    NatTranslation(
                        destination=self._pool_target(
                            pool_inventory, "destination", pool_name
                        )
                    ),
                    None,
                    pool_name,
                )

            return "translate", None, None, None

        static_nat = find(then, "static-nat")
        if static_nat is None:
            return "no_translate", None, None, None

        prefix_name = self._clean_text(find(static_nat, "prefix-name"))
        prefix_value = self._clean_text(find(static_nat, "prefix"))
        translation_ref: str | None = None
        translated_addresses: list[str] | None = None
        translation_zones = self._dedupe(
            [*source_zones, *destination_zones]
        )

        if prefix_name is not None:
            translation_ref = prefix_name
            translated_addresses = resolver.resolve_addresses(
                [prefix_name], translation_zones
            )
        elif prefix_value is not None:
            translated_addresses = [prefix_value]

        mapped_ports = self._collect_texts(static_nat, "mapped-port")
        return (
            "translate",
            NatTranslation(
                destination=NatTranslationTarget(
                    mode="fixed",
                    addresses=translated_addresses or None,
                    ports=mapped_ports or None,
                ),
                bidirectional=True,
            ),
            None,
            translation_ref,
        )

    @staticmethod
    def _pool_target(
        pool_inventory: dict[tuple[str, str], dict[str, Any]],
        nat_type: str,
        pool_name: str,
    ) -> NatTranslationTarget:
        pool = pool_inventory.get((nat_type, pool_name), {})
        return NatTranslationTarget(
            mode="pool",
            addresses=pool.get("addresses"),
            ports=pool.get("ports"),
        )

    @staticmethod
    def _serialize_nat_contexts(
        rules: list[NatRuleRecord], mode: str
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

    @classmethod
    def _serialize_translation_pools(
        cls,
        pool_inventory: dict[tuple[str, str], dict[str, Any]],
        rules: list[NatRuleRecord],
        mode: str,
    ) -> list[dict[str, Any]]:
        ordered_keys: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        for record in rules:
            trace = record.trace
            if trace is None:
                continue

            for key in (
                ("source", trace.translation_source_ref),
                ("destination", trace.translation_destination_ref),
            ):
                nat_type, pool_name = key
                if pool_name is None:
                    continue
                inventory_key = (nat_type, pool_name)
                if inventory_key not in pool_inventory:
                    continue
                if inventory_key in seen:
                    continue
                seen.add(inventory_key)
                ordered_keys.append(inventory_key)

        payloads: list[dict[str, Any]] = []
        for key in ordered_keys:
            pool = pool_inventory[key]
            payload = {
                "name": pool["name"],
                "nat_type": pool["nat_type"],
                "addresses": pool.get("addresses"),
                "ports": pool.get("ports"),
                "description": pool.get("description"),
                "routing_instance": pool.get("routing_instance"),
            }
            cleaned = {
                field: value
                for field, value in payload.items()
                if value is not None
            }
            if mode == "debug":
                cleaned["raw"] = pool["raw"]
            payloads.append(cleaned)

        return payloads

    @classmethod
    def _parse_nat_direction(
        cls, element: ET.Element | None
    ) -> dict[str, list[str] | None]:
        if element is None:
            return {
                "zones": None,
                "interfaces": None,
                "routing_instances": None,
            }

        zones = cls._collect_texts(element, "zone", "zone-name")
        interfaces = cls._collect_texts(element, "interface")
        routing_instances = cls._collect_texts(
            element, "routing-instance", "routing-instance-name"
        )
        return {
            "zones": zones or None,
            "interfaces": interfaces or None,
            "routing_instances": routing_instances or None,
        }

    @classmethod
    def _collect_nat_pool_addresses(cls, pool: ET.Element) -> list[str]:
        addresses = cls._collect_texts(pool, "address")

        host_address_base = cls._first_text(
            pool, "host-address-base", recursive=False
        )
        host_address_limit = cls._first_text(
            pool,
            "host-address-limit",
            "address-to",
            recursive=False,
        )
        if host_address_base:
            if host_address_limit:
                addresses.append(
                    cls._format_nat_pool_range(
                        host_address_base, host_address_limit
                    )
                )
            else:
                addresses.append(host_address_base)

        for range_element in (
            *findall(pool, "address"),
            *findall(pool, "address-range"),
            *findall(pool, "host-address-range"),
        ):
            range_value = cls._extract_nat_pool_range(range_element)
            if range_value is None:
                continue
            addresses.append(range_value)

        return cls._dedupe(addresses)

    @classmethod
    def _extract_nat_pool_range(
        cls, element: ET.Element
    ) -> str | None:
        lower = cls._first_text(
            element,
            "low",
            "range-low",
            "start-address",
            "low-address",
            "host-address-base",
            recursive=False,
        )
        upper = cls._first_text(
            element,
            "high",
            "range-high",
            "end-address",
            "high-address",
            "host-address-limit",
            "address-to",
            recursive=False,
        )
        if lower is None or upper is None:
            return None
        return cls._format_nat_pool_range(lower, upper)

    @staticmethod
    def _format_nat_pool_range(lower: str, upper: str) -> str:
        return f"{lower}-{upper}"

    @classmethod
    def _collect_texts(cls, element: ET.Element, *tags: str) -> list[str]:
        values: list[str] = []
        for tag in tags:
            for child in findall(element, tag):
                value = cls._clean_text(child)
                if value is None or value in values:
                    continue
                values.append(value)
        return values

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
    def _dedupe(cls, values: list[str]) -> list[str]:
        deduped: list[str] = []
        for value in values:
            cleaned = value.strip()
            if not cleaned or cleaned in deduped:
                continue
            deduped.append(cleaned)
        return deduped

    @staticmethod
    def _is_inactive(element: ET.Element) -> bool:
        inactive_attr = element.attrib.get("inactive", "")
        junos_inactive = element.attrib.get(f"{{{JUNOS_NS}}}inactive", "")
        return inactive_attr.lower() == "inactive" or bool(junos_inactive)

    @staticmethod
    def _utc_now() -> str:
        return (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _policy_hit_count_key(
        context: RuleContext, policy_name: str
    ) -> PolicyHitCountKey:
        if context.scope == "global":
            return ("global", None, None, policy_name)
        return (
            context.scope,
            context.from_zone,
            context.to_zone,
            policy_name,
        )

    @classmethod
    def _parse_hit_count_lookup(
        cls, root: ET.Element
    ) -> tuple[dict[PolicyHitCountKey, int], bool]:
        lookup: dict[PolicyHitCountKey, int] = {}
        candidates = [
            *find_recursive(root, "policy-information"),
            *find_recursive(root, "policy-hit-count-information"),
            *find_recursive(root, "policy-hit-count-entry"),
        ]
        parsed = bool(
            candidates
            or find_recursive(root, "policy-count")
            or find_recursive(root, "number-of-policy")
            or find_recursive(root, "policy-hit-count-count")
        )

        for candidate in candidates:
            entry = cls._extract_hit_count_entry(candidate)
            if entry is None:
                continue
            key, count = entry
            lookup[key] = count

        return lookup, parsed

    @classmethod
    def _parse_hit_count_text(
        cls, raw_output: str
    ) -> tuple[dict[PolicyHitCountKey, int], bool]:
        lookup: dict[PolicyHitCountKey, int] = {}
        parsed = False
        in_table = False
        text_output = cls._extract_cli_output_text(raw_output)

        for line in text_output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            normalized = " ".join(stripped.lower().split())
            if cls._is_hit_count_table_header(normalized):
                parsed = True
                in_table = True
                continue
            if normalized.startswith("number of policy:"):
                parsed = True
                in_table = False
                continue
            if normalized.startswith("logical system:"):
                parsed = True
                continue
            if normalized.startswith("tenant:"):
                parsed = True
                continue
            if normalized.startswith("node") and stripped.endswith(":"):
                continue
            if set(stripped) == {"-"}:
                continue
            if not in_table:
                continue

            entry = cls._parse_hit_count_table_row(stripped)
            if entry is None:
                continue

            key, count = entry
            lookup[key] = count

        return lookup, parsed

    @staticmethod
    def _extract_cli_output_text(raw_output: str) -> str:
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError:
            return raw_output

        outputs: list[str] = []
        for element in root.iter():
            tag = element.tag
            if "}" in tag:
                tag = tag.split("}", 1)[1]
            if tag != "output":
                continue

            block = "".join(element.itertext()).strip()
            if block:
                outputs.append(block)

        if outputs:
            return "\n".join(outputs)
        return raw_output

    @staticmethod
    def _is_hit_count_table_header(line: str) -> bool:
        return all(token in line for token in _HIT_COUNT_HEADER_TOKENS)

    @classmethod
    def _parse_hit_count_table_row(
        cls, line: str
    ) -> tuple[PolicyHitCountKey, int] | None:
        match = _HIT_COUNT_ROW_RE.match(line)
        if match is None:
            return None

        policy_name = match.group("policy_name").strip()
        count_text = match.group("count")
        from_zone = match.group("from_zone")
        to_zone = match.group("to_zone")

        try:
            count = int(count_text.replace(",", ""))
        except ValueError:
            return None

        if cls._is_global_policy(from_zone, to_zone):
            key: PolicyHitCountKey = ("global", None, None, policy_name)
        else:
            scope = "intra_zone" if from_zone == to_zone else "inter_zone"
            key = (scope, from_zone, to_zone, policy_name)

        return key, count

    @classmethod
    def _extract_hit_count_entry(
        cls, element: ET.Element
    ) -> tuple[PolicyHitCountKey, int] | None:
        policy_name = cls._first_text(
            element,
            "policy-name",
            "name",
            "policy-hit-count-policy-name",
            recursive=True,
        )
        count_text = cls._first_text(
            element,
            "policy-count",
            "hit-count",
            "count",
            "policy-hit-count-count",
            recursive=True,
        )
        if policy_name is None or count_text is None:
            return None

        try:
            count = int(count_text.replace(",", "").strip())
        except ValueError:
            return None

        from_zone = cls._first_text(
            element,
            "from-zone-name",
            "from-zone",
            "policy-hit-count-from-zone",
            recursive=True,
        )
        to_zone = cls._first_text(
            element,
            "to-zone-name",
            "to-zone",
            "policy-hit-count-to-zone",
            recursive=True,
        )
        if cls._is_global_policy(from_zone, to_zone):
            key: PolicyHitCountKey = ("global", None, None, policy_name)
        elif from_zone is None or to_zone is None:
            return None
        else:
            scope = "intra_zone" if from_zone == to_zone else "inter_zone"
            key = (scope, from_zone, to_zone, policy_name)

        return key, count

    @staticmethod
    def _is_global_policy(
        from_zone: str | None, to_zone: str | None
    ) -> bool:
        if from_zone is None and to_zone is None:
            return True
        if from_zone is None or to_zone is None:
            return False
        return (
            from_zone.strip().lower() in _GLOBAL_ZONE_TOKENS
            and to_zone.strip().lower() in _GLOBAL_ZONE_TOKENS
        )

    @staticmethod
    def _first_text(
        element: ET.Element, *tags: str, recursive: bool = False
    ) -> str | None:
        for tag in tags:
            value = text(find(element, tag))
            if value:
                return value

        if not recursive:
            return None

        for tag in tags:
            for match in find_recursive(element, tag):
                value = text(match)
                if value:
                    return value

        return None
