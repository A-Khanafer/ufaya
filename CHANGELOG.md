# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This is a breaking refactor of the public driver interface. The library is still pre-1.0, so back-compat aliases were not added; downstream code that used `FirewallDriver`, the skeleton drivers, or the removed `RuleContext.{package,vsys,vdom}` fields must be updated.

### Changed

- **Driver interface split.** The single `FirewallDriver` ABC has been replaced with three composable capability ABCs: `FirewallReader` (mandatory — security-policy reads, plus the connection-lifecycle protocol), `NatReader` (optional — NAT reads), and `FirewallWriter` (optional — `create_rule`/`delete_rule`/`commit`). Drivers implement only the capabilities they actually provide. Use `isinstance(driver, NatReader)` to ask "does this driver support NAT?" rather than calling and catching `NotImplementedError`.
- **Connection lifecycle.** `JuniperSRXDriver` now supports the context-manager protocol via `open()`/`close()`/`__enter__`/`__exit__` (inherited from `FirewallReader`). Wrapping calls in `with driver:` reuses one SSH session across `get_rules()`, `get_nat_rules()`, and any future operations. Bare calls outside a `with` block continue to work — they auto-open and auto-close a single-call session.
- **Pluggable factory.** `get_firewall_driver()` now lazy-imports drivers via `"module.path:ClassName"` specs instead of eagerly importing every vendor. Out-of-tree drivers can register themselves at runtime with `ufaya.register_driver()`, or via the `ufaya.drivers` entry-point group in their `pyproject.toml`. Built-in drivers are no longer re-exported from `ufaya.drivers`.
- **`NatRuleContext.rule_set`** is now optional (`str | None`). The "rule-set" concept is Junos-specific; vendors without an analog can leave it `None`.
- **Export I/O extracted.** `JuniperSRXDriver.export_rules_json()` and `export_nat_json()` now delegate atomic JSON writes and payload assembly to a new `ufaya.export` module so future drivers reuse the same shape. Public method signatures and on-disk JSON shape are unchanged — the `RuleContext` field removals do not affect output, since those fields were always `None` and already omitted via `exclude_none=True`.

### Added

- `ufaya.FirewallReader`, `ufaya.NatReader`, `ufaya.FirewallWriter` capability ABCs.
- `ufaya.register_driver(vendor, driver)`, `ufaya.unregister_driver(vendor)`, and `ufaya.available_vendors()` for runtime driver registration and discovery.
- Entry-point discovery: third-party packages can ship a driver and register it via `[project.entry-points."ufaya.drivers"]` without monkey-patching.
- `RuleContext.vendor_context: dict[str, Any]` and `NatRuleContext.vendor_context: dict[str, Any]` escape hatches for vendor-specific scoping data that does not belong on the shared model.
- `RuleContext.dump_for_export()` and `NatRuleContext.dump_for_export()` helpers that omit `None` fields and the empty `vendor_context` default before serialization.
- `ufaya.export` module: `write_json_atomic`, `build_rules_payload`, `build_nat_payload`, `normalize_export_mode`. Drivers reuse these instead of reimplementing the tempfile + `os.replace` dance per vendor.
- Public JSON Schemas: `schemas/firewall_rules.v3.schema.json` and `schemas/nat_rules.v2.schema.json`. Strict (`additionalProperties: false`) Draft 2020-12 contracts intended for downstream consumers.
- Schema validation tests (`tests/test_export_schema.py`): every fixture × export mode is validated against the published schema.
- Snapshot regression tests (`tests/test_export_snapshots.py`): every fixture × export mode is diffed against committed `tests/snapshots/{rules,nat}/{fixture}.{mode}.json` golden files. Run `UPDATE_SNAPSHOTS=1 pytest tests/test_export_snapshots.py` to regenerate after intentional output changes.
- Lifecycle tests verifying that `with driver:` reuses one Netmiko session across multiple calls, and that bare calls auto-open/close a single-call session.
- Top-level `Makefile` with `check`, `lint`, `type`, `test`, `snapshots`, `schema`, `update-snapshots`, `build`, `smoke`, and `clean` targets.
- `jsonschema>=4.0` added to the `dev` extra.

### Removed

- `ufaya.FirewallDriver` ABC. Drivers must inherit from one or more of the new capability ABCs instead.
- `RuleContext.package`, `RuleContext.vsys`, `RuleContext.vdom`. These were Cisco FMC, Palo Alto, and Fortinet concepts pre-baked into the shared model and were always `None` in practice. Use `vendor_context` for vendor-specific scoping data.
- Skeleton drivers `PaloAltoDriver`, `CiscoDriver`, `FortinetDriver` and the `tests/test_drivers.py` module. They returned empty rule lists and accepted writes as silent no-ops, which was indistinguishable from a real device with no rules. Vendor support for these platforms is now listed as "Planned" in the README.
- `JuniperSRXDriver.create_rule()`, `delete_rule()`, and `commit()`. The driver no longer implements `FirewallWriter`, so these methods do not exist (rather than raising `NotImplementedError`).
- The `ufaya.firewall.get_rules(vendor, **kwargs)` convenience wrapper. It bypassed the new context-manager idiom and added little value; use `ufaya.get_firewall_driver(vendor, **kwargs)` directly.
- Eager driver imports from `src/ufaya/drivers/__init__.py`. Import drivers directly from their package (e.g. `from ufaya.drivers.juniper import JuniperSRXDriver`) or look them up via the factory.

## [0.6.3]

### Fixed

- Source NAT `conditions.source` and destination NAT `conditions.destination` no longer default to `["any"]` when parsing real Junos `show configuration | display xml` output. Real device XML uses type-specific match tags (`<src-nat-rule-match>`, `<dest-nat-rule-match>`) rather than the generic `<match>` tag; the parser now tries the type-specific tag first and falls back to `<match>` for backward compatibility.

### Added

- `_NAT_MATCH_TAGS` lookup mapping each NAT type to its real Junos match element tag name (`src-nat-rule-match`, `dest-nat-rule-match`, `static-nat-rule-match`).
- Test fixture `juniper_nat_real_tags.xml` covering real Junos XML tag names with `<name>`-wrapped address values.
- Seven new tests in `TestNatRealXmlTags` verifying source, destination, and static NAT condition parsing against real XML tag formats.

## [0.6.2]

### Changed

- NAT export schema redesigned to v2 with explicit `conditions` (traffic match) and `mapping` (before/after rewrite) blocks, replacing the previous `match` and `translation` fields.
- Each NAT mapping step now includes `summary`, `original`/`translated` sides with `field`, `addresses`, `ports`, and `ref`, plus `mapping_kind`, `determinism`, and `resolution_status` for self-describing LLM-consumable output.
- Static NAT rules now export both `forward` and `reverse` mapping directions instead of a single `bidirectional` flag on the translation.
- Traceability refs (`source_refs`, `destination_refs`) moved from `NatRuleTrace` into `conditions`; translation refs moved into `mapping.*.translated.ref`.
- `NatRuleTrace` removed; all provenance data is now inline in the canonical payload.

### Added

- `NatMapping`, `NatRewrite`, and `NatMappingSide` models for explicit before/after NAT rewrite semantics.
- `determinism` field on each mapping step: `exact` (1:1), `set_based` (pool/range), or `dynamic` (interface NAT).
- `resolution_status` field: `resolved` or `unresolved`, ensuring static NAT with unresolvable prefix-names still export with the raw ref instead of silently dropping the target.
- Juniper NAT fixture and test coverage for source pool mapping, interface NAT, destination port rewrite, static NAT forward/reverse, unresolved prefix-names, unconstrained conditions, no-translate rules, summary text, and schema v2 assertions.

### Fixed

- Static NAT no longer serializes as `match: {}` with a bare `fixed` mode and no target address.
- Unresolved static NAT prefix-names now export with `resolution_status: "unresolved"` and the raw ref, instead of silently dropping the target.
- Juniper NAT match parsing now handles nested XML element variants (`static-nat-rule-match`, `destination-address-name/dst-addr-name`, `prefix-name/addr-prefix-name`) produced by real Junos `show configuration | display xml` output.
- Static NAT prefix-name values that are literal CIDRs (e.g. `10.28.8.2/32`) are now used directly as translated addresses instead of being sent through the address-book resolver.

### Removed

- NAT schema v1 compatibility. Consumers must update to schema v2.
- `NatMatch`, `NatTranslation`, `NatTranslationTarget`, and `NatRuleTrace` models.

## [0.6.1]

### Changed

- Juniper SRX NAT exports now render unconstrained source and destination address selectors explicitly as `["any"]` in canonical `match` payloads instead of leaving them empty.
- Juniper SRX NAT `application` references now resolve into canonical `protocols`, `source_ports`, and `destination_ports` while preserving raw `applications` names.
- Referenced Juniper NAT translation pools now export normalized address/port values from the same pool inventory used by rule-level translation targets, including supported address-range forms.

### Added

- Juniper NAT fixture and test coverage for unconstrained matches, application-derived service semantics, mixed explicit-plus-application matches, and translation-pool address ranges.

## [0.6.0]

### Added

- Canonical NAT models for vendor-agnostic `match`, `translation`, context, trace, debug, and record export.
- `JuniperSRXDriver.get_nat_rules()` for parsed Junos NAT rule extraction from configuration XML.
- `JuniperSRXDriver.export_nat_json()` for deterministic, context-grouped NAT JSON export with `minimal`, `enriched`, and `debug` modes.
- Juniper NAT fixture and test coverage for source, destination, and static NAT parsing and export.

### Changed

- Juniper SRX documentation now describes both firewall-rule export and XML-first NAT export.
- Juniper SRX NAT export uses full configuration XML in both live mode and file mode, parsing `<security><nat>` rather than CLI `set` lines.
- Enriched and debug NAT exports now include referenced translation pools under `supporting_objects.translation_pools`.

## [0.5.1]

### Fixed

- Juniper SRX live hit-count parsing now recognizes newer operational XML variants such as `multi-routing-engine-results` and `policy-hit-count-entry`, in addition to the older `policy-information` shape.
- Juniper SRX live exports now preserve valid zero hit counts like `0` instead of falling back to `null` when the operational XML was successfully parsed.
- Juniper SRX hit-count collection documentation now points to a dedicated maintenance note for future Junos XML schema changes.

## [0.5.0]

### Added

- Canonical `FirewallRule.hit_count` support so drivers can expose per-policy counters in the shared rule model.

### Changed

- Juniper SRX live mode now performs an additional operational fetch to attach policy hit counts to parsed rules and exported JSON when the device provides them.
- Juniper SRX JSON export schema advanced to version `3`, with per-rule `hit_count` fields and an optional top-level `hit_counts_collected_at` UTC timestamp for live hit-count snapshots.
- File-backed Juniper exports now emit `hit_count: null` for each rule when counters are unavailable, preserving a stable JSON shape across export modes.

## [0.4.0]

### Added

- Shared `RuleContext`, `FirewallRuleTrace`, `FirewallRuleDebug`, and `FirewallRuleRecord` models for canonical rule data plus optional trace/debug sections.
- Juniper fixture coverage for priority-ordered intra-zone, inter-zone, and global policy export.

### Changed

- `FirewallDriver.get_rules()` and `ufaya.firewall.get_rules()` now return `list[FirewallRuleRecord]` instead of bare `FirewallRule` objects.
- Juniper SRX JSON export now groups rules by evaluation context, adds `minimal`, `enriched`, and `debug` export modes, and emits explicit evaluation metadata.
- Juniper SRX rule sequencing now reflects top-down order within each policy context, and rules now carry `vendor_rule_id` instead of a synthetic flat export `id`.
- Canonical `FirewallRule` output is now leaner, with zones moved into context metadata and refs/debug payloads moved into explicit trace/debug wrappers.

## [0.3.0]

### Added

- Generic `ServiceDetail` model plus `FirewallRule.service_details` for structured service semantics across vendors.
- `FirewallRule.log_actions` to preserve exact logging actions such as `session-init` and `session-close`.
- Juniper fixtures and test coverage for term-based applications, richer service fields, and detailed logging extraction.

### Changed

- Juniper SRX application resolution now expands term-based applications into structured service details while keeping `service` as a deduplicated summary field.
- Juniper SRX logging extraction now preserves exact log actions instead of reducing logging to a single boolean.
- Project docs now describe the Juniper driver as supporting live mode or file-backed XML via `config_path`.

### Fixed

- Duplicate summary services produced by overlapping or multi-term Juniper application expansion are now deduplicated without discarding distinct underlying semantics.

### Removed

- `config_xml` from `JuniperSRXDriver`; offline Juniper ingestion now accepts only `config_path`.

## [0.2.1] - 2026-03-17

### Fixed

- PyPI publish workflow now marks the package as public.

## [0.2.0] - 2026-03-17

### Added

- Read-only Juniper SRX driver with live device fetch and file-based XML ingestion.
- Device-order rule extraction for zone-to-zone and global Juniper security policies.
- Recursive Juniper address-book, address-set, application, and application-set resolution with cycle protection.
- Juniper-specific JSON export for parsed firewall rules.
- Additional vendor-generic `FirewallRule` metadata including sequence, zones, object references, descriptions, logging summary, and raw vendor payloads.
- Comprehensive Juniper fixtures and test coverage for parsing, resolution, action normalization, inactive rules, RPC-reply handling, live fetch mocking, and JSON export.

### Changed

- `get_firewall_driver()` now accepts richer keyword arguments required by the Juniper driver.
- Juniper support was refactored from a single module into a package with dedicated driver, resolver, and XML helper modules.
- Import path changed from `ufaya.drivers.juniper_srx` to `ufaya.drivers.juniper`.

### Removed

- Legacy `src/ufaya/drivers/juniper_srx.py` module.

## [0.1.0] - 2026-03-16

### Added

- `FirewallDriver` abstract base class with typed CRUD and commit operations.
- `FirewallRule` Pydantic model shared across firewall drivers.
- Initial driver skeletons for Palo Alto, Fortinet, Cisco, and Juniper SRX.
- `get_firewall_driver()` factory for vendor-based driver selection.
- PEP 561 typing marker, test suite, and CI/dev tooling configuration.

[Unreleased]: https://github.com/A-Khanafer/ufaya/compare/v0.6.3...HEAD
[0.6.3]: https://github.com/A-Khanafer/ufaya/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/A-Khanafer/ufaya/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/A-Khanafer/ufaya/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/A-Khanafer/ufaya/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/A-Khanafer/ufaya/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/A-Khanafer/ufaya/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/A-Khanafer/ufaya/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/A-Khanafer/ufaya/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/A-Khanafer/ufaya/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/A-Khanafer/ufaya/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/A-Khanafer/ufaya/releases/tag/v0.1.0
