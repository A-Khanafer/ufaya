# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[Unreleased]: https://github.com/A-Khanafer/ufaya/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/A-Khanafer/ufaya/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/A-Khanafer/ufaya/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/A-Khanafer/ufaya/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/A-Khanafer/ufaya/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/A-Khanafer/ufaya/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/A-Khanafer/ufaya/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/A-Khanafer/ufaya/releases/tag/v0.1.0
