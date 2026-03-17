# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[Unreleased]: https://github.com/A-Khanafer/ufaya/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/A-Khanafer/ufaya/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/A-Khanafer/ufaya/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/A-Khanafer/ufaya/releases/tag/v0.1.0
