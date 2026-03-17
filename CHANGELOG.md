# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-03-17

### Added
- **Juniper SRX security-policy ingestion** — full read-only driver supporting three mutually exclusive source modes:
  - **Live** — connects to a device via Netmiko using `host`, `username`, `password`
  - **Offline file** — reads XML from a local path via `config_path`
  - **Offline raw XML** — accepts an XML string via `config_xml`
- `JuniperSRXDriver.get_rules()` returns `list[FirewallRule]` in device evaluation order
  - Zone-to-zone and global policies
  - Address-book and address-set resolution with recursive expansion and cycle protection
  - Custom application and application-set resolution
  - Action normalisation (`permit` → `allow`, `deny` → `deny`, `reject` → `reject`)
  - Inactive policy detection (`enabled=False`)
  - Description and logging extraction
  - Junos `<rpc-reply>` wrapper handling
  - Unresolved vendor names preserved (never silently dropped)
- `JuniperSRXDriver.export_rules_json(output_dir)` — Juniper-specific JSON export
  - Deterministic filename: `<sanitized_device>.firewall_rules.json`
  - Atomic overwrite via temp file + `os.replace()`
  - Creates output directory with `parents=True` if missing
  - Top-level JSON payload: `vendor`, `device`, `rule_count`, `order`, `rules`
- Extended `FirewallRule` model with new optional fields (backward-compatible):
  - `sequence`, `source_zones`, `destination_zones`
  - `source_refs`, `destination_refs`, `service_refs`
  - `description`, `log_events`, `raw`
- Comprehensive test suite for Juniper SRX (constructor validation, XML parsing, address/application resolution, action normalisation, inactive policies, RPC-reply unwrapping, live fetch mock, JSON export)
- XML test fixtures under `tests/fixtures/`

### Changed
- `get_firewall_driver()` kwargs widened from `str` to `Any` to support Juniper's richer constructor
- `JuniperSRXDriver` constructor now uses keyword-only arguments


## [0.1.0]

### Added
- `FirewallDriver` abstract base class with full type hints
- `FirewallRule` Pydantic model wired into the driver interface
- Skeleton drivers for Palo Alto, Fortinet, Cisco, and Juniper SRX
- `get_firewall_driver()` factory supporting all four vendors
- `py.typed` marker for PEP 561 compliance
- Full test suite (`tests/`)
- CI workflow (GitHub Actions) — lint, type-check, test on Python 3.10–3.12
- Dev tooling: ruff, mypy, pytest-cov configured in `pyproject.toml`
