# UFAYA

**Unified Firewall Abstraction laYer for Automation**

[![CI](https://github.com/A-Khanafer/ufaya/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Khanafer/ufaya/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/ufaya)](https://pypi.org/project/ufaya/)
[![Python versions](https://img.shields.io/pypi/pyversions/ufaya)](https://pypi.org/project/ufaya/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

UFAYA is a Python SDK that provides a single, consistent interface for interacting with firewalls from multiple vendors. Instead of writing separate automation scripts for each firewall platform, UFAYA exposes a unified abstraction layer that normalizes firewall operations across different systems.

The design follows the same architectural principle used by tools like NAPALM, which provide a unified API to interact with devices from different vendors through an abstraction layer.

## Supported Vendors

| Vendor | Driver | Status |
|---|---|---|
| Juniper SRX | `juniper_srx` | Read-only XML ingestion + firewall-rule JSON export with live policy hit counts + XML-first NAT JSON export |
| Palo Alto | `paloalto` | Planned |
| Fortinet | `fortinet` | Planned |
| Cisco | `cisco` | Planned |

Drivers can also be contributed out-of-tree and registered via the
`ufaya.drivers` entry-point group; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Juniper SRX exports

`JuniperSRXDriver.export_rules_json(output_dir, mode=...)` writes a context-grouped JSON document for parsed security policies.

- Export modes remain `minimal`, `enriched`, and `debug`.
- Export payloads now use `schema_version: 3`.
- Each exported rule includes a canonical `hit_count` field.
- In live mode, UFAYA fetches `show security policies hit-count | display xml | no-more` and populates `hit_count` when that operational snapshot is available.
- The live hit-count parser supports both older `policy-information` responses and newer Junos operational XML variants such as `multi-routing-engine-results` with `policy-hit-count-entry` records.
- In file mode, or when the live hit-count snapshot cannot be collected, rules still include `hit_count: null`.
- Live exports that successfully collect hit counts also include a top-level `hit_counts_collected_at` UTC timestamp.
- Hit-count parser maintenance notes live in [JUNIPER_HIT_COUNTS.md](JUNIPER_HIT_COUNTS.md).

`JuniperSRXDriver.export_nat_json(output_dir, mode=...)` writes a context-grouped JSON document for parsed Junos NAT rules.

- NAT export is XML-first in both modes:
  - live mode fetches `show configuration | display xml | no-more`
  - file mode reads the XML file passed via `config_path`
- NAT parsing walks `<security><nat><source>`, `<destination>`, and `<static>` from configuration XML.
- NAT export modes are also `minimal`, `enriched`, and `debug`.
- NAT payloads use `schema_version: 2`.
- Exported NAT rules use a vendor-agnostic, rule-centric shape with explicit `conditions` (traffic match) and `mapping` (before/after rewrite) blocks.
- `conditions` describes which packets the rule selects; `mapping` describes what field is rewritten, from which addresses/ports, to which addresses/ports.
- Each mapping step includes a human-readable `summary`, `original`/`translated` sides, `mapping_kind` (`fixed`/`pool`/`interface_address`), `determinism` (`exact`/`set_based`/`dynamic`), and `resolution_status` (`resolved`/`unresolved`).
- Static NAT exports both `forward` (inbound destination rewrite) and `reverse` (outbound source rewrite) mapping steps.
- Unconstrained NAT address selectors export explicitly as `["any"]` in `conditions`.
- NAT `application` references are resolved into canonical protocol/port condition fields while preserving raw application names.
- Enriched and debug NAT exports also include referenced translation pools under `supporting_objects.translation_pools`.
- `supporting_objects.translation_pools` remains scoped to pools actually referenced by exported rules, not the full device inventory.
- Referenced translation pools export the same normalized address/port values used by rule-level mapping targets, including supported address-range forms.
- NAT lookup metadata records Juniper precedence as `static`, then `destination`, then `source`.

## Installation

```bash
pip install ufaya
```

## Usage

```python
import ufaya

# File mode: parse a saved Junos XML config.
driver = ufaya.get_firewall_driver(
    "juniper_srx",
    config_path="srx-prod.xml",
)
rules = driver.get_rules()

# Live mode: SSH to the device. Use as a context manager so a single SSH
# session is shared across get_rules() and get_nat_rules() (and any future
# operational reads).
driver = ufaya.get_firewall_driver(
    "juniper_srx",
    host="srx-prod.example.com",
    username="readonly",
    password="...",
)
with driver:
    rules = driver.get_rules()
    nat_rules = driver.get_nat_rules()

# Capability discovery: ask what the driver can do, rather than calling and
# catching NotImplementedError.
from ufaya.firewall.base import NatReader, FirewallWriter
assert isinstance(driver, NatReader)        # supports NAT reads
assert not isinstance(driver, FirewallWriter)  # read-only
```

Out-of-tree drivers can register themselves via `ufaya.register_driver(...)` or by declaring a `[project.entry-points."ufaya.drivers"]` entry in their own `pyproject.toml`. See [CONTRIBUTING.md](CONTRIBUTING.md#out-of-tree-drivers).

## JSON Schemas

The `schemas/` directory publishes the canonical contract for each export type:

- [`schemas/firewall_rules.v3.schema.json`](schemas/firewall_rules.v3.schema.json) — `JuniperSRXDriver.export_rules_json()` output.
- [`schemas/nat_rules.v2.schema.json`](schemas/nat_rules.v2.schema.json) — `JuniperSRXDriver.export_nat_json()` output.

Both are strict (`additionalProperties: false`) Draft 2020-12 schemas. Downstream consumers can use them with any JSON Schema validator. The repo's CI fails any change that violates the contract; see [CONTRIBUTING.md](CONTRIBUTING.md#json-schema-and-snapshot-tests) for the development flow.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
