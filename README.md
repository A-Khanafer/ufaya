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
| Palo Alto | `paloalto` | Skeleton |
| Fortinet | `fortinet` | Skeleton |
| Cisco | `cisco` | Skeleton |

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
- NAT payloads use `schema_version: 1`.
- Exported NAT rules use a vendor-agnostic, rule-centric shape with canonical `match` and `translation` blocks.
- Unconstrained NAT address selectors export explicitly as `["any"]` in the canonical `match`.
- NAT `application` references are resolved into canonical protocol/port match fields while preserving raw application names.
- Enriched and debug NAT exports also include referenced translation pools under `supporting_objects.translation_pools`.
- `supporting_objects.translation_pools` remains scoped to pools actually referenced by exported rules, not the full device inventory.
- Referenced translation pools export the same normalized address/port values used by rule-level translation targets, including supported address-range forms.
- NAT lookup metadata records Juniper precedence as `static`, then `destination`, then `source`.

## Installation

```bash
pip install ufaya
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
