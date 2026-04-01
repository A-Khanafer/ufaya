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
| Juniper SRX | `juniper_srx` | Read-only ingestion + context-grouped JSON export with live policy hit counts |
| Palo Alto | `paloalto` | Skeleton |
| Fortinet | `fortinet` | Skeleton |
| Cisco | `cisco` | Skeleton |

## Juniper SRX JSON export

`JuniperSRXDriver.export_rules_json(output_dir, mode=...)` writes a context-grouped JSON document for parsed security policies.

- Export modes remain `minimal`, `enriched`, and `debug`.
- Export payloads now use `schema_version: 3`.
- Each exported rule includes a canonical `hit_count` field.
- In live mode, UFAYA fetches `show security policies hit-count | display xml | no-more` and populates `hit_count` when that operational snapshot is available.
- In file mode, or when the live hit-count snapshot cannot be collected, rules still include `hit_count: null`.
- Live exports that successfully collect hit counts also include a top-level `hit_counts_collected_at` UTC timestamp.
- Hit-count parser maintenance notes live in [JUNIPER_HIT_COUNTS.md](JUNIPER_HIT_COUNTS.md).

## Installation

```bash
pip install ufaya
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
