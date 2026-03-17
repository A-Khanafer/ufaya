# UFAYA

**Unified Firewall Abstraction laYer for Automation**

[![CI](https://github.com/A-Khanafer/ufaya/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Khanafer/ufaya/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/ufaya)](https://pypi.org/project/ufaya/)
[![Python versions](https://img.shields.io/pypi/pyversions/ufaya)](https://pypi.org/project/ufaya/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

UFAYA is a Python SDK that provides a single, consistent interface for interacting with firewalls from multiple vendors. Instead of writing separate automation scripts for each firewall platform, UFAYA exposes a unified abstraction layer that normalizes firewall operations across different systems.

The design follows the same architectural principle used by tools like NAPALM, which provide a unified API to interact with devices from different vendors through an abstraction layer.

## Supported Vendors

| Vendor | Driver |
|---|---|
| Palo Alto | `paloalto` |
| Fortinet | `fortinet` |
| Cisco | `cisco` |
| Juniper SRX | `juniper_srx` |

## Installation

```bash
pip install ufaya
```

## Quick Start

```python
from ufaya import get_firewall_driver, FirewallRule

# Connect to a firewall
driver = get_firewall_driver("paloalto", host="192.168.1.1", username="admin", password="secret")

# Retrieve existing rules
rules = driver.get_rules()

# Create a new rule
rule = FirewallRule(
    name="allow-web",
    source="10.0.0.0/24",
    destination="0.0.0.0/0",
    action="allow",
    protocol="tcp",
    port=443,
)
driver.create_rule(rule)
driver.commit()
```

## Development

```bash
git clone https://github.com/A-Khanafer/ufaya.git
cd ufaya
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)
