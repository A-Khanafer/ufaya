# Architecture

ufaya is a thin, vendor-agnostic SDK that wraps vendor-specific firewall APIs behind a single abstract interface.

## Package layout

```
src/ufaya/
├── __init__.py          # Public re-exports
├── py.typed             # PEP 561 marker — declares the package as typed
├── firewall/
│   └── base.py          # FirewallDriver ABC — the single interface all drivers implement
├── models/
│   └── firewall_rule.py # FirewallRule Pydantic model — canonical data shape
├── drivers/
│   ├── paloalto.py      # Palo Alto Networks driver
│   ├── fortinet.py      # Fortinet FortiGate driver
│   ├── cisco.py         # Cisco ASA / FTD driver
│   └── juniper_srx.py   # Juniper SRX driver
└── services/
    └── device_factory.py # get_firewall_driver() — instantiates the right driver by vendor string
```

## Data flow

```
User code
  └─► get_firewall_driver("paloalto", host=..., ...)
        └─► PaloAltoDriver  (implements FirewallDriver)
              ├─ get_rules()    → list[FirewallRule]
              ├─ create_rule()  ← FirewallRule
              ├─ delete_rule()  ← rule_id: str
              └─ commit()
```

## Design principles

- **Single interface**: all drivers expose the same four methods — callers never need to know the vendor.
- **Pydantic models**: `FirewallRule` is a strict, typed data transfer object shared by all drivers.
- **No coupling**: drivers only import from `firewall.base` and `models`; they do not import each other.
- **Easy extension**: add a new vendor by subclassing `FirewallDriver` and registering it in `device_factory.py`.
