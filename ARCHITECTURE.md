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
│   ├── paloalto.py      # Palo Alto Networks driver (skeleton)
│   ├── fortinet.py      # Fortinet FortiGate driver (skeleton)
│   ├── cisco.py         # Cisco ASA / FTD driver (skeleton)
│   └── juniper/         # Juniper SRX driver package
│       ├── __init__.py   # Re-exports JuniperSRXDriver
│       ├── driver.py     # JuniperSRXDriver — ingestion, export, source modes
│       ├── resolver.py   # Address-book/application resolution, action normalisation
│       └── xml_helpers.py# Namespace-agnostic XML element lookup utilities
└── services/
    └── device_factory.py # get_firewall_driver() — instantiates the right driver by vendor string
```

## Data flow

### Generic (all vendors)

```
User code
  └─► get_firewall_driver("paloalto", host=..., ...)
        └─► PaloAltoDriver  (implements FirewallDriver)
              ├─ get_rules()    → list[FirewallRule]
              ├─ create_rule()  ← FirewallRule
              ├─ delete_rule()  ← rule_id: str
              └─ commit()
```

### Juniper SRX (read-only ingestion + export)

```
User code
  └─► JuniperSRXDriver(host=... | config_path=... | config_xml=...)
        ├─ get_rules()           → list[FirewallRule]  (device evaluation order)
        │    ├─ _load_xml()      → raw XML string (live / file / raw)
        │    ├─ _parse_xml()     → ElementTree root (unwraps <rpc-reply>)
        │    └─ _extract_rules() → walks policies, resolves addresses & apps
        │         └─ Resolver    → expands address-books, address-sets, applications
        └─ export_rules_json()   → Path  (atomic JSON write)
```

## Design principles

- **Single interface**: all drivers expose the same four methods — callers never need to know the vendor.
- **Pydantic models**: `FirewallRule` is a strict, typed data transfer object shared by all drivers.
- **No coupling**: drivers only import from `firewall.base` and `models`; they do not import each other.
- **Easy extension**: add a new vendor by subclassing `FirewallDriver` and registering it in `device_factory.py`.
- **Vendor packages**: complex drivers (e.g., Juniper) are split into sub-packages to keep modules focused and testable.
