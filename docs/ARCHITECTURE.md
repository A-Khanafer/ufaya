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
│   ├── firewall_rule.py # Canonical firewall-rule, context, trace, hit-count, and record Pydantic models
│   └── nat_rule.py      # Canonical NAT rule, conditions, mapping, rewrite, and record Pydantic models
├── drivers/
│   ├── paloalto.py      # Palo Alto Networks driver (skeleton)
│   ├── fortinet.py      # Fortinet FortiGate driver (skeleton)
│   ├── cisco.py         # Cisco ASA / FTD driver (skeleton)
│   └── juniper/         # Juniper SRX driver package
│       ├── __init__.py   # Re-exports JuniperSRXDriver
│       ├── driver.py     # JuniperSRXDriver — XML ingestion, firewall export, NAT export, source modes
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
              ├─ get_rules()    → list[FirewallRuleRecord]
              ├─ create_rule()  ← FirewallRule
              ├─ delete_rule()  ← rule_id: str
              └─ commit()
```

### Juniper SRX (read-only ingestion + export)

```
User code
  └─► JuniperSRXDriver(host=... | config_path=...)
        ├─ get_rules()           → list[FirewallRuleRecord]
        │    ├─ _load_rule_data()→ config XML + optional live hit-count snapshot
        │    │    └─ _fetch_live_data() → operational hit-count command + config fetch
        │    ├─ _parse_xml()     → ElementTree root (config or operational XML)
        │    ├─ _parse_hit_count_lookup()
        │    │    └─ accepts multiple operational XML schemas, including multi-routing-engine wrappers
        │    └─ _extract_rules() → walks contexts, resolves addresses/apps, applies hit counts
        │         └─ Resolver    → expands address-books, address-sets, applications
        ├─ export_rules_json()   → Path  (atomic schema v3 JSON write, minimal/enriched/debug modes)
        ├─ get_nat_rules()       → list[NatRuleRecord]
        │    ├─ _load_config_xml() → config XML only
        │    ├─ _parse_xml()       → ElementTree root
        │    └─ _extract_nat()     → walks security/nat/source|destination|static
        │         ├─ Resolver      → expands address-book and application references used by NAT conditions/mappings
        │         └─ pool inventory → normalizes referenced translation pools for rule output + supporting objects
        └─ export_nat_json()     → Path  (atomic schema v2 JSON write, minimal/enriched/debug modes)
```

## Design principles

- **Single interface**: all drivers expose the same four methods — callers never need to know the vendor.
- **Pydantic models**: `FirewallRuleRecord` and `NatRuleRecord` wrap canonical firewall and NAT data with evaluation context plus optional trace/debug sections.
- **No coupling**: drivers only import from `firewall.base` and `models`; they do not import each other.
- **Easy extension**: add a new vendor by subclassing `FirewallDriver` and registering it in `device_factory.py`.
- **Vendor packages**: complex drivers (e.g., Juniper) are split into sub-packages to keep modules focused and testable.

For Juniper SRX, live-mode exports enrich the canonical rule model with operational hit-count data fetched from `show security policies hit-count | display xml | no-more`, not from configuration XML. When that snapshot is available, the JSON export also records a top-level `hit_counts_collected_at` UTC timestamp; file-backed exports keep the same per-rule shape with `hit_count: null`.

Because Junos operational XML can vary by release and platform wrapper, the Juniper hit-count parser supports multiple known response shapes. Maintenance notes for future schema changes live in `JUNIPER_HIT_COUNTS.md`.

For Juniper SRX NAT export, both live mode and file mode use configuration XML as the only source of truth. `export_nat_json()` fetches or reads the full configuration XML, parses `<security><nat>`, and emits vendor-agnostic, rule-centric NAT JSON (schema v2) grouped by rule-set context.

The canonical NAT payload distinguishes **conditions** (traffic match) from **mapping** (address/port rewrite):

- **`conditions`**: traffic selectors that determine which packets a NAT rule applies to. Unconstrained source or destination selectors export explicitly as `["any"]`. Junos `application` references are resolved into canonical protocol/source-port/destination-port fields while preserving raw application names. Explicit `<protocol>`, `<source-port>`, and `<destination-port>` selectors are merged with application-derived semantics deterministically. `source_refs` and `destination_refs` inline the raw config-object references used for resolution.

- **`mapping`**: explicit before/after rewrite. Contains a required `forward` step and an optional `reverse` step (static NAT only). Each step (`NatRewrite`) includes:
  - `summary`: human-readable rewrite string, e.g. `"destination 203.0.113.10/32:443 -> 10.10.10.10/32:8443"`
  - `original` / `translated`: `NatMappingSide` with `field` (source/destination), `addresses`, `ports`, `ref` (raw pool/prefix reference), `address_source` (for interface NAT)
  - `mapping_kind`: `fixed` (static), `pool` (pool-based), or `interface_address`
  - `determinism`: `exact` (1:1 mapping), `set_based` (pool/range), or `dynamic` (interface)
  - `resolution_status`: `resolved` or `unresolved` — unresolved entries still export the raw ref so downstream consumers can identify the gap

Enriched and debug NAT exports also include referenced translation pools under `supporting_objects.translation_pools`. Those supporting objects stay scoped to pools actually used by exported rules and reuse the same normalized address/port values as the rule-level mapping targets, including supported address-range forms.
