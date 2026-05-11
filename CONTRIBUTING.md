# Contributing to ufaya

Thank you for your interest in contributing!

## Setup

```bash
git clone https://github.com/A-Khanafer/ufaya.git
cd ufaya
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

The project targets Python 3.10 through 3.12.

## Development workflow

The repo ships a `Makefile` that wraps the full pre-push gauntlet:

```bash
make check              # lint + types + all tests (~3 seconds)
make lint               # ruff only
make type               # mypy only
make test               # pytest only
make snapshots          # snapshot regression tests only
make schema             # JSON Schema validation tests only
make update-snapshots   # regenerate tests/snapshots/ after intentional output changes
```

Run `make check` before every push. The CI job runs the same gauntlet, so passing locally means CI will pass too.

If `make` is not available on your system, the equivalent commands are:

```bash
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
.venv/bin/pytest -q
```

## JSON Schema and snapshot tests

The library publishes two JSON Schemas as the canonical contract for downstream consumers:

- `schemas/firewall_rules.v3.schema.json`
- `schemas/nat_rules.v2.schema.json`

Two test layers exercise the export pipeline. Both run under `make check`:

| Layer | Asks | Fails when |
|---|---|---|
| **Schema validation** (`tests/test_export_schema.py`) | "Does this output match the documented contract?" | The export grows a field the schema does not declare, drops a required field, or changes a type. |
| **Snapshot regression** (`tests/test_export_snapshots.py`) | "Did the output change at all since last commit?" | *Any* observable change in the JSON, even contract-conforming ones. |

Snapshots are pure JSON files under `tests/snapshots/` so `git diff` shows reviewers exactly what consumers will see.

### When you intentionally change export output

```bash
make update-snapshots          # regenerates tests/snapshots/*.json
git diff tests/snapshots/      # eyeball every change
git add tests/snapshots/
```

If the change also affects the public contract (renamed field, new required field, removed field, type change), update the matching schema in `schemas/` in the same PR. If the change is a breaking contract change, also bump the schema's `schema_version` constant in the schema file and in the corresponding `build_*_payload` call inside the driver.

## Adding a new vendor driver

The library uses capability-based interfaces — drivers implement only the capabilities they actually support.

1. Create your driver module, e.g. `src/ufaya/drivers/<vendor>/driver.py`. The class should inherit from one or more capability ABCs:

   ```python
   from ufaya.firewall.base import FirewallReader, NatReader, FirewallWriter

   class MyVendorDriver(FirewallReader, NatReader):
       def __init__(self, *, host: str, username: str, password: str) -> None:
           ...

       def get_rules(self) -> list[FirewallRuleRecord]:
           ...

       def get_nat_rules(self) -> list[NatRuleRecord]:
           ...

       # Override open()/close() if the driver holds a network connection so
       # `with driver:` can reuse one session across multiple calls. The
       # default implementations are no-ops, which is correct for offline drivers.
   ```

   Implement `FirewallWriter` only when the driver can actually push and commit changes.

2. Register the driver in `_BUILTIN_DRIVERS` in `src/ufaya/services/device_factory.py` using a `"module.path:ClassName"` string. The string form keeps the driver lazy-loaded:

   ```python
   _BUILTIN_DRIVERS: dict[str, DriverSpec] = {
       "juniper_srx": "ufaya.drivers.juniper:JuniperSRXDriver",
       "my_vendor":   "ufaya.drivers.my_vendor:MyVendorDriver",
   }
   ```

3. Add fixtures under `tests/fixtures/` and driver-specific tests. The schema and snapshot suites currently target the Juniper driver only; if you want them to cover your vendor too, extend `tests/_export_helpers.py` to dispatch on vendor, or add a parallel test module.

4. Vendors with scoping concepts that do not exist on the shared model (Palo Alto `vsys`, Fortinet `vdom`, Cisco FMC `package`, etc.) should populate `RuleContext.vendor_context` / `NatRuleContext.vendor_context` rather than adding fields to the shared models.

5. Rules created by drivers should use the canonical `FirewallRule` model:

   ```python
   FirewallRule(
       vendor="my_vendor",
       device="fw-01",
       name="allow-web",
       source=["10.0.0.0/24"],
       destination=["any"],
       service=["tcp/443"],
       action="allow",
   )
   ```

   Optional fields like `vendor_rule_id`, `sequence`, `description`, `log_actions`, and `hit_count` should be populated when the vendor exposes them.

### Out-of-tree drivers

Drivers do not have to live in this repo. A third-party package can register a driver via the `ufaya.drivers` entry-point group in its own `pyproject.toml`:

```toml
[project.entry-points."ufaya.drivers"]
my_vendor = "my_pkg.driver:MyVendorDriver"
```

After `pip install`, `ufaya.get_firewall_driver("my_vendor", ...)` and `ufaya.available_vendors()` will pick it up automatically.

## Pull requests

- Keep PRs focused: one feature or fix per PR.
- Include tests for any new behaviour.
- Run `make check` before opening a PR.
- Update `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, or the `schemas/` files whenever the public API, JSON schema, workflow, or release behaviour changes.

## Releasing

Releases are decoupled from pushes to `main`. A release happens only when you create and push a git tag.

```bash
make check                                            # green
make build                                            # produces dist/, runs twine check
make smoke                                            # installs the wheel into a throwaway venv
git tag v0.X.Y && git push --tags                     # setuptools_scm derives the version from the tag
.venv/bin/twine upload --repository testpypi dist/*   # rehearse on TestPyPI first
.venv/bin/twine upload dist/*                         # publish to PyPI
```

Pushing to `main` without tagging never publishes anything. The version on PyPI is whatever the most recent tag is; intermediate commits stay internal.
