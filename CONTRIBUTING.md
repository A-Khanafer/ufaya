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

The repo ships a `Makefile` that uses the tools installed in `.venv/`; you do not
need to activate the environment to run these commands:

```bash
make check-fast         # lint + formatting checks + types before committing
make fix                # apply safe lint fixes, then format Python files
make check              # check-fast + all tests before pushing
make lint               # ruff only
make format-check       # check formatting without changing files
make format             # apply formatting
make type               # mypy only
make test               # pytest only
make snapshots          # snapshot regression tests only
make schema             # JSON Schema validation tests only
make update-snapshots   # regenerate tests/snapshots/ after intentional output changes
```

Run `make check-fast` before committing and `make check` before pushing. Both
commands check files without editing them. If lint or formatting fails, run
`make fix`, address any remaining errors, review the diff, and rerun the checks.
CI runs the same lint, formatting, type, and test checks on Python 3.10–3.12.

If `make` is not available, activate your virtual environment and run:

```bash
python -m ruff check src/ tests/
python -m ruff format --check src/ tests/
python -m mypy src/
python -m pytest -q
```

The first three commands are equivalent to `make check-fast`; add pytest for
the full `make check` suite.

### Optional commit hooks

To run lint, formatting, and type checks automatically on each commit, install
the [pre-commit](https://pre-commit.com/) hooks once per clone:

```bash
.venv/bin/python -m pip install -e ".[dev]"  # refresh existing environments
make install-hooks
```

The hooks require `make` and the project's `.venv/`. They reuse the Makefile
targets and check all of `src/` and `tests/` (types cover `src/` only), including
commits that change configuration rather than Python files. Checks do not edit
files. When a commit fails, run `make fix` or correct the reported errors,
review and stage the changes, then retry the commit. Tests remain part of
`make check` and CI.

Run the hooks manually or remove them with:

```bash
.venv/bin/pre-commit run --all-files
.venv/bin/pre-commit uninstall
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

The [Publish to PyPI workflow](.github/workflows/publish.yml) runs when a tag
matching `v*` is pushed. Merging or pushing to `main` runs CI but does not publish
a package. Creating a GitHub Release for an existing tag is not a publishing
trigger.

### One-time trusted publisher setup

A PyPI project owner must configure a GitHub Actions trusted publisher for
`ufaya` under the project's **Manage → Publishing** page. Use these values to
match the workflow:

| PyPI field | Value |
|---|---|
| Owner | `A-Khanafer` |
| Repository | `ufaya` |
| Workflow filename | `publish.yml` |
| Environment | `pypi` |

The workflow filename is just `publish.yml`, without `.github/workflows/`.
Configure the GitHub repository's `pypi` environment to allow the intended
release tags. If that environment requires reviewers, an authorized reviewer
must approve the deployment before publishing can start. These settings live
in GitHub and PyPI and must be checked separately from the repository files.
See [PyPI's trusted publisher setup guide](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).

The publish job already declares `environment: pypi` and `id-token: write`.
The PyPA publishing action uses GitHub's OIDC identity to obtain a short-lived
PyPI credential; this workflow needs no stored PyPI password or API token.
See [publishing with a trusted publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/).

### Prepare the release

Choose an unused version and move the relevant `CHANGELOG.md` entries from
`Unreleased` into a dated release section. Merge that change and all release
work into `main`, then start from a clean checkout of the intended commit:

```bash
git switch main
git pull --ff-only
git fetch origin --tags
git status --short  # must be empty before proceeding
git log -1 --oneline  # confirm the commit you intend to release
```

Use a Python 3.10–3.12 development environment from the setup instructions
above. Activate it so the smoke target's `python3` uses that interpreter, then
install the local packaging tools and run the release checks:

```bash
source .venv/bin/activate
.venv/bin/python -m pip install -e ".[dev]" build twine
make check
make smoke
```

`make check` runs lint, formatting, types, and all tests. `make smoke` also runs
`make build`: it rebuilds the wheel and source distribution, validates their
metadata with `twine check`, then installs the wheel into a temporary environment
and parses a Juniper fixture. These commands build and validate locally; the
publish job builds its own artifacts from the tagged commit.

Versions come from Git tags through `setuptools-scm`. Do not edit
`src/ufaya/_version.py` or add a static version to `pyproject.toml`. A local build
before tagging may have a development version; the clean tagged build in CI
gets the release version.

### Tag and publish

Replace `0.X.Y` below with the chosen unpublished version. After all local
checks pass and the working tree is clean, create an annotated tag and push
that specific tag:

```bash
release_version=0.X.Y
git tag -a "v${release_version}" -m "Release ${release_version}"
git push origin "refs/tags/v${release_version}"
```

Pushing the tag starts the release workflow:

1. The `test` job runs the reusable CI workflow on Python 3.10, 3.11, and 3.12.
2. After all checks pass and any `pypi` environment approval is granted, the
   `publish` job checks out the tag with full Git history and builds the wheel
   and source distribution on Python 3.12.
3. `pypa/gh-action-pypi-publish` uploads the contents of `dist/` to PyPI using
   trusted publishing.

This workflow targets production PyPI. It has no TestPyPI rehearsal step.
Adding one would require a separate TestPyPI trusted publisher and an explicit
TestPyPI destination in the workflow; manual `twine upload` is not part of this
release process.

### Verify the release

Open [Publish to PyPI runs](https://github.com/A-Khanafer/ufaya/actions/workflows/publish.yml)
and confirm that the run for your tag completed successfully, including the
upload step. Then check the version and wheel/source distribution on
[UFAYA's PyPI page](https://pypi.org/project/ufaya/#history).

In the same shell where `release_version` was set, install that exact version
from PyPI into a fresh environment and confirm it imports:

```bash
release_check_dir=$(mktemp -d "${TMPDIR:-/tmp}/ufaya-release.XXXXXX")
.venv/bin/python -m venv "$release_check_dir"
"$release_check_dir/bin/python" -m pip install --index-url https://pypi.org/simple "ufaya==${release_version}"
"$release_check_dir/bin/python" -c 'import ufaya; print(ufaya.__version__)'
```

The printed version should match the release version. You can then create a
GitHub Release for the existing tag and copy in the changelog notes.

### If publishing fails

- If CI or the build fails, inspect that job's logs. Merge any necessary code
  fixes into `main` and prepare a new version and tag.
- If the job is waiting for approval, check the `pypi` environment's deployment
  review. For an authentication error such as `invalid-publisher`, compare the
  PyPI publisher fields with the table above and check `id-token: write`.
  See [PyPI's troubleshooting guide](https://docs.pypi.org/trusted-publishers/troubleshooting/).
- For a transient failure before any files were uploaded, retry the failed
  workflow jobs after resolving the cause. If files were already uploaded,
  inspect the release on PyPI before retrying. Publish corrections under a new
  version rather than moving a published tag or replacing published files.
