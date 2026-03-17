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

## Running tests

```bash
pytest
```

Pytest is configured with coverage reporting, so the default run includes a terminal coverage summary.

## Code style

This project uses **ruff** for linting and formatting, and **mypy** for type checking.

```bash
ruff check src/ tests/
mypy src/ufaya
```

If you are preparing a release or validating packaging changes, build the distribution locally:

```bash
python -m pip install build
python -m build
```

## Adding a new vendor driver

1. Create `src/ufaya/drivers/<vendor>.py` with a class that inherits from `FirewallDriver`.
2. Implement all required driver methods: `get_rules`, `create_rule`, `delete_rule`, and `commit`.
3. Register the driver in `src/ufaya/services/device_factory.py` by adding it to `_DRIVERS`.
4. Export the driver from `src/ufaya/drivers/__init__.py`.
5. Add or extend tests in `tests/test_factory.py` and `tests/test_drivers.py`.

Driver implementations should accept the standard connection kwargs used by `get_firewall_driver(...)`: `host`, `username`, and `password`.

Rules created by drivers should use the current `FirewallRule` model shape:

```python
FirewallRule(
    vendor="paloalto",
    device="fw-01",
    name="allow-web",
    source=["10.0.0.0/24"],
    destination=["any"],
    service=["tcp/443"],
    action="allow",
)
```

## Pull requests

- Keep PRs focused: one feature or fix per PR.
- Include tests for any new behaviour.
- Make sure `pytest`, `ruff`, and `mypy` all pass before opening a PR.
- Update `README.md`, `CONTRIBUTING.md`, or `CHANGELOG.md` when the public API, workflow, or release behaviour changes.
