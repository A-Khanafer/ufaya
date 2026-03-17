# Contributing to ufaya

Thank you for your interest in contributing!

## Setup

```bash
git clone https://github.com/A-Khanafer/ufaya.git
cd ufaya
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest
```

## Code style

This project uses **ruff** for linting and formatting, and **mypy** for type checking.

```bash
ruff check src/ tests/
mypy src/ufaya
```

## Adding a new vendor driver

1. Create `src/ufaya/drivers/<vendor>.py` with a class that inherits from `FirewallDriver`.
2. Implement all four abstract methods: `get_rules`, `create_rule`, `delete_rule`, `commit`.
3. Register the driver in `src/ufaya/services/device_factory.py` (`_DRIVERS` dict).
4. Export the class from `src/ufaya/drivers/__init__.py`.
5. Add tests in `tests/test_drivers.py`.

## Pull requests

- Keep PRs focused — one feature or fix per PR.
- Include tests for any new behaviour.
- Make sure `pytest`, `ruff`, and `mypy` all pass before opening a PR.
