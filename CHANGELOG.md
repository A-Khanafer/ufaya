# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `FirewallDriver` abstract base class with full type hints
- `FirewallRule` Pydantic model wired into the driver interface
- Skeleton drivers for Palo Alto, Fortinet, Cisco, and Juniper SRX
- `get_firewall_driver()` factory supporting all four vendors
- `py.typed` marker for PEP 561 compliance
- Full test suite (`tests/`)
- CI workflow (GitHub Actions) — lint, type-check, test on Python 3.10–3.12
- Dev tooling: ruff, mypy, pytest-cov configured in `pyproject.toml`
