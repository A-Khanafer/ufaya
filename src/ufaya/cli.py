"""Command-line interface for UFAYA exports."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, Protocol, runtime_checkable

from ufaya.export import VALID_EXPORT_MODES
from ufaya.firewall.base import NatReader
from ufaya.services.device_factory import get_firewall_driver


@runtime_checkable
class _RulesJsonExporter(Protocol):
    def export_rules_json(
        self, output_dir: str | Path, mode: str = "enriched"
    ) -> Path: ...


@runtime_checkable
class _NatJsonExporter(Protocol):
    def export_nat_json(
        self, output_dir: str | Path, mode: str = "enriched"
    ) -> Path: ...


class _CLIError(Exception):
    """An expected command-line usage or runtime error."""


def build_parser() -> argparse.ArgumentParser:
    """Build the public UFAYA argument parser."""
    parser = argparse.ArgumentParser(
        prog="ufaya",
        description="Export normalized firewall configuration data.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    export_parser = commands.add_parser(
        "export", help="Export firewall configuration data as JSON."
    )
    resources = export_parser.add_subparsers(dest="resource", required=True)

    for resource, help_text in (
        ("rules", "Export security policies."),
        ("nat", "Export NAT rules."),
    ):
        resource_parser = resources.add_parser(resource, help=help_text)
        resource_parser.add_argument(
            "--vendor",
            required=True,
            help="Registered UFAYA vendor key, for example juniper_srx.",
        )
        resource_parser.add_argument(
            "--config",
            required=True,
            type=Path,
            help="Path to an offline vendor configuration file.",
        )
        resource_parser.add_argument(
            "--out",
            required=True,
            type=Path,
            help="Directory in which to write the JSON export.",
        )
        resource_parser.add_argument(
            "--mode",
            choices=VALID_EXPORT_MODES,
            default="enriched",
            help="Export detail level (default: enriched).",
        )

    return parser


def _validate_config_path(path: Path) -> None:
    if not path.exists():
        raise _CLIError(f"Configuration file does not exist: {path}")
    if not path.is_file():
        raise _CLIError(f"Configuration path is not a file: {path}")


def _run_export(args: argparse.Namespace) -> Path:
    config_path: Path = args.config
    _validate_config_path(config_path)

    driver = get_firewall_driver(args.vendor, config_path=config_path)
    with driver:
        if args.resource == "rules":
            if not isinstance(driver, _RulesJsonExporter):
                raise _CLIError(
                    f"Vendor '{args.vendor}' does not support "
                    "firewall-rule JSON export."
                )
            return driver.export_rules_json(args.out, mode=args.mode)

        if not isinstance(driver, NatReader):
            raise _CLIError(f"Vendor '{args.vendor}' does not support NAT reads.")
        if not isinstance(driver, _NatJsonExporter):
            raise _CLIError(
                f"Vendor '{args.vendor}' does not support NAT-rule JSON export."
            )
        return driver.export_nat_json(args.out, mode=args.mode)


def _exit_with_error(parser: argparse.ArgumentParser, message: str) -> NoReturn:
    parser.exit(1, f"{parser.prog}: error: {message}\n")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the UFAYA command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        output_path = _run_export(args)
    except (_CLIError, ImportError, OSError, ValueError) as exc:
        _exit_with_error(parser, str(exc))

    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
