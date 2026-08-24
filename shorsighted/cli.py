"""Command-line surface (FR-17). Argparse plumbing only — no logic lives here."""

import argparse
from collections.abc import Sequence

from shorsighted import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shorsighted",
        description="Scan compiled Windows PE binaries and emit a CycloneDX 1.6 CBOM.",
    )
    parser.add_argument("--version", action="version", version=f"shorsighted {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Return a process exit code (FR-16: 0 ok, 1 usage/IO, 2 per-file errors)."""
    build_parser().parse_args(argv)
    return 0
