"""Command-line surface (FR-17). Argparse plumbing and exit codes; no analysis.

Single files only in this slice. `--format json`, directory walking,
`--min-confidence`, and `--detectors` arrive with the slices that give them
something to do.
"""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from shorsighted import __version__
from shorsighted.core.model import AnalysisStatus
from shorsighted.core.scanner import scan_paths
from shorsighted.output import text
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import SignatureError

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FILE_ERRORS = 2
"""FR-16. Exit 2 means the scan ran but at least one file could not be read —
distinct from exit 1, which means the scan itself never got going. CI callers
depend on being able to tell those apart."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shorsighted",
        description="Scan compiled Windows PE binaries and emit a CycloneDX 1.6 CBOM.",
        epilog=(
            "Findings are evidence of presence, never proof of use. "
            "No findings means none detected, not that a binary is free of cryptography."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        help="PE file to scan (directory scanning arrives in a later slice)",
    )
    parser.add_argument("--version", action="version", version=f"shorsighted {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.path is None:
        parser.print_help()
        return EXIT_OK

    if not args.path.is_file():
        print(f"shorsighted: not a file: {args.path}", file=sys.stderr)
        return EXIT_USAGE

    try:
        signatures = load_signatures()
    except SignatureError as exc:
        # Bundled data failed to validate: the install is broken, not the input.
        print(f"shorsighted: signature data is invalid: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = scan_paths([args.path], signatures, tool_version=__version__)
    print(text.render(result))

    errored = any(f.status is AnalysisStatus.ERROR for f in result.files)
    return EXIT_FILE_ERRORS if errored else EXIT_OK
