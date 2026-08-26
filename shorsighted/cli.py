"""Command-line surface (FR-17). Argparse plumbing and exit codes; no analysis."""

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from shorsighted import __version__
from shorsighted.core.model import AnalysisStatus, ScanResult
from shorsighted.core.scanner import DEFAULT_TIMEOUT, scan_tree
from shorsighted.detectors.base import REGISTRY, Detector
from shorsighted.output import cbom, report, text
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
        help="PE file, or a directory to walk recursively",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text", "html"),
        default="json",
        help="json emits a CycloneDX 1.6 CBOM (the contract); text is a summary "
        "table with no stability guarantee; html is a printable evidence report "
        "(default: json)",
    )
    parser.add_argument(
        "--appendix-limit",
        type=int,
        default=report.APPENDIX_LIMIT,
        metavar="N",
        help="html only: list files with no detections individually up to N, then "
        f"give the count alone. Counts stay exact either way (default: {report.APPENDIX_LIMIT})",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="write to FILE instead of stdout",
    )
    parser.add_argument(
        "--detectors",
        metavar="LIST",
        help="comma-separated detectors to run, from: "
        + ",".join(sorted(REGISTRY))
        + " (default: all)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="X",
        help="drop findings below X (0.0-1.0). Applied after corroboration, so a "
        "finding two detectors agree on can rise above the threshold "
        "(default: 0.0, report everything)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help="give up on a single file after SECONDS and record it as errored; "
        f"0 disables (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--reproducible",
        action="store_true",
        help="omit the serial number and timestamp so identical input, tool and "
        "signature versions produce a byte-identical CBOM",
    )
    parser.add_argument("--version", action="version", version=f"shorsighted {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "render":
        return _render_existing(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.path is None:
        parser.print_help()
        return EXIT_OK

    if args.timeout < 0:
        print("shorsighted: --timeout cannot be negative", file=sys.stderr)
        return EXIT_USAGE

    if not 0.0 <= args.min_confidence <= 1.0:
        print(
            f"shorsighted: --min-confidence must be between 0.0 and 1.0, got {args.min_confidence}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    if not args.path.exists():
        print(f"shorsighted: no such file or directory: {args.path}", file=sys.stderr)
        return EXIT_USAGE

    try:
        detectors = _chosen_detectors(args.detectors)
    except KeyError as exc:
        known = ", ".join(sorted(REGISTRY))
        print(f"shorsighted: unknown detector {exc.args[0]!r} (known: {known})", file=sys.stderr)
        return EXIT_USAGE

    try:
        signatures = load_signatures()
    except SignatureError as exc:
        # Bundled data failed to validate: the install is broken, not the input.
        print(f"shorsighted: signature data is invalid: {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = scan_tree(
        args.path,
        signatures,
        tool_version=__version__,
        detectors=detectors,
        min_confidence=args.min_confidence,
        timeout=args.timeout,
    )
    rendered = _render(
        result,
        args.format,
        reproducible=args.reproducible,
        appendix_limit=args.appendix_limit,
    )

    if _emit(rendered, args.output) != EXIT_OK:
        return EXIT_USAGE

    errored = any(f.status is AnalysisStatus.ERROR for f in result.files)
    return EXIT_FILE_ERRORS if errored else EXIT_OK


def _render(
    result: ScanResult, output_format: str, *, reproducible: bool, appendix_limit: int
) -> str:
    if output_format == "json":
        return cbom.serialize(result, reproducible=reproducible)
    if output_format == "html":
        return report.render(
            cbom.serialize(result, reproducible=reproducible), appendix_limit=appendix_limit
        )
    return text.render(result) + "\n"


def _emit(rendered: str, output: Path | None) -> int:
    if output is None:
        print(rendered, end="")
        return EXIT_OK
    try:
        output.write_text(rendered, encoding="utf-8", newline="\n")
    except OSError as exc:
        print(f"shorsighted: cannot write {output}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def _render_existing(argv: Sequence[str]) -> int:
    """`shorsighted render <cbom.json>` — the CBOM-consumer path.

    A separate parser rather than argparse subcommands: subcommands would make
    the ordinary `shorsighted PATH` invocation a special case of something
    larger, and this is one verb, not the start of a verb family.
    """
    parser = argparse.ArgumentParser(
        prog="shorsighted render",
        description="Render an existing CycloneDX 1.6 document as a printable report.",
    )
    parser.add_argument("document", type=Path, help="a CycloneDX 1.6 JSON file")
    parser.add_argument("-o", "--output", type=Path, metavar="FILE", help="write to FILE")
    parser.add_argument("--appendix-limit", type=int, default=report.APPENDIX_LIMIT, metavar="N")
    args = parser.parse_args(argv)

    try:
        document = args.document.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"shorsighted: cannot read {args.document}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        rendered = report.render(document, appendix_limit=args.appendix_limit)
    except (ValueError, TypeError) as exc:
        # Someone else's document, so a parse failure is bad input, not a bug.
        print(f"shorsighted: {args.document} is not a usable CBOM: {exc}", file=sys.stderr)
        return EXIT_USAGE

    return _emit(rendered, args.output)


def _chosen_detectors(names: str | None) -> Sequence[Detector] | None:
    """Resolve `--detectors`, or None for "run everything".

    Selecting a subset is how the evaluation measures one detector at a time
    (NFR-5), and how a user who distrusts the heuristics turns them off without
    losing the rest.
    """
    if not names:
        return None
    return [REGISTRY[name.strip()] for name in names.split(",") if name.strip()]
