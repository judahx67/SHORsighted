"""Orchestrator: walk paths, run the per-file pipeline, contain errors.

The contract that makes a directory scan usable is that one hostile file cannot
end it. Every failure is caught here and turned into a `ScannedFile` carrying an
error class, so a tree with a corrupt binary in it still produces a complete
CBOM for the other eight hundred (FR-1, FR-3).

Non-PE files are skipped by magic bytes rather than extension, because the
extension is the attacker's to choose and because a `.dat` that is really a DLL
is exactly the thing an inventory should not miss.
"""

from collections.abc import Iterator, Sequence
from pathlib import Path

from shorsighted.core.merge import merge_findings, suppress_below
from shorsighted.core.model import AnalysisStatus, Finding, ScannedFile, ScanResult
from shorsighted.detectors import constants as constant_detector
from shorsighted.detectors import imports as import_detector
from shorsighted.detectors.base import Detector
from shorsighted.pe import traits
from shorsighted.pe.loader import PEFormatError, load
from shorsighted.signatures.schema import SignatureSet

BUILTIN_DETECTORS: tuple[Detector, ...] = (
    import_detector.DETECTOR,
    constant_detector.DETECTOR,
)
"""The detectors a scan runs by default.

Listed explicitly rather than read from `base.REGISTRY` so that importing this
module is what populates the registry, instead of the registry quietly being
empty because nobody imported the detector that fills it. Heuristics join this
tuple in slice 8.
"""


def scan_file(
    path: Path,
    signatures: SignatureSet,
    detectors: Sequence[Detector] | None = None,
    min_confidence: float = 0.0,
) -> ScannedFile:
    """Analyse one file. Never raises for anything about the file's content.

    A file that cannot be parsed still comes back as a `ScannedFile`, carrying
    its error class — FR-3 and FR-13 both depend on that: the CBOM has to be
    able to say "we could not read this" rather than omitting the file and
    letting a reader infer it was clean.
    """
    chosen = list(BUILTIN_DETECTORS) if detectors is None else list(detectors)

    try:
        with load(path) as pe:
            findings: list[Finding] = []
            for detector in chosen:
                findings.extend(detector.scan(pe, signatures))
            merged = merge_findings(findings, signatures.corroboration_bonus)
            return suppress_below(
                ScannedFile(
                    path=path,
                    sha256=pe.sha256,
                    size=pe.size,
                    machine=pe.machine,
                    status=traits.analyse(pe),
                    findings=merged,
                ),
                min_confidence,
            )
    except PEFormatError as exc:
        return ScannedFile(
            path=path,
            sha256="",
            size=_size_or_zero(path),
            machine="",
            status=AnalysisStatus.ERROR,
            error_class=exc.error_class,
        )


def scan_paths(
    paths: Sequence[Path],
    signatures: SignatureSet,
    tool_version: str,
    detectors: Sequence[Detector] | None = None,
    min_confidence: float = 0.0,
) -> ScanResult:
    """Scan each path and collect the results into one report."""
    files = tuple(scan_file(path, signatures, detectors, min_confidence) for path in paths)
    return ScanResult(
        files=files,
        tool_version=tool_version,
        signature_version=signatures.version,
    )


def _size_or_zero(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


MZ_MAGIC = b"MZ"
"""FR-1 filters by magic bytes, never by extension.

An installer directory is full of `.dat`, `.bin`, and extensionless files that
are really PEs, and full of `.exe` files that are really something else. Reading
two bytes is cheap and correct; trusting the name is neither.
"""


def is_probably_pe(path: Path) -> bool:
    """Cheap pre-filter: does this file start with `MZ`?

    Deliberately weak. Anything that passes still goes through the full
    defensive loader, which is where a real decision is made - this only avoids
    mapping and parsing the thousands of PNGs and XML files in a typical tree.
    """
    try:
        with path.open("rb") as handle:
            return handle.read(2) == MZ_MAGIC
    except OSError:
        return False


def walk(root: Path) -> Iterator[Path]:
    """Yield candidate PE files under `root`, in a stable order.

    Sorted at every level so two scans of an unchanged tree produce identical
    output (NFR-6); directory iteration order is not guaranteed otherwise.

    Symlinks are not followed. A tree that links to itself would otherwise
    recurse until something gave way, and following a link out of the tree the
    user pointed at would scan files they did not ask about.
    """
    if root.is_file():
        yield root
        return

    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            # An unreadable directory is not a reason to abandon the scan.
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                stack.append(entry)
            elif entry.is_file():
                yield entry


def scan_tree(
    root: Path,
    signatures: SignatureSet,
    tool_version: str,
    detectors: Sequence[Detector] | None = None,
    min_confidence: float = 0.0,
) -> ScanResult:
    """Scan every PE under `root`, counting what was skipped (FR-1, US-2).

    The skipped count is metadata rather than a list on purpose: a directory of
    ten thousand assets would drown the CBOM, but "we looked at 40 files and
    ignored 9,960" is information the reader needs to judge the scan.
    """
    # A file the user named explicitly is never silently skipped. FR-1's quiet
    # skipping is for the thousands of assets in a tree nobody asked about; if
    # someone points at one file and it is not a PE, reporting nothing would
    # read as "scanned, clean" — which is the confusion FR-13 exists to prevent.
    explicit = root.is_file()

    files = []
    skipped = 0
    for path in walk(root):
        if not explicit and not is_probably_pe(path):
            skipped += 1
            continue
        files.append(scan_file(path, signatures, detectors, min_confidence))

    return ScanResult(
        files=tuple(files),
        skipped_non_pe=skipped,
        tool_version=tool_version,
        signature_version=signatures.version,
    )
