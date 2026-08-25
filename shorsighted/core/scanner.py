"""Orchestrator: run one file through the pipeline, containing its errors.

Single files only in this slice. Directory walking, magic-byte filtering, trait
analysis, and per-file timeouts arrive in slice 7 — the shape here is the one
that walk will call per file, which is why error containment already lives at
this level rather than in the caller.
"""

from collections.abc import Sequence
from pathlib import Path

from shorsighted.core.merge import merge_findings, suppress_below
from shorsighted.core.model import AnalysisStatus, Finding, ScannedFile, ScanResult
from shorsighted.detectors import constants as constant_detector
from shorsighted.detectors import imports as import_detector
from shorsighted.detectors.base import Detector
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
                    status=AnalysisStatus.OK,
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
