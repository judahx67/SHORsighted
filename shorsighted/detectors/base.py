"""Detector protocol and registry (design §3, D-8).

Detectors are pure functions dressed as objects: given a loaded PE and a
signature set, return findings. No I/O, no globals, no reaching for another
detector's results. That last constraint is enforced by an import-linter
contract, and it is not tidiness — the evaluation reports per-detector
precision and recall (NFR-5), which requires each detector's *raw* independent
output. A detector that consulted another's findings would destroy the
measurement before it could be taken. Corroboration happens later, in
`core/merge.py` (D-13).

No entry-point plugin loading in v0.1 (D-8). The contributor extension surface
is signature data, not Python: third-party code loading in a security tool's
first release raises supply-chain questions this project is not ready to own.
The Protocol keeps the seam, so adding a loader later is a small change.
"""

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from shorsighted.core.model import Finding
from shorsighted.pe.loader import LoadedPE
from shorsighted.signatures.schema import SignatureSet


@runtime_checkable
class Detector(Protocol):
    """One source of evidence about one file."""

    name: str
    """Stable id. It appears in every Evidence record and in `--detectors`, so
    renaming one silently rewrites the meaning of published eval numbers."""

    def scan(self, pe: LoadedPE, signatures: SignatureSet) -> Sequence[Finding]:
        """Return findings, or an empty sequence. Must not raise."""
        ...


REGISTRY: dict[str, Detector] = {}
"""Built-in detectors by name, populated at import time by each module."""


def register(detector: Detector) -> Detector:
    """Add a detector to the registry, rejecting duplicate names.

    A silently overwritten detector would be a genuinely nasty bug: the scan
    would keep working and simply stop reporting a whole class of finding.
    """
    if detector.name in REGISTRY:
        raise ValueError(f"detector {detector.name!r} is already registered")
    REGISTRY[detector.name] = detector
    return detector
