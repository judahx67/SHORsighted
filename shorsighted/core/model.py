"""Shared datatypes for the whole pipeline (design §2).

This module is the bottom of the dependency graph: it imports nothing from its
siblings, and every other module imports it. The import-linter contract in
`.importlinter` enforces that.

Everything here is frozen and slotted. Findings flow forward through the
pipeline and are never mutated in place; all mutation lives at the edges
(loading bytes, writing output).
"""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class AssetType(StrEnum):
    """CycloneDX 1.6 `cryptoProperties.assetType`.

    The heuristic detector (FR-8) may only ever produce CERTIFICATE or
    RELATED_MATERIAL — it claims that *material* exists, which is a different
    kind of claim from "this algorithm is present", and is evaluated separately.
    """

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    RELATED_MATERIAL = "related-crypto-material"


class AnalysisStatus(StrEnum):
    """Per-file outcome, surfaced in the CBOM so absence is never read as innocence.

    DEGRADED_PACKED and UNSUPPORTED_MANAGED both mean "we could not see clearly
    here" — a scan that finds nothing in such a file has found nothing *about*
    that file, which is not the same as finding no cryptography (FR-13).
    """

    OK = "ok"
    DEGRADED_PACKED = "degraded-packed"
    UNSUPPORTED_MANAGED = "unsupported-managed"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Evidence:
    """Why a finding was reported.

    Detailed enough to defend the claim to a vendor who disputes it (US-3, FR-12).
    """

    detector: str
    """Stable detector id: "imports" | "constants" | "heuristics"."""

    signature_id: str
    """Signature that matched, e.g. "aes-sbox-fwd" — traces the claim back to a
    reviewable data file."""

    description: str
    """Human-readable one-liner, e.g. "matched BCryptEncrypt import"."""

    offsets: tuple[int, ...] = ()
    """File offsets of the match. Empty for import evidence, which comes from a
    parsed table rather than a located byte pattern."""

    symbol: str | None = None
    """Imported symbol name, when the evidence came from the import table."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One cryptographic asset detected in one file.

    Post-merge there is at most one Finding per (family-or-algorithm, file):
    multiple hits become multiple Evidence entries on the same Finding rather
    than duplicate components (D-14).
    """

    asset_type: AssetType

    algorithm: str | None = None
    """Canonical name from signature data, e.g. "AES-256-GCM". None when only a
    family could be established."""

    family: str | None = None
    """Merge key, e.g. "AES", "SHA-2", "RSA"."""

    primitive: str | None = None
    """CycloneDX primitive: "block-cipher", "hash", "signature", ..."""

    parameter_set: str | None = None
    """CycloneDX parameterSetIdentifier, e.g. "256", "P-256", "ML-KEM-768"."""

    oid: str | None = None

    nist_quantum_level: int | None = None
    """NIST category, from signature data and never hardcoded (FR-14).
    0 means quantum-broken: RSA, ECC, DH, DSA."""

    confidence: float = 0.0
    """[0, 1], sourced from confidence.toml and possibly raised by merge
    corroboration. Capped at 0.99 — we do not claim certainty about a binary we
    did not build."""

    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True, slots=True)
class ScannedFile:
    """One file the scan touched, findings or not.

    A file with no findings still appears in the CBOM, carrying its status so
    the reader can tell "we looked and saw nothing" from "we could not look".
    """

    path: Path
    sha256: str
    size: int

    machine: str
    """"x86" | "x64", or "" when the header could not be read."""

    status: AnalysisStatus

    error_class: str | None = None
    """Set only when status is ERROR — a short stable class such as
    "truncated-header", never a raw traceback."""

    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The whole scan. Serializers consume this and nothing else."""

    files: tuple[ScannedFile, ...] = ()

    skipped_non_pe: int = 0
    """Counted, not listed: FR-1 skips non-PE files silently, but the count
    belongs in scan metadata."""

    tool_version: str = ""

    signature_version: str = ""
    """Version/hash of the signature data directory. Required for NFR-6: same
    input + same tool + same signatures must reproduce a byte-identical CBOM."""

    errors: tuple[str, ...] = field(default_factory=tuple)
    """Scan-level problems (unreadable directory, etc). Per-file errors live on
    ScannedFile."""
