"""The model carries claims about other people's binaries, so its guarantees
are worth asserting.

Frozen-ness is not style here: findings flow through detectors → merge →
output, and a mutable Finding would let a later stage silently rewrite the
evidence an earlier one recorded.
"""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from shorsighted.core.model import (
    AnalysisStatus,
    AssetType,
    Evidence,
    Finding,
    ScannedFile,
    ScanResult,
)


def test_findings_are_immutable() -> None:
    finding = Finding(asset_type=AssetType.ALGORITHM, family="AES", confidence=0.9)
    with pytest.raises(FrozenInstanceError):
        finding.confidence = 0.99  # type: ignore[misc]


def test_enums_serialize_as_their_cyclonedx_strings() -> None:
    """These values go straight into the CBOM, so the wire format is the test."""
    assert AssetType.RELATED_MATERIAL.value == "related-crypto-material"
    assert AnalysisStatus.UNSUPPORTED_MANAGED.value == "unsupported-managed"
    assert f"{AssetType.CERTIFICATE}" == "certificate"


def test_a_clean_file_is_still_a_scanned_file() -> None:
    """FR-13: "none detected" still needs a file component in the CBOM."""
    scanned = ScannedFile(
        path=Path("app.exe"),
        sha256="0" * 64,
        size=1024,
        machine="x64",
        status=AnalysisStatus.OK,
    )
    assert scanned.findings == ()
    assert scanned.error_class is None
    assert ScanResult(files=(scanned,)).skipped_non_pe == 0


def test_evidence_defaults_to_no_offsets() -> None:
    """Import evidence has no byte offset, and that is a legitimate state
    rather than a missing value."""
    evidence = Evidence(detector="imports", signature_id="cng-provider", description="x")
    assert evidence.offsets == ()
    assert evidence.symbol is None
