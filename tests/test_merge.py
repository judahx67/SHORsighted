"""Merge stage (FR-10, design §6), table-driven.

Every rule in design §6 gets a case. The rules are small but each one is a
decision about what the tool claims, and getting one backwards would be
invisible in the output — a slightly wrong confidence, a slightly wrong label —
which is exactly the kind of bug that survives to a release.
"""

from pathlib import Path

import pytest

from shorsighted.core.merge import CONFIDENCE_CEILING, merge_findings, merge_result
from shorsighted.core.model import (
    AnalysisStatus,
    AssetType,
    Evidence,
    Finding,
    ScannedFile,
    ScanResult,
)

BONUS = 0.05


def evidence(detector: str = "imports", signature_id: str = "sig", **kwargs: object) -> Evidence:
    return Evidence(
        detector=detector,
        signature_id=signature_id,
        description=kwargs.pop("description", "seen"),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "asset_type": AssetType.ALGORITHM,
        "algorithm": "AES",
        "family": "AES",
        "primitive": "block-cipher",
        "nist_quantum_level": 1,
        "confidence": 0.9,
        "evidence": (evidence(),),
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


# --- the core rule --------------------------------------------------------


def test_two_detectors_on_one_family_become_one_finding() -> None:
    """FR-10. Separately these are two components claiming AES in one file,
    which is noise and an invalid CBOM besides."""
    merged = merge_findings(
        [
            finding(confidence=0.95, evidence=(evidence("imports", "openssl-aes"),)),
            finding(confidence=0.90, evidence=(evidence("constants", "aes-sbox-fwd"),)),
        ],
        BONUS,
    )
    assert len(merged) == 1
    assert {e.detector for e in merged[0].evidence} == {"imports", "constants"}


def test_corroborated_confidence_beats_either_source() -> None:
    """FR-10 requires confidence at least as high as either alone; independent
    agreement should actually raise it."""
    merged = merge_findings(
        [
            finding(confidence=0.80, evidence=(evidence("imports"),)),
            finding(confidence=0.90, evidence=(evidence("constants"),)),
        ],
        BONUS,
    )
    assert merged[0].confidence == pytest.approx(0.95)


def test_confidence_is_capped_below_certainty() -> None:
    """Never 1.0: this is static analysis of a binary we did not build."""
    merged = merge_findings(
        [
            finding(confidence=0.98, evidence=(evidence("imports"),)),
            finding(confidence=0.97, evidence=(evidence("constants"),)),
        ],
        0.5,
    )
    assert merged[0].confidence == CONFIDENCE_CEILING


def test_the_same_detector_twice_earns_no_bonus() -> None:
    """One kind of observation seen twice is not corroboration. Two constant
    tables from the same detector are correlated evidence, and treating them as
    independent would inflate every confidence in the report."""
    merged = merge_findings(
        [
            finding(confidence=0.90, evidence=(evidence("constants", "aes-sbox-fwd"),)),
            finding(confidence=0.90, evidence=(evidence("constants", "aes-te0"),)),
        ],
        BONUS,
    )
    assert merged[0].confidence == pytest.approx(0.90)
    assert len(merged[0].evidence) == 2


def test_a_lone_finding_passes_through_untouched() -> None:
    single = finding()
    assert merge_findings([single], BONUS) == (single,)


def test_different_families_do_not_merge() -> None:
    merged = merge_findings(
        [finding(algorithm="AES", family="AES"), finding(algorithm="RSA", family="RSA")],
        BONUS,
    )
    assert len(merged) == 2


# --- specificity ----------------------------------------------------------


def test_a_named_algorithm_subsumes_a_bare_family() -> None:
    """Design §6: "AES-256-GCM" tells a migration planner something "AES"
    does not."""
    merged = merge_findings(
        [
            finding(algorithm=None, family="AES", confidence=0.9, evidence=(evidence("c"),)),
            finding(
                algorithm="AES-256-GCM",
                family="AES",
                parameter_set="256",
                confidence=0.8,
                evidence=(evidence("i"),),
            ),
        ],
        BONUS,
    )
    assert merged[0].algorithm == "AES-256-GCM"
    assert merged[0].parameter_set == "256"


def test_fields_missing_from_the_winner_are_filled_from_the_group() -> None:
    """One detector often knows a field another does not. Dropping it would
    make the merged finding poorer than its parts."""
    merged = merge_findings(
        [
            finding(
                algorithm="ECDSA-P256",
                family="ECDSA",
                oid=None,
                primitive=None,
                confidence=0.9,
                evidence=(evidence("i"),),
            ),
            finding(
                algorithm=None,
                family="ECDSA",
                oid="1.2.840.10045.3.1.7",
                primitive="signature",
                confidence=0.7,
                evidence=(evidence("c"),),
            ),
        ],
        BONUS,
    )
    assert merged[0].algorithm == "ECDSA-P256"
    assert merged[0].oid == "1.2.840.10045.3.1.7"
    assert merged[0].primitive == "signature"


def test_the_most_alarming_quantum_level_wins() -> None:
    """Deliberately not an average or the winner's own value. If any evidence
    says a file holds something Shor breaks, that is the fact the planner needs,
    and a merge that could soften it would work against the tool's purpose."""
    merged = merge_findings(
        [
            finding(family="RSA", nist_quantum_level=0, confidence=0.7, evidence=(evidence("i"),)),
            finding(family="RSA", nist_quantum_level=3, confidence=0.9, evidence=(evidence("c"),)),
        ],
        BONUS,
    )
    assert merged[0].nist_quantum_level == 0


def test_an_absent_quantum_level_does_not_become_zero() -> None:
    """Level 0 means quantum-broken. Inventing it for MD5, whose weakness is
    classical, would be a false alarm in the column that matters most."""
    merged = merge_findings(
        [
            finding(family="MD5", nist_quantum_level=None, evidence=(evidence("i"),)),
            finding(family="MD5", nist_quantum_level=None, evidence=(evidence("c"),)),
        ],
        BONUS,
    )
    assert merged[0].nist_quantum_level is None


# --- asset types ----------------------------------------------------------


def test_an_algorithm_and_a_certificate_never_merge() -> None:
    """Different claims about different things. Collapsing them would be a lie
    of category rather than of degree."""
    merged = merge_findings(
        [
            finding(asset_type=AssetType.ALGORITHM, family="RSA"),
            finding(asset_type=AssetType.CERTIFICATE, family="RSA", algorithm=None),
        ],
        BONUS,
    )
    assert len(merged) == 2


# --- evidence -------------------------------------------------------------


def test_identical_evidence_is_not_repeated() -> None:
    duplicate = evidence("constants", "aes-sbox-fwd", offsets=(0x100,))
    merged = merge_findings([finding(evidence=(duplicate,)), finding(evidence=(duplicate,))], BONUS)
    assert len(merged[0].evidence) == 1


def test_evidence_order_is_stable() -> None:
    """NFR-6: identical input must produce identical output, and evidence order
    reaches the CBOM."""
    group = [
        finding(confidence=0.9, evidence=(evidence("constants", "aes-te0", offsets=(2,)),)),
        finding(confidence=0.9, evidence=(evidence("imports", "openssl-aes"),)),
    ]
    forward = merge_findings(group, BONUS)[0].evidence
    backward = merge_findings(list(reversed(group)), BONUS)[0].evidence
    assert forward == backward


def test_merging_preserves_every_offset() -> None:
    merged = merge_findings(
        [
            finding(evidence=(evidence("constants", "a", offsets=(1, 2)),)),
            finding(evidence=(evidence("imports", "b"),)),
        ],
        BONUS,
    )
    offsets = {o for e in merged[0].evidence for o in e.offsets}
    assert offsets == {1, 2}


# --- whole-result merging -------------------------------------------------


def test_merge_result_applies_per_file() -> None:
    scanned = ScannedFile(
        path=Path("a.exe"),
        sha256="a" * 64,
        size=1,
        machine="x64",
        status=AnalysisStatus.OK,
        findings=(
            finding(confidence=0.9, evidence=(evidence("imports"),)),
            finding(confidence=0.9, evidence=(evidence("constants"),)),
        ),
    )
    merged = merge_result(ScanResult(files=(scanned,)), BONUS)
    assert len(merged.files[0].findings) == 1


def test_merging_never_invents_a_finding() -> None:
    assert merge_findings([], BONUS) == ()
