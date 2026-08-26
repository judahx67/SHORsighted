"""CycloneDX output: conformance (AC-5), reproducibility (NFR-6), and honesty.

D-10 traded `cyclonedx-python-lib` away for a hand-rolled serializer, and the
thing bought with it was this file. Every document the suite can produce is
validated against the official 1.6 schema here; without that, the trade was a
bad one.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from shorsighted.core.model import (
    AnalysisStatus,
    AssetType,
    Evidence,
    Finding,
    ScannedFile,
    ScanResult,
)
from shorsighted.core.scanner import scan_paths
from shorsighted.output import cbom
from shorsighted.signatures.loader import load_signatures
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe

Validator = Callable[[dict[str, Any]], None]

GOLDEN = Path(__file__).parent / "golden" / "cng-sample.cbom.json"


def wide(*values: str) -> bytes:
    return b"".join((value + "\x00").encode("utf-16-le") for value in values)


CNG_IMAGE = build_pe(
    machine="x64",
    sections=(
        SectionSpec(".text", b"\xc3" * 64, SCN_CODE),
        SectionSpec(".rdata", wide("AES", "SHA256", "RSA")),
    ),
    imports=(
        ("bcrypt.dll", ("BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptSignHash")),
        ("kernel32.dll", ("ExitProcess",)),
    ),
)


def scan_image(tmp_path: Path, image: bytes, name: str = "sample.exe") -> ScanResult:
    target = tmp_path / name
    target.write_bytes(image)
    return scan_paths([target], load_signatures(), tool_version="0.1.0.test")


def finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "asset_type": AssetType.ALGORITHM,
        "algorithm": "AES",
        "family": "AES",
        "primitive": "block-cipher",
        "nist_quantum_level": 1,
        "confidence": 0.9,
        "evidence": (
            Evidence(
                detector="imports",
                signature_id="openssl-aes",
                description="imports AES_encrypt",
                symbol="AES_encrypt",
            ),
        ),
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def scanned(**overrides: object) -> ScannedFile:
    base: dict[str, object] = {
        "path": Path("app.exe"),
        "sha256": "a" * 64,
        "size": 4096,
        "machine": "x64",
        "status": AnalysisStatus.OK,
    }
    base.update(overrides)
    return ScannedFile(**base)  # type: ignore[arg-type]


def result_of(*files: ScannedFile) -> ScanResult:
    return ScanResult(files=files, tool_version="0.1.0.test", signature_version="deadbeefcafe")


# --- AC-5: conformance ----------------------------------------------------


def test_a_real_scan_produces_a_valid_cbom(tmp_path: Path, assert_valid_cbom: Validator) -> None:
    assert_valid_cbom(cbom.build(scan_image(tmp_path, CNG_IMAGE)))


@pytest.mark.parametrize(
    ("label", "files"),
    [
        ("empty-scan", ()),
        ("clean-file", (scanned(),)),
        ("with-findings", (scanned(findings=(finding(),)),)),
        (
            "errored-file",
            (scanned(sha256="", machine="", status=AnalysisStatus.ERROR, error_class="truncated"),),
        ),
        ("packed-file", (scanned(status=AnalysisStatus.DEGRADED_PACKED),)),
        ("managed-file", (scanned(status=AnalysisStatus.UNSUPPORTED_MANAGED),)),
        (
            "x86-file",
            (scanned(machine="x86", findings=(finding(),)),),
        ),
        (
            "no-quantum-level",
            (scanned(findings=(finding(algorithm="MD5", family="MD5", nist_quantum_level=None),)),),
        ),
        (
            "family-only",
            (scanned(findings=(finding(algorithm=None, family="CNG", primitive=None),)),),
        ),
        (
            "offset-evidence",
            (
                scanned(
                    findings=(
                        finding(
                            evidence=(
                                Evidence(
                                    detector="imports",
                                    signature_id="cng-alg-aes",
                                    description="UTF-16 literal",
                                    offsets=(0x400, 0x1200),
                                ),
                            )
                        ),
                    )
                ),
            ),
        ),
        (
            "with-oid",
            (scanned(findings=(finding(algorithm="SHA-256", oid="2.16.840.1.101.3.4.2.1"),)),),
        ),
        (
            "two-files",
            (scanned(), scanned(path=Path("sub/other.dll"), findings=(finding(),))),
        ),
    ],
)
def test_every_document_shape_validates(
    label: str, files: tuple[ScannedFile, ...], assert_valid_cbom: Validator
) -> None:
    """Each of these reaches a different branch of the serializer. AC-5 is only
    a real gate if the shapes it covers are the ones the tool can emit."""
    assert_valid_cbom(cbom.build(result_of(*files)))
    assert_valid_cbom(cbom.build(result_of(*files), reproducible=True))


# --- NFR-6: reproducibility -----------------------------------------------


def test_reproducible_omits_serial_number_and_timestamp() -> None:
    document = cbom.build(result_of(scanned()), reproducible=True)
    assert "serialNumber" not in document
    assert "timestamp" not in document["metadata"]  # type: ignore[operator]


def test_default_output_carries_serial_number_and_timestamp() -> None:
    """Both are useful provenance in normal use; they are dropped only when the
    caller has asked for byte-identical output."""
    document = cbom.build(result_of(scanned()))
    assert str(document["serialNumber"]).startswith("urn:uuid:")
    assert "timestamp" in document["metadata"]  # type: ignore[operator]


def test_two_reproducible_runs_are_byte_identical(tmp_path: Path) -> None:
    first = cbom.serialize(scan_image(tmp_path, CNG_IMAGE), reproducible=True)
    second = cbom.serialize(scan_image(tmp_path, CNG_IMAGE), reproducible=True)
    assert first == second


def test_findings_are_ordered_deterministically() -> None:
    """Sorting happens whether or not --reproducible was asked for: a diffable
    CBOM is worth having by default and costs nothing."""
    forward = cbom.build(
        result_of(scanned(findings=(finding(algorithm="AES"), finding(algorithm="RSA"))))
    )
    backward = cbom.build(
        result_of(scanned(findings=(finding(algorithm="RSA"), finding(algorithm="AES"))))
    )
    assert _names(forward) == _names(backward)


def _names(document: dict[str, Any]) -> list[str]:
    return [c["name"] for c in document["components"]]


# --- the golden file ------------------------------------------------------


def test_matches_the_golden_file(tmp_path: Path) -> None:
    """A byte-for-byte diff against committed expected output.

    Its job is to make silent output drift impossible: any change to the
    document shape shows up here as a diff a reviewer has to look at and
    approve, rather than as a field that quietly appeared or vanished.

    Regenerate deliberately, never reflexively:
        python -m tests.regenerate_golden
    """
    result = scan_image(tmp_path, CNG_IMAGE, name="cng-sample.exe")
    produced = cbom.serialize(_with_stable_path(result), reproducible=True)
    assert produced == GOLDEN.read_text(encoding="utf-8"), (
        "CBOM output drifted from the golden file. If the change is intended, "
        "run `python -m tests.regenerate_golden` and review the diff."
    )


def _with_stable_path(result: ScanResult) -> ScanResult:
    """Rewrite the tmp_path to a fixed name so the golden file is portable."""
    from dataclasses import replace

    return replace(
        result,
        files=tuple(replace(f, path=Path("fixtures/cng-sample.exe")) for f in result.files),
        scan_root="fixtures/cng-sample.exe",
    )


# --- honesty rules --------------------------------------------------------


def test_a_clean_file_still_appears_as_a_component() -> None:
    """FR-13: omitting files with no findings would let a reader infer they were
    never scanned, or worse, that they were clean."""
    document = cbom.build(result_of(scanned()))
    assert _names(document) == ["app.exe"]
    assert _property(document["components"][0], "analysis") == "ok"  # type: ignore[index]


def test_an_errored_file_carries_its_error_class_and_no_hash() -> None:
    document = cbom.build(
        result_of(scanned(sha256="", status=AnalysisStatus.ERROR, error_class="not-pe"))
    )
    component = document["components"][0]  # type: ignore[index]
    assert _property(component, "error-class") == "not-pe"
    assert "hashes" not in component


def test_unknown_fields_are_omitted_not_guessed() -> None:
    """The spec has slots for executionEnvironment and mode. Static analysis of
    a PE cannot establish either, and an omitted field reads as "not
    established" where a wrong one reads as fact."""
    document = cbom.build(result_of(scanned(findings=(finding(),))))
    properties = document["components"][1]["cryptoProperties"]["algorithmProperties"]  # type: ignore[index]
    assert "executionEnvironment" not in properties
    assert "mode" not in properties


def test_absent_quantum_level_is_omitted_rather_than_zeroed() -> None:
    """Level 0 means quantum-broken. Defaulting an unknown to 0 would libel
    every hash that simply has no category."""
    document = cbom.build(
        result_of(scanned(findings=(finding(algorithm="MD5", nist_quantum_level=None),)))
    )
    properties = document["components"][1]["cryptoProperties"]["algorithmProperties"]  # type: ignore[index]
    assert "nistQuantumSecurityLevel" not in properties


def test_evidence_carries_offsets_never_bytes(tmp_path: Path) -> None:
    """Non-goal 9. A CBOM that quotes key material is itself a leak, so the
    document must be describable entirely in offsets and names."""
    document = cbom.build(scan_image(tmp_path, CNG_IMAGE))
    serialized = json.dumps(document)
    for occurrence in _occurrences(document):
        assert set(occurrence) <= {"location", "offset", "symbol", "additionalContext"}
    assert "\\u0000" not in serialized


def test_confidence_travels_in_namespaced_properties() -> None:
    """Design §7: the spec's evidence-confidence fields are about component
    identity, which is a different question from how sure we are the algorithm
    is present."""
    document = cbom.build(result_of(scanned(findings=(finding(confidence=0.95),))))
    assert _property(document["components"][1], "confidence") == "0.95"  # type: ignore[index]
    assert _property(document["components"][1], "detectors") == "imports"  # type: ignore[index]


# --- structure ------------------------------------------------------------


def test_bom_refs_are_unique_even_for_repeated_families() -> None:
    """The spec requires unique bom-refs. Until merge lands in slice 6, an
    OpenSSL import and a CNG string both claiming AES can reach the serializer
    separately, and must not collide into an invalid document."""
    document = cbom.build(result_of(scanned(findings=(finding(), finding(confidence=0.7)))))
    refs = [c["bom-ref"] for c in cast("list[dict[str, Any]]", document["components"])]
    assert len(refs) == len(set(refs))


def test_dependencies_link_each_file_to_its_assets() -> None:
    document = cbom.build(result_of(scanned(findings=(finding(),))))
    dependency = document["dependencies"][0]  # type: ignore[index]
    assert dependency["ref"] == "file:app.exe"
    assert dependency["dependsOn"] == ["crypto:app.exe/aes"]


def test_a_file_with_no_findings_depends_on_nothing() -> None:
    document = cbom.build(result_of(scanned()))
    assert document["dependencies"][0]["dependsOn"] == []  # type: ignore[index]


def test_machine_maps_to_the_spec_platform_enum() -> None:
    for machine, expected in (("x86", "x86_32"), ("x64", "x86_64")):
        document = cbom.build(result_of(scanned(machine=machine, findings=(finding(),))))
        properties = document["components"][1]["cryptoProperties"]["algorithmProperties"]  # type: ignore[index]
        assert properties["implementationPlatform"] == expected


def test_serialize_ends_with_a_newline() -> None:
    """POSIX text files end in a newline, and a CBOM redirected to a file that
    does not will annoy every tool that reads it."""
    assert cbom.serialize(result_of(scanned())).endswith("}\n")


def _property(component: Any, name: str) -> str | None:
    for item in component.get("properties", []):
        if item["name"] == f"shorsighted:{name}":
            return str(item["value"])
    return None


def _occurrences(document: dict[str, Any]) -> list[dict[str, Any]]:
    components = cast("list[dict[str, Any]]", document["components"])
    return [
        occurrence
        for component in components
        for occurrence in component.get("evidence", {}).get("occurrences", [])
    ]
