"""Terminal output (FR-15), and the honesty rules it must not break.

Most of this file is about wording. That is not fussiness: FR-13 is a promise
about what the tool claims, and the text renderer is where the claim reaches a
human. "No cryptography present" and "none detected" are different statements,
and only one of them is something this tool can support.
"""

from pathlib import Path

from shorsighted.core.model import (
    AnalysisStatus,
    AssetType,
    Evidence,
    Finding,
    ScannedFile,
    ScanResult,
)
from shorsighted.output import text


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
                description="x",
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


def render(*files: ScannedFile) -> str:
    return text.render(ScanResult(files=files, tool_version="0.0.0", signature_version="deadbeef"))


# --- FR-13: what absence is allowed to mean -------------------------------


def test_a_clean_file_says_none_detected_not_no_cryptography() -> None:
    output = render(scanned())
    assert "none detected" in output
    assert "no cryptography" not in output.lower()


def test_every_render_carries_the_evidence_caveat() -> None:
    """The footer states the claim's limit whether or not anything was found,
    because a report gets screenshotted and forwarded without its context."""
    assert "evidence of presence, not proof of use" in render(scanned())


def test_a_packed_binary_says_absence_means_little() -> None:
    """FR-5. Reporting a clean result for a packed binary without saying so
    would be the single most misleading thing this tool could do."""
    output = render(scanned(status=AnalysisStatus.DEGRADED_PACKED))
    assert "packed" in output
    assert "none detected (see note above)" in output


def test_a_managed_assembly_explains_why_it_was_not_read() -> None:
    """FR-4: .NET cryptography lives in CLR metadata, and pretending to have
    scanned it would produce a systematically wrong 'clean' result."""
    output = render(scanned(status=AnalysisStatus.UNSUPPORTED_MANAGED))
    assert "CLR metadata" in output
    assert "none detected (see note above)" in output


def test_an_errored_file_reports_its_error_class() -> None:
    output = render(scanned(status=AnalysisStatus.ERROR, error_class="truncated"))
    assert "could not analyse: truncated" in output
    assert "none detected" not in output


# --- the table ------------------------------------------------------------


def test_quantum_broken_is_spelled_out_not_left_as_a_digit() -> None:
    """In a column of small integers, "0" reads like "least severe" when it
    means broken outright by Shor. The word does the work the number cannot."""
    output = render(scanned(findings=(finding(algorithm="RSA", nist_quantum_level=0),)))
    assert "0 BROKEN" in output


def test_unknown_quantum_level_is_not_invented() -> None:
    """MD5 is broken, but not in the way this field measures. Printing a number
    would misreport what the column means."""
    output = render(scanned(findings=(finding(algorithm="MD5", nist_quantum_level=None),)))
    assert "n/a" in output


def test_quantum_broken_findings_sort_first() -> None:
    output = render(
        scanned(
            findings=(
                finding(algorithm="AES", nist_quantum_level=1, confidence=0.99),
                finding(algorithm="RSA", nist_quantum_level=0, confidence=0.50),
            )
        )
    )
    assert output.index("RSA") < output.index("AES")


def test_evidence_column_names_the_signature_and_symbol() -> None:
    """US-3 again: the reader has to be able to check the claim."""
    output = render(scanned(findings=(finding(),)))
    assert "imports/openssl-aes" in output
    assert "AES_encrypt" in output


def test_extra_evidence_is_counted_not_dropped() -> None:
    many = finding(
        evidence=tuple(
            Evidence(detector="imports", signature_id="openssl-aes", description="x", symbol=s)
            for s in ("AES_encrypt", "AES_decrypt", "AES_cbc_encrypt")
        )
    )
    assert "(+2 more)" in render(scanned(findings=(many,)))


def test_offset_evidence_is_shown_when_there_is_no_symbol() -> None:
    string_hit = finding(
        evidence=(
            Evidence(
                detector="imports",
                signature_id="cng-alg-aes",
                description="x",
                offsets=(0x1234,),
            ),
        )
    )
    assert "@0x1234" in render(scanned(findings=(string_hit,)))


def test_a_family_only_finding_falls_back_to_the_family_name() -> None:
    output = render(scanned(findings=(finding(algorithm=None, family="CNG"),)))
    assert "CNG" in output


# --- footer ---------------------------------------------------------------


def test_footer_counts_files_errors_findings_and_broken() -> None:
    output = render(
        scanned(findings=(finding(nist_quantum_level=0),)),
        scanned(path=Path("b.exe"), status=AnalysisStatus.ERROR, error_class="not-pe"),
    )
    assert "2 file(s) scanned, 1 errored, 1 finding(s), 1 quantum-broken" in output


def test_footer_states_the_signature_version() -> None:
    """NFR-6: a result is only reproducible if you can tell which signature set
    produced it."""
    assert "signatures deadbeef" in render(scanned())


# --- NFR-4: it has to print on a Windows console --------------------------


def test_output_is_pure_ascii() -> None:
    """A legacy Windows codepage will mangle or refuse a U+2026, and nothing in
    a summary table is worth an encoding crash on someone else's machine."""
    output = render(
        scanned(findings=(finding(),)),
        scanned(path=Path("b.exe"), status=AnalysisStatus.ERROR, error_class="not-pe"),
        scanned(path=Path("c.exe"), status=AnalysisStatus.DEGRADED_PACKED),
    )
    output.encode("ascii")  # raises UnicodeEncodeError if this ever regresses


def test_rendering_is_deterministic() -> None:
    """NFR-6 wants byte-identical output for identical input, and a stable sort
    is free."""
    files = (scanned(findings=(finding(algorithm="AES"), finding(algorithm="RSA"))),)
    first = text.render(ScanResult(files=files, tool_version="1", signature_version="s"))
    second = text.render(ScanResult(files=files, tool_version="1", signature_version="s"))
    assert first == second
