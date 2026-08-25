"""CLI wiring and exit codes (FR-16, FR-17).

End-to-end through the real pipeline, on synthetic PEs built in memory. No
binary is fetched or read from the host system anywhere in this suite.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shorsighted import __version__
from shorsighted.cli import EXIT_FILE_ERRORS, EXIT_OK, EXIT_USAGE, main
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe


def wide(*values: str) -> bytes:
    return b"".join((value + "\x00").encode("utf-16-le") for value in values)


def write_pe(tmp_path: Path, name: str, image: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(image)
    return target


# --- the basics -----------------------------------------------------------


def test_version_flag_prints_version_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == EXIT_OK
    assert __version__ in capsys.readouterr().out


def test_no_arguments_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == EXIT_OK
    assert "usage:" in capsys.readouterr().out


def test_module_entry_point_runs() -> None:
    """`python -m shorsighted` must work, not only the console script."""
    result = subprocess.run(
        [sys.executable, "-m", "shorsighted", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == EXIT_OK
    assert __version__ in result.stdout


# --- exit codes (FR-16) ---------------------------------------------------


def test_missing_path_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "nope.exe")]) == EXIT_USAGE
    assert "not a file" in capsys.readouterr().err


def test_a_clean_scan_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = write_pe(
        tmp_path, "clean.exe", build_pe(sections=(SectionSpec(".text", b"\xc3", SCN_CODE),))
    )
    assert main([str(target), "--format", "text"]) == EXIT_OK
    assert "none detected" in capsys.readouterr().out


def test_an_unreadable_file_exits_two_not_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """FR-16 distinguishes 'the scan never started' from 'the scan ran and some
    files failed'. CI callers act on that difference."""
    target = tmp_path / "junk.exe"
    target.write_bytes(b"this is not a PE file at all")
    assert main([str(target), "--format", "text"]) == EXIT_FILE_ERRORS
    assert "could not analyse: not-pe" in capsys.readouterr().out


# --- the slice 3 milestone ------------------------------------------------


def test_a_synthetic_cng_binary_reports_its_algorithms(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The AC-1 shape, end to end through the CLI: provider imports plus the
    wide-string algorithm identifiers a BCrypt caller carries.

    Deliberately synthetic. The handoff's milestone names a real CNG binary,
    and that check belongs in the corpus (slice 10) where ground truth is exact
    by construction — not in a unit suite that would then depend on a binary
    nobody else has.
    """
    image = build_pe(
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
    assert main([str(write_pe(tmp_path, "cng.exe", image)), "--format", "text"]) == EXIT_OK

    output = capsys.readouterr().out
    for expected in ("AES", "SHA-256", "RSA", "0 BROKEN", "block-cipher", "hash"):
        assert expected in output, f"{expected!r} missing from output"
    assert "1 quantum-broken" in output


def test_a_statically_linked_shape_is_not_yet_detected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Honest negative, kept as a test so the gap stays visible.

    A binary with AES constants and no crypto imports is exactly AC-2's case,
    and the import detector cannot see it by design. This passes today by
    finding nothing; when the constant detector lands in slice 5, it should
    start failing and be rewritten as a positive.
    """
    image = build_pe(
        sections=(SectionSpec(".rdata", bytes(range(256))),),
        imports=(("kernel32.dll", ("ExitProcess",)),),
    )
    assert main([str(write_pe(tmp_path, "static.exe", image)), "--format", "text"]) == EXIT_OK
    assert "none detected" in capsys.readouterr().out


# --- output formats and destinations (FR-11, FR-15, NFR-6) ----------------


def test_json_is_the_default_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """FR-11: the CBOM is the contract, so it is what you get without asking.
    The text table is the opt-in convenience."""
    target = write_pe(
        tmp_path, "clean.exe", build_pe(sections=(SectionSpec(".text", b"\xc3", SCN_CODE),))
    )
    assert main([str(target)]) == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"


def test_output_flag_writes_to_a_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = write_pe(tmp_path, "clean.exe", build_pe())
    destination = tmp_path / "out" / "bom.json"
    destination.parent.mkdir()

    assert main([str(target), "--output", str(destination)]) == EXIT_OK
    assert capsys.readouterr().out == ""
    assert json.loads(destination.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


def test_unwritable_output_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A path that cannot be written is the caller's mistake, not the binary's,
    so it is exit 1 rather than exit 2."""
    target = write_pe(tmp_path, "clean.exe", build_pe())
    assert main([str(target), "--output", str(tmp_path / "no" / "such" / "dir.json")]) == EXIT_USAGE
    assert "cannot write" in capsys.readouterr().err


def test_reproducible_output_is_byte_identical_across_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """NFR-6, end to end through the CLI rather than only in the serializer."""
    target = write_pe(tmp_path, "clean.exe", build_pe())
    main([str(target), "--reproducible"])
    first = capsys.readouterr().out
    main([str(target), "--reproducible"])
    assert capsys.readouterr().out == first
    assert "serialNumber" not in first


def test_default_json_carries_a_serial_number(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = write_pe(tmp_path, "clean.exe", build_pe())
    main([str(target)])
    assert "urn:uuid:" in capsys.readouterr().out


def test_cli_json_validates_against_the_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], assert_valid_cbom: object
) -> None:
    """AC-5 applies to what the CLI actually prints, not only to what the
    serializer returns in-process."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES", "RSA")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    main([str(write_pe(tmp_path, "cng.exe", image))])
    assert_valid_cbom(json.loads(capsys.readouterr().out))  # type: ignore[operator]


def test_output_has_a_short_flag(tmp_path: Path) -> None:
    """The README documents `-o`, so the README gets a test."""
    target = write_pe(tmp_path, "clean.exe", build_pe())
    destination = tmp_path / "bom.json"
    assert main([str(target), "-o", str(destination)]) == EXIT_OK
    assert json.loads(destination.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


# --- corroboration and filtering (FR-10, FR-12, US-4) ---------------------


def test_two_detectors_agreeing_produce_one_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """FR-10 end to end: an OpenSSL AES import and an AES S-box in the same
    file are two observations of one fact, and must be reported as one."""
    from tools.derive_constants import aes_sbox

    image = build_pe(
        machine="x64",
        sections=(
            SectionSpec(".text", b"\x90" * 64, SCN_CODE),
            SectionSpec(".rdata", b"\x00" * 32 + aes_sbox()),
        ),
        imports=(("libcrypto-3-x64.dll", ("AES_encrypt",)),),
    )
    assert main([str(write_pe(tmp_path, "both.exe", image))]) == EXIT_OK

    document = json.loads(capsys.readouterr().out)
    aes = [c for c in document["components"] if c["name"] == "AES"]
    assert len(aes) == 1, "AES should appear once, not once per detector"
    detectors = next(
        p["value"] for p in aes[0]["properties"] if p["name"] == "shorsighted:detectors"
    )
    assert detectors == "constants,imports"


def test_min_confidence_filters_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """US-4: a report for management keeps only high-precision findings."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES", "RSA")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    target = write_pe(tmp_path, "cng.exe", image)

    main([str(target), "--format", "text"])
    everything = capsys.readouterr().out
    main([str(target), "--format", "text", "--min-confidence", "0.85"])
    filtered = capsys.readouterr().out

    assert "AES" in everything
    assert "AES" not in filtered  # a 0.75 utf16-string finding
    assert "CNG" in filtered  # the 0.90 provider import survives


@pytest.mark.parametrize("value", ["-0.1", "1.5", "2"])
def test_min_confidence_outside_zero_to_one_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    target = write_pe(tmp_path, "clean.exe", build_pe())
    assert main([str(target), "--min-confidence", value]) == EXIT_USAGE
    assert "between 0.0 and 1.0" in capsys.readouterr().err


def test_filtering_happens_after_corroboration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Order matters: filtering first would discard the very evidence that
    would have raised a finding above the threshold."""
    from tools.derive_constants import aes_sbox

    image = build_pe(
        machine="x64",
        sections=(SectionSpec(".rdata", b"\x00" * 32 + aes_sbox()),),
        imports=(("libcrypto-3-x64.dll", ("AES_encrypt",)),),
    )
    target = write_pe(tmp_path, "both.exe", image)
    # Neither detector alone reaches 0.96; corroborated, AES does.
    assert main([str(target), "--format", "text", "--min-confidence", "0.96"]) == EXIT_OK
    assert "AES" in capsys.readouterr().out
