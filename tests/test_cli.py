"""CLI wiring and exit codes (FR-16, FR-17).

End-to-end through the real pipeline, on synthetic PEs built in memory. No
binary is fetched or read from the host system anywhere in this suite.
"""

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
    assert main([str(target)]) == EXIT_OK
    assert "none detected" in capsys.readouterr().out


def test_an_unreadable_file_exits_two_not_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """FR-16 distinguishes 'the scan never started' from 'the scan ran and some
    files failed'. CI callers act on that difference."""
    target = tmp_path / "junk.exe"
    target.write_bytes(b"this is not a PE file at all")
    assert main([str(target)]) == EXIT_FILE_ERRORS
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
    assert main([str(write_pe(tmp_path, "cng.exe", image))]) == EXIT_OK

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
    assert main([str(write_pe(tmp_path, "static.exe", image))]) == EXIT_OK
    assert "none detected" in capsys.readouterr().out
