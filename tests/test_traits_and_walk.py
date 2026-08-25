"""Trait analysis and directory walking (FR-1, FR-4, FR-5, AC-4).

Both features exist to protect the same promise: the tool must never report a
confident silence it has not earned. A packed binary, a managed assembly, and a
truncated file can each produce zero findings, and a reader has to be able to
tell those apart from a file that was genuinely examined and found clean.
"""

import os
from pathlib import Path

import pytest

from shorsighted.core.model import AnalysisStatus
from shorsighted.core.scanner import is_probably_pe, scan_tree, walk
from shorsighted.pe import traits
from shorsighted.pe.loader import PEFormatError, load_bytes
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import SignatureSet
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe
from tools.derive_constants import aes_sbox

ENOUGH_IMPORTS = (
    "ExitProcess",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "CloseHandle",
    "GetLastError",
    "HeapAlloc",
    "HeapFree",
    "ExitThread",
)


@pytest.fixture(scope="module")
def signatures() -> SignatureSet:
    return load_signatures()


def ordinary_pe(**kwargs: object) -> bytes:
    """A plain native binary: low-entropy code, a normal number of imports."""
    defaults: dict[str, object] = {
        "sections": (SectionSpec(".text", b"\x55\x8b\xec\x83\xec" * 200, SCN_CODE),),
        "imports": (("kernel32.dll", ENOUGH_IMPORTS),),
    }
    defaults.update(kwargs)
    return build_pe(**defaults)  # type: ignore[arg-type]


# --- FR-4: managed assemblies ---------------------------------------------


def test_a_clr_header_marks_a_file_unsupported_managed() -> None:
    """.NET cryptography lives in metadata references, not the import table.
    Running native detectors over it and reporting nothing would be
    systematically wrong rather than merely incomplete."""
    pe = load_bytes(ordinary_pe(clr=True))
    assert traits.is_managed(pe)
    assert traits.analyse(pe) is AnalysisStatus.UNSUPPORTED_MANAGED


def test_a_native_binary_is_not_managed() -> None:
    assert not traits.is_managed(load_bytes(ordinary_pe()))


def test_managed_is_checked_before_packed() -> None:
    """A managed assembly's native layout says nothing useful; calling it
    packed would misdescribe why the tool cannot see in."""
    pe = load_bytes(build_pe(sections=(SectionSpec("UPX1", b"\xc3" * 64, SCN_CODE),), clr=True))
    assert traits.analyse(pe) is AnalysisStatus.UNSUPPORTED_MANAGED


# --- FR-5: packing --------------------------------------------------------


@pytest.mark.parametrize("name", ["UPX1", "upx0", ".aspack", ".vmp0", ".themida"])
def test_known_packer_section_names_are_recognised(name: str) -> None:
    pe = load_bytes(build_pe(sections=(SectionSpec(name, b"\xc3" * 512, SCN_CODE),)))
    assert traits.looks_packed(pe)


def test_high_entropy_executable_section_looks_packed() -> None:
    """Compiled x86 sits around 6.0-6.8 bits per byte; compressed or encrypted
    data approaches 8.0. The gap is what this threshold lives in."""
    pe = load_bytes(
        build_pe(
            sections=(SectionSpec(".text", os.urandom(8192), SCN_CODE),),
            imports=(("kernel32.dll", ENOUGH_IMPORTS),),
        )
    )
    assert traits.looks_packed(pe)


def test_ordinary_code_is_not_packed() -> None:
    """The test that keeps the heuristic honest: repetitive real-looking
    instruction bytes with a normal import table must come back clean."""
    assert not traits.looks_packed(load_bytes(ordinary_pe()))


def test_high_entropy_in_a_data_section_is_not_packing() -> None:
    """An embedded certificate, a compressed resource, or a key blob lives in
    .rdata and is not evidence of packing. Only executable sections count."""
    pe = load_bytes(
        build_pe(
            sections=(
                SectionSpec(".text", b"\x55\x8b\xec" * 300, SCN_CODE),
                SectionSpec(".rdata", os.urandom(8192)),
            ),
            imports=(("kernel32.dll", ENOUGH_IMPORTS),),
        )
    )
    assert not traits.looks_packed(pe)


def test_a_stub_with_almost_no_imports_looks_packed() -> None:
    """Packers resolve imports at runtime, so the visible table shrinks to a
    bootstrap handful while a section claims far more memory than it occupies."""
    image = bytearray(build_pe(sections=(SectionSpec(".text", b"\xc3" * 512, SCN_CODE),)))
    # Inflate VirtualSize far beyond SizeOfRawData: where the packer unpacks to.
    import struct

    from tests.test_loader import _section_table_offset

    struct.pack_into("<I", image, _section_table_offset(bytes(image)) + 8, 0x100000)
    assert traits.looks_packed(load_bytes(bytes(image)))


def test_a_packed_file_is_still_scanned() -> None:
    """FR-5: packed binaries are flagged, not skipped. Whatever is visible is
    still worth reporting."""
    pe = load_bytes(
        build_pe(
            sections=(
                SectionSpec("UPX1", b"\xc3" * 512, SCN_CODE),
                SectionSpec(".rdata", aes_sbox()),
            )
        )
    )
    assert traits.analyse(pe) is AnalysisStatus.DEGRADED_PACKED
    assert pe.sections  # still parsed, still scannable


# --- truncation, which pefile is too forgiving about ----------------------


def test_a_pe_cut_off_mid_header_is_truncated_not_clean() -> None:
    """The bug this test exists for: pefile happily returns a parsed object with
    a plausible machine word and zero sections, which the pipeline would then
    report as a successfully scanned file with nothing in it — the single most
    misleading result the tool could produce."""
    with pytest.raises(PEFormatError) as exc:
        load_bytes(ordinary_pe()[:200])
    assert exc.value.error_class == "truncated"


@pytest.mark.parametrize("cut", [70, 100, 200, 300])
def test_headers_that_do_not_fit_are_refused(cut: int) -> None:
    with pytest.raises(PEFormatError) as exc:
        load_bytes(ordinary_pe()[:cut])
    assert exc.value.error_class == "truncated"


def test_a_complete_file_is_not_called_truncated() -> None:
    assert load_bytes(ordinary_pe()).machine == "x64"


# --- FR-1: walking and filtering ------------------------------------------


def test_non_pe_files_are_filtered_by_magic_bytes(tmp_path: Path) -> None:
    """Not by extension: an installer tree is full of `.dat` files that are
    really DLLs, and `.exe` files that are really something else."""
    (tmp_path / "real.dat").write_bytes(ordinary_pe())
    (tmp_path / "fake.exe").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    assert is_probably_pe(tmp_path / "real.dat")
    assert not is_probably_pe(tmp_path / "fake.exe")


def test_an_unreadable_file_is_not_a_pe(tmp_path: Path) -> None:
    assert not is_probably_pe(tmp_path / "absent.exe")


def test_walk_recurses_and_is_sorted(tmp_path: Path) -> None:
    """NFR-6: directory iteration order is not guaranteed, so two scans of an
    unchanged tree would otherwise differ."""
    (tmp_path / "b").mkdir()
    (tmp_path / "a").mkdir()
    for name in ("a/2.exe", "a/1.exe", "b/3.exe", "top.exe"):
        (tmp_path / name).write_bytes(b"MZ")

    first = [p.relative_to(tmp_path).as_posix() for p in walk(tmp_path)]
    second = [p.relative_to(tmp_path).as_posix() for p in walk(tmp_path)]
    assert first == second
    assert set(first) == {"a/1.exe", "a/2.exe", "b/3.exe", "top.exe"}


def test_walk_accepts_a_single_file(tmp_path: Path) -> None:
    target = tmp_path / "one.exe"
    target.write_bytes(b"MZ")
    assert list(walk(target)) == [target]


def test_walk_does_not_follow_symlinks(tmp_path: Path) -> None:
    """A tree that links to itself would otherwise recurse until something gave
    way, and a link out of the tree would scan files nobody asked about."""
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "a.exe").write_bytes(b"MZ")
    try:
        (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need privileges this machine does not grant")
    assert len(list(walk(tmp_path))) == 1


# --- AC-4 end to end ------------------------------------------------------


def test_a_mixed_tree_scan_reports_every_category(tmp_path: Path, signatures: SignatureSet) -> None:
    """AC-4: native PE, .NET assembly, non-PE junk, one malformed PE. The scan
    completes, produces one report, and classifies each correctly."""
    (tmp_path / "bin").mkdir()
    (tmp_path / "assets").mkdir()

    (tmp_path / "bin" / "app.exe").write_bytes(
        build_pe(
            sections=(
                SectionSpec(".text", b"\x55\x8b\xec" * 200, SCN_CODE),
                SectionSpec(".rdata", b"\x00" * 32 + aes_sbox()),
            ),
            imports=(("libcrypto-3-x64.dll", ("AES_encrypt", "RSA_sign")),),
        )
    )
    (tmp_path / "bin" / "plugin.dll").write_bytes(ordinary_pe(clr=True, is_dll=True))
    (tmp_path / "bin" / "packed.exe").write_bytes(
        build_pe(sections=(SectionSpec("UPX1", os.urandom(2048), SCN_CODE),))
    )
    (tmp_path / "bin" / "broken.exe").write_bytes(ordinary_pe()[:200])
    (tmp_path / "assets" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200)
    (tmp_path / "assets" / "notes.txt").write_text("not a binary")

    result = scan_tree(tmp_path, signatures, tool_version="test")

    by_name = {f.path.name: f for f in result.files}
    assert by_name["app.exe"].status is AnalysisStatus.OK
    assert by_name["plugin.dll"].status is AnalysisStatus.UNSUPPORTED_MANAGED
    assert by_name["packed.exe"].status is AnalysisStatus.DEGRADED_PACKED
    assert by_name["broken.exe"].status is AnalysisStatus.ERROR
    assert by_name["broken.exe"].error_class == "truncated"
    assert result.skipped_non_pe == 2

    families = {f.family for f in by_name["app.exe"].findings}
    assert {"AES", "RSA"} <= families


def test_a_malformed_file_does_not_end_the_scan(tmp_path: Path, signatures: SignatureSet) -> None:
    """FR-3. The whole point of error containment: eight hundred good files
    must survive one bad one."""
    (tmp_path / "broken.exe").write_bytes(b"MZ" + b"\x00" * 400)
    (tmp_path / "good.exe").write_bytes(ordinary_pe())

    result = scan_tree(tmp_path, signatures, tool_version="test")
    assert len(result.files) == 2
    assert {f.status for f in result.files} == {AnalysisStatus.ERROR, AnalysisStatus.OK}


def test_scanning_an_empty_directory_is_not_an_error(
    tmp_path: Path, signatures: SignatureSet
) -> None:
    result = scan_tree(tmp_path, signatures, tool_version="test")
    assert result.files == ()
    assert result.skipped_non_pe == 0


def test_managed_and_packed_files_produce_no_findings_but_are_reported(
    tmp_path: Path, signatures: SignatureSet
) -> None:
    """FR-4 and FR-13 together: no findings, and no implicit claim of cleanliness
    — the file is present in the report with its status attached."""
    (tmp_path / "plugin.dll").write_bytes(ordinary_pe(clr=True))
    result = scan_tree(tmp_path, signatures, tool_version="test")
    assert result.files[0].findings == ()
    assert result.files[0].status is AnalysisStatus.UNSUPPORTED_MANAGED
