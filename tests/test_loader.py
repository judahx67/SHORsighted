"""Loader tests, weighted toward hostile input.

The happy path here is three assertions. The rest of the file is about files
that lie, because that is what the loader is actually for: a directory scan
that dies on one malformed binary has failed the eight hundred behind it.
"""

import contextlib
import struct
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from shorsighted.pe.loader import (
    LoadedPE,
    PEFormatError,
    load,
    load_bytes,
    shannon_entropy,
)
from tests.fixtures.build import MACHINE_ARM64, SCN_CODE, SectionSpec, build_pe, minimal_pe


def _section_table_offset(image: bytes) -> int:
    (e_lfanew,) = struct.unpack("<I", image[0x3C:0x40])
    (optional_size,) = struct.unpack("<H", image[e_lfanew + 4 + 16 : e_lfanew + 4 + 18])
    return int(e_lfanew) + 4 + 20 + int(optional_size)


# --- the happy path -------------------------------------------------------


@pytest.mark.parametrize("machine", ["x86", "x64"])
def test_loads_both_architectures(machine: str) -> None:
    """FR-2: PE32 and PE32+ are both first-class, not one plus a fallback."""
    pe = load_bytes(minimal_pe(machine))
    assert pe.machine == machine
    assert pe.is_dll is False


def test_reports_dll_characteristic() -> None:
    pe = load_bytes(build_pe(sections=(SectionSpec(".text", b"\xc3"),), is_dll=True))
    assert pe.is_dll is True


def test_sections_expose_their_bytes() -> None:
    payload = b"crypto goes here"
    pe = load_bytes(build_pe(sections=(SectionSpec(".rdata", payload),)))
    section = next(s for s in pe.sections if s.name == ".rdata")
    assert section.data.startswith(payload)
    assert section.virtual_address >= 0x1000


def test_imports_are_parsed_with_names_and_ordinals() -> None:
    """Ordinal-only imports carry no name. That is a legitimate binary, not an
    error, and the import detector simply has nothing to match on (test-plan §2)."""
    pe = load_bytes(
        build_pe(
            imports=(
                ("bcrypt.dll", ("BCryptEncrypt", "BCryptOpenAlgorithmProvider")),
                ("kernel32.dll", (12,)),
            )
        )
    )
    by_name = {dll.name: dll for dll in pe.imports}
    assert [s.name for s in by_name["bcrypt.dll"].symbols] == [
        "BCryptEncrypt",
        "BCryptOpenAlgorithmProvider",
    ]
    ordinal_only = by_name["kernel32.dll"].symbols[0]
    assert ordinal_only.name is None
    assert ordinal_only.ordinal == 12


def test_a_pe_without_imports_is_not_an_error() -> None:
    """Statically linked binaries are the whole reason this project exists —
    an empty import table is the normal case, not a failure (D-6)."""
    assert load_bytes(minimal_pe()).imports == ()


def test_sha256_matches_the_image() -> None:
    import hashlib

    image = minimal_pe()
    assert load_bytes(image).sha256 == hashlib.sha256(image).hexdigest()


# --- files that lie -------------------------------------------------------


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        (b"", "empty"),
        (b"not an executable at all", "not-pe"),
        (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56, "not-pe"),
        (b"MZ", "truncated"),
        (b"MZ" + b"\x00" * 40, "truncated"),
    ],
    ids=["empty", "plain-text", "elf", "mz-only", "short-dos-header"],
)
def test_obvious_non_pe_is_classified_not_crashed(image: bytes, expected: str) -> None:
    with pytest.raises(PEFormatError) as exc:
        load_bytes(image)
    assert exc.value.error_class == expected


def test_mz_with_garbage_pe_offset_is_truncated_not_crashed() -> None:
    image = bytearray(minimal_pe())
    struct.pack_into("<I", image, 0x3C, 0xFFFFFFF0)
    with pytest.raises(PEFormatError) as exc:
        load_bytes(bytes(image))
    assert exc.value.error_class == "truncated"


def test_mz_pointing_at_non_pe_signature_is_not_pe() -> None:
    image = bytearray(minimal_pe())
    image[0x40:0x44] = b"NE\x00\x00"  # a 16-bit binary, genuinely not our problem
    with pytest.raises(PEFormatError) as exc:
        load_bytes(bytes(image))
    assert exc.value.error_class == "not-pe"


def test_unsupported_machine_is_refused_rather_than_mislabelled() -> None:
    """FR-2 covers x86 and x64. An ARM64 binary must fail loudly: guessing
    "x86" here would put a wrong `implementationPlatform` in someone's CBOM."""
    image = build_pe(machine="x64", machine_id=MACHINE_ARM64)
    with pytest.raises(PEFormatError) as exc:
        load_bytes(image)
    assert exc.value.error_class == "unsupported-machine"


def test_absurd_section_size_is_clamped_to_the_file() -> None:
    """A header claiming a 4 GB section must not produce a 4 GB read (NFR-1)."""
    image = bytearray(build_pe(sections=(SectionSpec(".text", b"\xc3" * 32, SCN_CODE),)))
    struct.pack_into("<I", image, _section_table_offset(bytes(image)) + 16, 0xFFFFFFFF)

    pe = load_bytes(bytes(image))
    section = pe.sections[0]
    assert section.raw_offset + section.raw_size <= len(image)
    assert len(section.data) == section.raw_size


def test_section_offset_past_end_of_file_never_reads_outside_the_image() -> None:
    """pefile drops a section whose raw pointer is out of range rather than
    clamping it, so the observable result is zero sections. Either answer is
    fine; what must hold is that nothing describes bytes we do not have."""
    image = bytearray(build_pe(sections=(SectionSpec(".text", b"\xc3" * 32, SCN_CODE),)))
    struct.pack_into("<I", image, _section_table_offset(bytes(image)) + 20, 0xFFFFFFF0)

    pe = load_bytes(bytes(image))
    for section in pe.sections:
        assert section.raw_offset + section.raw_size <= len(image)
        assert len(section.data) == section.raw_size


@pytest.mark.parametrize("cut", [64, 128, 200, 336, 512, 1000])
def test_truncation_at_any_boundary_raises_only_pe_format_error(cut: int) -> None:
    """Truncation is the most common real-world corruption, and every cut point
    lands in a different parser. None of them may escape as another exception."""
    image = build_pe(
        sections=(SectionSpec(".text", b"\xc3" * 64, SCN_CODE),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    with contextlib.suppress(PEFormatError):  # the only acceptable failure
        load_bytes(image[:cut])


@settings(max_examples=200, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.binary(max_size=512))
def test_arbitrary_bytes_never_raise_anything_but_pe_format_error(data: bytes) -> None:
    """Test-plan §2's property: the loader has exactly one failure mode."""
    try:
        result = load_bytes(data)
    except PEFormatError:
        return
    assert isinstance(result, LoadedPE)


@settings(max_examples=100)
@given(st.integers(min_value=0, max_value=1535), st.integers(min_value=0, max_value=255))
def test_single_byte_corruption_never_escapes(offset: int, value: int) -> None:
    """Mutation fuzzing in miniature — the full harness lands in slice 9, but a
    valid PE with one byte rewritten is the cheapest way to reach deep parser
    paths that random bytes never will."""
    image = bytearray(
        build_pe(
            sections=(SectionSpec(".text", b"\xc3" * 64, SCN_CODE),),
            imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
        )
    )
    image[offset % len(image)] = value
    try:
        pe = load_bytes(bytes(image))
    except PEFormatError:
        return
    for section in pe.sections:  # force the lazy paths too
        assert len(section.data) == section.raw_size


# --- reading from disk ----------------------------------------------------


def test_load_from_path_maps_and_closes(tmp_path: Path) -> None:
    target = tmp_path / "sample.exe"
    target.write_bytes(minimal_pe())

    with load(target) as pe:
        assert pe.machine == "x64"
        assert pe.path == target
        assert pe.size == target.stat().st_size

    # The mapping is closed on exit; touching it now must fail rather than
    # quietly read freed memory.
    with pytest.raises(ValueError):
        _ = pe.data[0:1]


def test_empty_file_on_disk_is_empty_not_a_crash(tmp_path: Path) -> None:
    target = tmp_path / "nothing.exe"
    target.write_bytes(b"")
    with pytest.raises(PEFormatError) as exc, load(target):
        pass
    assert exc.value.error_class == "empty"


def test_missing_file_is_unreadable(tmp_path: Path) -> None:
    with pytest.raises(PEFormatError) as exc, load(tmp_path / "absent.exe"):
        pass
    assert exc.value.error_class == "unreadable"


# --- entropy --------------------------------------------------------------


def test_entropy_of_uniform_bytes_is_zero() -> None:
    assert shannon_entropy(b"\x00" * 4096) == 0.0


def test_entropy_of_every_byte_value_is_eight() -> None:
    """The maximum: a flat distribution over all 256 values."""
    assert shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)


def test_entropy_of_empty_input_is_zero_not_an_error() -> None:
    assert shannon_entropy(b"") == 0.0


def test_section_entropy_is_computed_from_section_bytes() -> None:
    pe = load_bytes(build_pe(sections=(SectionSpec(".rdata", bytes(range(256)) * 2),)))
    section = pe.sections[0]
    assert section.entropy == pytest.approx(shannon_entropy(section.data))


# --- the promise itself ---------------------------------------------------


def test_unexpected_pefile_exception_becomes_pe_format_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pefile raises more than `PEFormatError` on hostile input — `struct.error`,
    `IndexError`, `MemoryError`. The module docstring promises none of them
    escape, so the promise gets a test rather than a comment."""
    import pefile

    def explode(*args: object, **kwargs: object) -> object:
        raise MemoryError("a header claimed four gigabytes")

    monkeypatch.setattr(pefile, "PE", explode)
    with pytest.raises(PEFormatError) as exc:
        load_bytes(minimal_pe())
    assert exc.value.error_class == "parse-failed"
    assert "MemoryError" in str(exc.value)


def test_failure_after_parsing_also_becomes_pe_format_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second guard: headers parse, then reading the import directory walks
    off a cliff. Same single failure shape."""
    from shorsighted.pe import loader as loader_module

    def explode(_parsed: object) -> object:
        raise IndexError("thunk array runs past the section")

    monkeypatch.setattr(loader_module, "_read_imports", explode)
    with pytest.raises(PEFormatError) as exc:
        load_bytes(minimal_pe())
    assert exc.value.error_class == "parse-failed"
    assert "IndexError" in str(exc.value)
