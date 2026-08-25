"""Deterministic PE mutation generator for the robustness suite (test-plan §6).

Takes a valid synthetic PE and damages it in the ways real files are damaged:
truncated downloads, corrupt section tables, headers that lie about their own
sizes, import directories that point in circles.

Seeded throughout. A fuzz failure nobody can reproduce is a bug report nobody
can act on, so every mutant is a pure function of (seed, index) and CI prints
the seed on failure.

The mutations are deliberately *structured* rather than uniformly random. Random
bytes almost never get past the DOS header, so a purely random fuzzer would
spend two thousand iterations re-testing the same three lines. These aim at the
fields a parser actually has to trust.
"""

import random
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe

BASE_IMPORTS = (
    ("bcrypt.dll", ("BCryptEncrypt", "BCryptCreateHash")),
    ("kernel32.dll", ("ExitProcess", "CreateFileW", "ReadFile")),
)


def base_image(machine: str = "x64") -> bytes:
    """A valid PE with enough structure that corrupting it reaches real code.

    Sections, an import directory with two DLLs, and a data section — a mutant
    of an empty file would only ever exercise the early rejections.
    """
    return build_pe(
        machine=machine,
        sections=(
            SectionSpec(".text", b"\x55\x8b\xec\x83\xec" * 100, SCN_CODE),
            SectionSpec(".rdata", bytes(range(256)) * 2),
        ),
        imports=BASE_IMPORTS,
    )


@dataclass(frozen=True)
class Mutant:
    """One damaged image, labelled with how it was damaged."""

    data: bytes
    kind: str
    seed: int

    def describe(self) -> str:
        return f"{self.kind} (seed {self.seed}, {len(self.data)} bytes)"


def _e_lfanew(image: bytes) -> int:
    return int(struct.unpack("<I", image[0x3C:0x40])[0])


def _section_table_offset(image: bytes) -> int:
    coff = _e_lfanew(image) + 4
    optional_size = int(struct.unpack("<H", image[coff + 16 : coff + 18])[0])
    return coff + 20 + optional_size


def truncate(image: bytes, rng: random.Random) -> bytes:
    """The most common real-world corruption: an interrupted copy."""
    return image[: rng.randrange(0, len(image))]


def flip_header_bytes(image: bytes, rng: random.Random) -> bytes:
    """Damage inside the headers, where every byte is load-bearing."""
    data = bytearray(image)
    headers_end = min(_section_table_offset(image) + 80, len(data))
    for _ in range(rng.randint(1, 6)):
        data[rng.randrange(0, headers_end)] = rng.randrange(0, 256)
    return bytes(data)


def corrupt_section_table(image: bytes, rng: random.Random) -> bytes:
    """Absurd offsets and sizes in the section table.

    The clamping in `pe/loader.py` exists for exactly this, so it is worth
    hitting hard: a header claiming a section at offset 0xFFFFFFF0 of length
    0xFFFFFFFF must not produce a read, an allocation, or a crash.
    """
    data = bytearray(image)
    table = _section_table_offset(image)
    field = rng.choice([8, 12, 16, 20])  # VirtualSize, VA, SizeOfRawData, PointerToRawData
    value = rng.choice([0xFFFFFFFF, 0xFFFFFFF0, 0x7FFFFFFF, 0, 1, 0x80000000])
    entry = table + 40 * rng.randint(0, 1)
    if entry + field + 4 <= len(data):
        struct.pack_into("<I", data, entry + field, value)
    return bytes(data)


def lie_about_section_count(image: bytes, rng: random.Random) -> bytes:
    """A NumberOfSections the file cannot possibly hold."""
    data = bytearray(image)
    struct.pack_into("<H", data, _e_lfanew(image) + 4 + 2, rng.choice([0, 0xFFFF, 0x1000, 200]))
    return bytes(data)


def lie_about_optional_header(image: bytes, rng: random.Random) -> bytes:
    """A SizeOfOptionalHeader that moves the section table somewhere absurd."""
    data = bytearray(image)
    struct.pack_into("<H", data, _e_lfanew(image) + 4 + 16, rng.choice([0, 1, 0xFFFF, 0x7FFF]))
    return bytes(data)


def overlap_sections(image: bytes, rng: random.Random) -> bytes:
    """Two sections claiming the same bytes — legal in the file format, and a
    classic way to confuse tools that assume otherwise."""
    data = bytearray(image)
    table = _section_table_offset(image)
    if table + 80 <= len(data):
        first_offset = struct.unpack("<I", data[table + 20 : table + 24])[0]
        struct.pack_into("<I", data, table + 40 + 20, int(first_offset))
    return bytes(data)


def corrupt_import_directory(image: bytes, rng: random.Random) -> bytes:
    """Point the import directory at itself, at nothing, or past the file.

    Import-table cycles are the classic way to hang a naive parser, and the
    reason NFR-2 asks for a timeout at all.
    """
    data = bytearray(image)
    coff = _e_lfanew(image) + 4
    optional_size = int(struct.unpack("<H", data[coff + 16 : coff + 18])[0])
    directories = coff + 20 + optional_size - 128
    if directories > 0 and directories + 16 <= len(data):
        struct.pack_into(
            "<II",
            data,
            directories + 8,  # data directory 1 = imports
            rng.choice([0, 1, 0xFFFFFFF0, directories, 0x1000]),
            rng.choice([0, 0xFFFFFFFF, 20, 0x1000]),
        )
    return bytes(data)


def corrupt_idata(image: bytes, rng: random.Random) -> bytes:
    """Scramble the import section itself: thunks, name RVAs, terminators."""
    data = bytearray(image)
    start = min(len(data) - 1, _section_table_offset(image) + 200)
    for _ in range(rng.randint(2, 12)):
        position = rng.randrange(start, len(data))
        data[position] = rng.randrange(0, 256)
    return bytes(data)


def lie_about_size_of_image(image: bytes, rng: random.Random) -> bytes:
    """A SizeOfImage in the gigabytes (NFR-1's memory ceiling)."""
    data = bytearray(image)
    coff = _e_lfanew(image) + 4
    struct.pack_into("<I", data, coff + 20 + 56, rng.choice([0xFFFFFFFF, 0x7FFFFFFF, 0]))
    return bytes(data)


MUTATIONS = {
    "truncate": truncate,
    "flip-header-bytes": flip_header_bytes,
    "corrupt-section-table": corrupt_section_table,
    "lie-about-section-count": lie_about_section_count,
    "lie-about-optional-header": lie_about_optional_header,
    "overlap-sections": overlap_sections,
    "corrupt-import-directory": corrupt_import_directory,
    "corrupt-idata": corrupt_idata,
    "lie-about-size-of-image": lie_about_size_of_image,
}


def generate(count: int, seed: int = 0) -> Iterator[Mutant]:
    """Yield `count` mutants, cycling through every mutation kind.

    Cycling rather than choosing randomly so a small run still covers every
    kind: a 200-mutant PR subset that happened to skip section-table corruption
    would be a gate with a hole in it.
    """
    kinds = sorted(MUTATIONS)
    images = {machine: base_image(machine) for machine in ("x86", "x64")}

    for index in range(count):
        rng = random.Random(seed * 1_000_003 + index)
        kind = kinds[index % len(kinds)]
        machine = "x64" if index % 2 else "x86"
        yield Mutant(
            data=MUTATIONS[kind](images[machine], rng),
            kind=kind,
            seed=seed * 1_000_003 + index,
        )
