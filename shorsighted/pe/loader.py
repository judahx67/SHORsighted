"""Defensive `pefile` wrapper producing a `LoadedPE` (FR-3, D-11).

This module is the only place in the package allowed to touch `pefile`. Every
byte it reads came from somewhere untrustworthy, so the contract is narrow and
absolute:

    loading a PE either yields a LoadedPE, or raises PEFormatError.

Nothing else escapes. Not `struct.error`, not `IndexError`, not `MemoryError`
from a header claiming a four-gigabyte section. A directory scan has to walk
past a hostile file without losing the other nine hundred (FR-1, NFR-2), and it
can only do that if failure here has exactly one shape.
"""

import hashlib
import mmap
import struct
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import cached_property
from math import log2
from pathlib import Path

import pefile

_DOS_HEADER_SIZE = 0x40
_E_LFANEW_OFFSET = 0x3C
_PE_SIGNATURE = b"PE\x00\x00"

_MACHINES = {0x014C: "x86", 0x8664: "x64"}

_IMAGE_FILE_DLL = 0x2000


class PEFormatError(Exception):
    """A file could not be understood as a PE.

    `error_class` is a short stable token — never a traceback, never a pefile
    message — because it lands in the CBOM as scan metadata and users will
    filter and count on it.
    """

    def __init__(self, error_class: str, detail: str = "") -> None:
        super().__init__(f"{error_class}: {detail}" if detail else error_class)
        self.error_class = error_class


@dataclass(frozen=True)
class Section:
    """One section header, plus lazy access to the bytes behind it."""

    name: str
    """Decoded and null-stripped. Section names are attacker-controlled: they
    may be empty, non-ASCII, or a lie about the content."""

    virtual_address: int
    virtual_size: int
    raw_offset: int

    raw_size: int
    """Clamped to the real end of file at load time, so slicing can never read
    past the buffer no matter what the header claimed."""

    characteristics: int

    _image: bytes | mmap.mmap = field(repr=False, compare=False)

    @cached_property
    def data(self) -> bytes:
        """The section's raw bytes. Copied on first access, then cached.

        ponytail: copies per inspected section, so a file whose sections are
        all examined costs roughly its own size again. Fine under NFR-1's
        512 MB ceiling for now; if slice 5's benchmark disagrees, hand
        detectors offsets into the parent buffer instead of slices.
        """
        return bytes(self._image[self.raw_offset : self.raw_offset + self.raw_size])

    @cached_property
    def entropy(self) -> float:
        """Shannon entropy over the section bytes, in bits per byte (0.0-8.0).

        Consumed by the packing heuristic (FR-5) and the key-region heuristic
        (FR-8), both of which arrive in later slices — hence lazy: most files
        never pay for it.
        """
        return shannon_entropy(self.data)


@dataclass(frozen=True)
class ImportedSymbol:
    """One entry in an import thunk array."""

    name: str | None
    """None for an ordinal-only import, which is a legitimate binary and not an
    error — it simply carries no symbol for the import detector to match on."""

    ordinal: int | None = None


@dataclass(frozen=True)
class ImportedDLL:
    name: str
    symbols: tuple[ImportedSymbol, ...] = ()


@dataclass(frozen=True)
class LoadedPE:
    """A parsed PE, and the input every detector receives.

    Deliberately plain data: no open `pefile.PE`, no file handle, no methods
    that re-parse. Once this exists the hostile-input problem is behind us, and
    detectors can be pure functions over ordinary Python values.
    """

    path: Path

    machine: str
    """"x86" or "x64" — FR-2's supported set. Anything else fails to load
    rather than being silently mislabelled."""

    is_dll: bool
    sections: tuple[Section, ...]
    imports: tuple[ImportedDLL, ...]

    _image: bytes | mmap.mmap = field(repr=False, compare=False)

    @property
    def data(self) -> bytes | mmap.mmap:
        """The whole file. The constant detector (slice 5) scans this directly,
        which is why it stays an mmap rather than being read into bytes."""
        return self._image

    @property
    def size(self) -> int:
        return len(self._image)

    @cached_property
    def sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(self._image)
        return digest.hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte, 0.0 for empty input.

    ponytail: 256 C-level passes via bytes.count, which beats any Python-level
    histogram loop and needs no numpy. Swap for a single-pass counter only if a
    benchmark shows it mattering.
    """
    length = len(data)
    if length == 0:
        return 0.0
    total = 0.0
    for byte in range(256):
        count = data.count(byte)
        if count:
            probability = count / length
            total -= probability * log2(probability)
    return total


def load_bytes(data: bytes | mmap.mmap, path: Path = Path("<memory>")) -> LoadedPE:
    """Parse an in-memory image. Raises `PEFormatError` and nothing else.

    Split out from `load` so tests — and the fuzz harness in slice 9 — can feed
    arbitrary bytes without touching the filesystem.
    """
    _reject_obvious_non_pe(data)

    try:
        parsed = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise PEFormatError("parse-failed", str(exc)) from exc
    except Exception as exc:  # see module docstring: nothing else escapes
        raise PEFormatError("parse-failed", type(exc).__name__) from exc

    try:
        machine = _MACHINES.get(int(parsed.FILE_HEADER.Machine))
        if machine is None:
            raise PEFormatError("unsupported-machine", hex(parsed.FILE_HEADER.Machine))
        is_dll = bool(int(parsed.FILE_HEADER.Characteristics) & _IMAGE_FILE_DLL)
        sections = _read_sections(parsed, data)
        imports = _read_imports(parsed)
    except PEFormatError:
        raise
    except Exception as exc:  # hostile headers may break anything
        raise PEFormatError("parse-failed", type(exc).__name__) from exc
    finally:
        parsed.close()

    return LoadedPE(
        path=path,
        machine=machine,
        is_dll=is_dll,
        sections=sections,
        imports=imports,
        _image=data,
    )


@contextmanager
def load(path: Path) -> Iterator[LoadedPE]:
    """Memory-map `path` and parse it, closing the mapping on the way out.

    A context manager because the mapping must outlive parsing (detectors scan
    it) but must not outlive the scan of this file — a directory walk holding
    one mapping open per file would breach NFR-1's memory ceiling on the first
    large tree.
    """
    try:
        handle = path.open("rb")
    except OSError as exc:
        raise PEFormatError("unreadable", type(exc).__name__) from exc

    with handle:
        try:
            image = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError as exc:
            # mmap refuses zero-length files; that is "empty", not a crash.
            raise PEFormatError("empty") from exc
        except OSError as exc:
            raise PEFormatError("unreadable", type(exc).__name__) from exc

        try:
            yield load_bytes(image, path)
        finally:
            image.close()


def _reject_obvious_non_pe(data: bytes | mmap.mmap) -> None:
    """Classify the cheap failures before pefile sees them.

    pefile reports "not a PE" and "truncated PE" through the same exception,
    but the distinction matters downstream: a non-PE is skipped silently and
    counted (FR-1), while a truncated PE is a reported per-file error (FR-3).
    """
    length = len(data)
    if length == 0:
        raise PEFormatError("empty")
    if data[:2] != b"MZ":
        raise PEFormatError("not-pe")
    if length < _DOS_HEADER_SIZE:
        raise PEFormatError("truncated", "shorter than a DOS header")

    (e_lfanew,) = struct.unpack("<I", data[_E_LFANEW_OFFSET : _E_LFANEW_OFFSET + 4])
    if e_lfanew + len(_PE_SIGNATURE) > length:
        raise PEFormatError("truncated", "PE header offset past end of file")
    if data[e_lfanew : e_lfanew + len(_PE_SIGNATURE)] != _PE_SIGNATURE:
        raise PEFormatError("not-pe")


def _read_sections(parsed: pefile.PE, data: bytes | mmap.mmap) -> tuple[Section, ...]:
    """Copy the section table out, clamping every range to the real file.

    A header is free to claim a section runs to offset 0xFFFFFFFF. Clamping
    here means no later stage has to remember to distrust these numbers.
    """
    length = len(data)
    sections = []
    for raw in parsed.sections:
        offset = min(int(raw.PointerToRawData), length)
        size = max(0, min(int(raw.SizeOfRawData), length - offset))
        sections.append(
            Section(
                name=raw.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                virtual_address=int(raw.VirtualAddress),
                virtual_size=int(raw.Misc_VirtualSize),
                raw_offset=offset,
                raw_size=size,
                characteristics=int(raw.Characteristics),
                _image=data,
            )
        )
    return tuple(sections)


def _read_imports(parsed: pefile.PE) -> tuple[ImportedDLL, ...]:
    """Parse the import directory only — not exports, relocs, or resources.

    Every extra directory is more attacker-reachable parsing for no benefit:
    FR-6 needs imports and nothing else.
    """
    parsed.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    entries = getattr(parsed, "DIRECTORY_ENTRY_IMPORT", None)
    if not entries:
        return ()

    dlls = []
    for entry in entries:
        symbols = tuple(
            ImportedSymbol(
                name=imp.name.decode("utf-8", errors="replace") if imp.name else None,
                ordinal=int(imp.ordinal) if imp.ordinal else None,
            )
            for imp in (entry.imports or ())
        )
        dlls.append(
            ImportedDLL(
                name=(entry.dll or b"").decode("utf-8", errors="replace"),
                symbols=symbols,
            )
        )
    return tuple(dlls)
