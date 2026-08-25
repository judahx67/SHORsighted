"""Build minimal-but-valid PE32 / PE32+ images in pure Python (test-plan §3).

Real-world binaries are never committed to this repo: they are large, their
licensing is murky, and a repo full of crypto-bearing executables trips
antivirus on contributors' machines. Instead every fixture is synthesized here,
which has a nicer property than mere convenience — a test can build a file
carrying *exactly* the trait under test and nothing else, so when it fails
there is no third possibility to rule out.

Deviation from test-plan §3, worth knowing: the plan describes committing the
built files. These are built in-memory per test instead. Same determinism, no
`.exe` blobs in git, nothing to regenerate when the builder changes.

Nothing here validates its inputs, and nothing here should: this module exists
partly to produce *malformed* files, and a builder that refused to emit a bad
header would be useless for testing a defensive loader.
"""

import struct
from dataclasses import dataclass

DOS_HEADER_SIZE = 0x40
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664
MACHINE_ARM64 = 0xAA64

_OPTIONAL_HEADER_SIZE = {"x86": 224, "x64": 240}
_MAGIC = {"x86": 0x10B, "x64": 0x20B}
_THUNK_SIZE = {"x86": 4, "x64": 8}
_ORDINAL_FLAG = {"x86": 0x80000000, "x64": 0x8000000000000000}

CHARACTERISTICS_DLL = 0x2000

SCN_CODE = 0x60000020
"""Executable + readable + contains-code: what a real .text carries."""

SCN_RDATA = 0x40000040
"""Readable initialised data: what .rdata and .idata carry."""


@dataclass(frozen=True)
class SectionSpec:
    """A section to place in the image. `data` is written verbatim."""

    name: str
    data: bytes
    characteristics: int = SCN_RDATA


def _machine_word(machine: str, override: int | None) -> int:
    if override is not None:
        return override
    return MACHINE_I386 if machine == "x86" else MACHINE_AMD64


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def build_pe(
    *,
    machine: str = "x64",
    sections: tuple[SectionSpec, ...] = (),
    imports: tuple[tuple[str, tuple[str | int, ...]], ...] = (),
    is_dll: bool = False,
    machine_id: int | None = None,
    clr: bool = False,
) -> bytes:
    """Assemble a loadable PE image.

    `imports` is a tuple of (dll name, symbols), where a symbol is a `str` name
    or an `int` ordinal — ordinal-only imports are a real thing in the wild and
    the loader has to survive them.

    `machine_id` overrides the machine word without changing the layout, which
    is how a test produces an ARM64 file to check that unsupported machines are
    rejected rather than mislabelled.

    `clr` sets the COM descriptor data directory, making the result a managed
    assembly as far as FR-4 is concerned. The directory points at a plausible
    RVA and nothing parses it, which is exactly the level of detail the trait
    check needs.
    """
    if machine not in _MAGIC:
        raise ValueError(f"unknown machine {machine!r}")

    all_sections = list(sections)
    import_section_index = -1
    if imports:
        import_section_index = len(all_sections)
        all_sections.append(SectionSpec(".idata", b"", SCN_RDATA))

    headers_size = _align(
        DOS_HEADER_SIZE + 4 + 20 + _OPTIONAL_HEADER_SIZE[machine] + 40 * len(all_sections),
        FILE_ALIGNMENT,
    )

    # Lay the sections out first: the import directory has to know its own RVA
    # before its thunks can point anywhere.
    layout = []
    rva = SECTION_ALIGNMENT
    raw = headers_size
    for spec in all_sections:
        payload_size = _align(len(spec.data), FILE_ALIGNMENT)
        layout.append((rva, raw, payload_size))
        rva += _align(max(len(spec.data), 1), SECTION_ALIGNMENT)
        raw += payload_size

    import_rva = 0
    import_size = 0
    if imports:
        idata_rva, _, _ = layout[import_section_index]
        blob = _build_import_blob(imports, idata_rva, machine)
        all_sections[import_section_index] = SectionSpec(".idata", blob, SCN_RDATA)
        import_rva, import_size = idata_rva, len(blob)

        # The blob is bigger than the placeholder, so redo the layout it shifted.
        layout = []
        rva = SECTION_ALIGNMENT
        raw = headers_size
        for spec in all_sections:
            payload_size = _align(len(spec.data), FILE_ALIGNMENT)
            layout.append((rva, raw, payload_size))
            rva += _align(max(len(spec.data), 1), SECTION_ALIGNMENT)
            raw += payload_size

    size_of_image = _align(rva, SECTION_ALIGNMENT)

    dos = bytearray(DOS_HEADER_SIZE)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, DOS_HEADER_SIZE)

    characteristics = CHARACTERISTICS_DLL if is_dll else 0x0002  # EXECUTABLE_IMAGE
    file_header = struct.pack(
        "<HHIIIHH",
        _machine_word(machine, machine_id),
        len(all_sections),
        0,
        0,
        0,
        _OPTIONAL_HEADER_SIZE[machine],
        characteristics,
    )

    optional = _build_optional_header(
        machine=machine,
        size_of_image=size_of_image,
        size_of_headers=headers_size,
        import_rva=import_rva,
        import_size=import_size,
        clr=clr,
    )

    table = b"".join(
        struct.pack(
            "<8sIIIIIIHHI",
            spec.name.encode()[:8].ljust(8, b"\x00"),
            max(len(spec.data), 1),
            section_rva,
            payload_size,
            section_raw if payload_size else 0,
            0,
            0,
            0,
            0,
            spec.characteristics,
        )
        for spec, (section_rva, section_raw, payload_size) in zip(all_sections, layout, strict=True)
    )

    image = bytearray(bytes(dos) + b"PE\x00\x00" + file_header + optional + table)
    image.extend(b"\x00" * (headers_size - len(image)))

    for spec, (_, section_raw, payload_size) in zip(all_sections, layout, strict=True):
        image.extend(spec.data.ljust(payload_size, b"\x00"))
        assert len(image) == section_raw + payload_size, "section layout drifted"

    return bytes(image)


def _build_optional_header(
    *,
    machine: str,
    size_of_image: int,
    size_of_headers: int,
    import_rva: int,
    import_size: int,
    clr: bool = False,
) -> bytes:
    """The optional header, which is not optional."""
    if machine == "x86":
        head = struct.pack(
            "<HBBIIIIIIIII",
            _MAGIC["x86"],
            14,
            0,
            0x200,  # SizeOfCode
            0x200,  # SizeOfInitializedData
            0,
            SECTION_ALIGNMENT,  # AddressOfEntryPoint
            SECTION_ALIGNMENT,  # BaseOfCode
            SECTION_ALIGNMENT,  # BaseOfData (PE32 only)
            0x00400000,  # ImageBase
            SECTION_ALIGNMENT,
            FILE_ALIGNMENT,
        )
        tail_sizes = struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    else:
        head = struct.pack(
            "<HBBIIIIIQII",
            _MAGIC["x64"],
            14,
            0,
            0x200,
            0x200,
            0,
            SECTION_ALIGNMENT,
            SECTION_ALIGNMENT,
            0x0000000140000000,  # ImageBase (64-bit, no BaseOfData)
            SECTION_ALIGNMENT,
            FILE_ALIGNMENT,
        )
        tail_sizes = struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)

    middle = struct.pack(
        "<HHHHHHIIIIHH",
        6,
        0,  # OS version
        0,
        0,  # image version
        6,
        0,  # subsystem version
        0,  # Win32VersionValue
        size_of_image,
        size_of_headers,
        0,  # CheckSum
        3,  # Subsystem: CONSOLE
        0,  # DllCharacteristics
    )
    trailer = struct.pack("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes

    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 1 * 8, import_rva, import_size)
    if clr:
        struct.pack_into("<II", directories, 14 * 8, SECTION_ALIGNMENT, 0x48)

    return head + middle + tail_sizes + trailer + bytes(directories)


def _build_import_blob(
    imports: tuple[tuple[str, tuple[str | int, ...]], ...],
    base_rva: int,
    machine: str,
) -> bytes:
    """Lay out a complete import directory at `base_rva`.

    Both thunk arrays are emitted. A real linker writes the ILT and IAT with
    identical contents pre-load, and pefile will read whichever it finds, so
    emitting both keeps the fixture honest rather than merely parseable.
    """
    thunk_size = _THUNK_SIZE[machine]
    pack_thunk = "<I" if thunk_size == 4 else "<Q"
    ordinal_flag = _ORDINAL_FLAG[machine]

    descriptors_size = 20 * (len(imports) + 1)

    offset = descriptors_size
    ilt_offsets = []
    iat_offsets = []
    for _, symbols in imports:
        ilt_offsets.append(offset)
        offset += thunk_size * (len(symbols) + 1)
    for _, symbols in imports:
        iat_offsets.append(offset)
        offset += thunk_size * (len(symbols) + 1)

    hint_name_offsets: dict[tuple[int, int], int] = {}
    hint_name_blob = bytearray()
    for dll_index, (_, symbols) in enumerate(imports):
        for symbol_index, symbol in enumerate(symbols):
            if isinstance(symbol, int):
                continue
            hint_name_offsets[(dll_index, symbol_index)] = offset + len(hint_name_blob)
            entry = struct.pack("<H", 0) + symbol.encode() + b"\x00"
            if len(entry) % 2:
                entry += b"\x00"
            hint_name_blob.extend(entry)
    offset += len(hint_name_blob)

    dll_name_offsets = []
    dll_name_blob = bytearray()
    for name, _ in imports:
        dll_name_offsets.append(offset + len(dll_name_blob))
        encoded = name.encode() + b"\x00"
        if len(encoded) % 2:
            encoded += b"\x00"
        dll_name_blob.extend(encoded)

    def thunks(dll_index: int, symbols: tuple[str | int, ...]) -> bytes:
        out = bytearray()
        for symbol_index, symbol in enumerate(symbols):
            if isinstance(symbol, int):
                value = ordinal_flag | symbol
            else:
                value = base_rva + hint_name_offsets[(dll_index, symbol_index)]
            out.extend(struct.pack(pack_thunk, value))
        out.extend(struct.pack(pack_thunk, 0))  # terminator
        return bytes(out)

    descriptors = bytearray()
    for dll_index in range(len(imports)):
        descriptors.extend(
            struct.pack(
                "<IIIII",
                base_rva + ilt_offsets[dll_index],
                0,
                0,
                base_rva + dll_name_offsets[dll_index],
                base_rva + iat_offsets[dll_index],
            )
        )
    descriptors.extend(b"\x00" * 20)

    blob = bytearray(descriptors)
    for dll_index, (_, symbols) in enumerate(imports):
        blob.extend(thunks(dll_index, symbols))
    for dll_index, (_, symbols) in enumerate(imports):
        blob.extend(thunks(dll_index, symbols))
    blob.extend(hint_name_blob)
    blob.extend(dll_name_blob)
    return bytes(blob)


def minimal_pe(machine: str = "x64") -> bytes:
    """The smallest thing this package should agree to call a PE."""
    return build_pe(machine=machine, sections=(SectionSpec(".text", b"\xc3", SCN_CODE),))
