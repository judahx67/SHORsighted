"""File-level trait analysis: packing and managed code (FR-4, FR-5).

Both traits answer the same question — *can we see clearly into this file?* —
and both exist so the tool never reports a confident silence it has not earned.
A packed binary and a .NET assembly can each produce zero findings while being
stuffed with cryptography, and FR-13 says the difference between "we looked and
saw nothing" and "we could not look" has to reach the reader.

Thresholds here are heuristics with no ground truth behind them yet. They are
named constants rather than inline numbers precisely because slice 10's corpus
is expected to move them, and a magic number buried in a condition is a number
nobody re-tunes.
"""

from shorsighted.core.model import AnalysisStatus
from shorsighted.pe.loader import LoadedPE

CLR_DIRECTORY_INDEX = 14
"""IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR. Its presence is what makes a PE a
managed assembly."""

PACKED_ENTROPY = 7.2
"""Bits per byte above which an executable section looks compressed or
encrypted rather than compiled.

Native x86 code sits well below this — typically 6.0 to 6.8 — because opcodes
and operands are far from uniformly distributed. Compressed and encrypted data
approaches 8.0. The gap is wide, so 7.2 is comfortably inside it rather than
finely tuned, which is the right posture for a threshold no corpus has
challenged yet.
"""

MIN_IMPORTS = 8
"""Below this many imported symbols, a binary is suspiciously self-sufficient.

Packers resolve their real imports at runtime, so the visible import table
shrinks to the handful needed to bootstrap: LoadLibrary, GetProcAddress, and
little else. A genuinely tiny program can also land here, which is why this
alone is not enough to call something packed.
"""

KNOWN_PACKER_SECTIONS = frozenset(
    {
        "upx0",
        "upx1",
        "upx2",
        ".aspack",
        ".adata",
        "aspack",
        ".nsp0",
        ".nsp1",
        ".petite",
        "themida",
        ".themida",
        ".vmp0",
        ".vmp1",
        ".vmp2",
        "pelock",
        ".mpress1",
        ".mpress2",
        ".enigma1",
        ".boom",
    }
)
"""Section names packers leave behind. Cheap, high-precision, and easily
defeated by anyone who renames them — which is why it is one signal of three."""


def analyse(pe: LoadedPE) -> AnalysisStatus:
    """Classify what kind of look we got at this file.

    Order matters: managed is checked first because a .NET assembly's native
    section layout is uninformative, and calling it packed would misdescribe why
    the tool cannot see in.
    """
    if is_managed(pe):
        return AnalysisStatus.UNSUPPORTED_MANAGED
    if looks_packed(pe):
        return AnalysisStatus.DEGRADED_PACKED
    return AnalysisStatus.OK


def is_managed(pe: LoadedPE) -> bool:
    """True if the CLR header is present (FR-4).

    .NET cryptography lives in metadata references — `System.Security.
    Cryptography.Aes` — not in the import table and not as constant tables,
    because the BCL implements it elsewhere. Scanning a managed assembly with
    native detectors would therefore produce a systematically wrong "no
    cryptography found", which is why FR-4 makes it a reported status rather
    than a quiet zero.
    """
    return pe.clr_directory is not None


def looks_packed(pe: LoadedPE) -> bool:
    """True if the file shows the shape of a packed or protected binary (FR-5).

    Three independent signals, any of which is enough:

    - a known packer section name
    - high entropy in a section marked executable
    - almost no imports alongside an executable section that is mostly empty
      on disk but large in memory, which is the unpacking stub's signature

    Deliberately generous. A false "packed" costs a caveat in the report; a
    false "clean" on a packed binary costs the reader a wrong conclusion, and
    those are not symmetric.
    """
    if any(section.name.lower() in KNOWN_PACKER_SECTIONS for section in pe.sections):
        return True

    executable = [section for section in pe.sections if _is_executable(section.characteristics)]
    if any(section.raw_size > 0 and section.entropy >= PACKED_ENTROPY for section in executable):
        return True

    symbol_count = sum(len(dll.symbols) for dll in pe.imports)
    if symbol_count < MIN_IMPORTS:
        # A section that claims far more memory than it occupies on disk is
        # where a packer unpacks itself into.
        return any(
            section.virtual_size > max(section.raw_size * 4, 0x1000) for section in executable
        )
    return False


def _is_executable(characteristics: int) -> bool:
    return bool(characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
