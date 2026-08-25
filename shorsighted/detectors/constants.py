"""Constant detector (FR-7) — the differentiator (D-6).

Statically linked cryptography imports nothing. An OpenSSL built into an
executable exposes no `libcrypto` in the import table, no symbols, no DLL name:
to the import detector it is indistinguishable from a binary that does no
cryptography at all. That is the common case in commercial Windows software,
and it is invisible to every existing CBOM tool because they read source.

What it cannot hide is its tables. AES needs an S-box, SHA-256 needs eight
initial hash values, and those bytes sit in `.rdata` whether or not anything is
imported. Finding them is the whole reason this project exists, which is why
this detector is treated as core rather than as a fallback.

Search strategy (design §5, D-12): one `bytes.find` per expanded pattern over
the file's mmap. Roughly thirty sequential C-speed scans per file, no index to
build, no native dependency. The documented upgrade path if the NFR-1 benchmark
disagrees is `pyahocorasick` behind an optional extra — a decision to be made
from measurements rather than in advance.
"""

from collections.abc import Sequence

from shorsighted.core.model import AssetType, Evidence, Finding
from shorsighted.detectors.base import register
from shorsighted.pe.loader import LoadedPE
from shorsighted.signatures.schema import ConstantSignature, SignatureSet

MAX_OCCURRENCES = 8
"""Offsets recorded per signature per file.

A table can legitimately appear several times — separate encrypt and decrypt
copies, a statically linked library included twice. After a handful of offsets a
reader has what they need to go and look, and the rest is CBOM weight.
"""


class ConstantDetector:
    """Scan raw file bytes for known cryptographic constant tables."""

    name = "constants"

    def scan(self, pe: LoadedPE, signatures: SignatureSet) -> Sequence[Finding]:
        suppressed: list[tuple[int, int]] = []
        candidates: list[tuple[ConstantSignature, tuple[int, ...], int]] = []

        for signature in signatures.constants:
            matches = _find_matches(pe, signature)
            if not matches:
                continue
            offsets, matched_length = matches
            if signature.suppresses:
                suppressed.extend((offset, offset + matched_length) for offset in offsets)
            else:
                candidates.append((signature, offsets, matched_length))

        findings = []
        for signature, offsets, matched_length in candidates:
            kept = tuple(
                offset
                for offset in offsets
                if not _overlaps(offset, offset + matched_length, suppressed)
            )
            if kept:
                findings.append(_finding(signature, kept, signatures))
        return findings


def _find_matches(pe: LoadedPE, signature: ConstantSignature) -> tuple[tuple[int, ...], int] | None:
    """Offsets of this signature in the file, plus how many bytes matched.

    Only the first `min_match` bytes are searched for. A compiler is free to
    split a table across sections, emit only the half its implementation uses,
    or reorder the tail; requiring the whole table would quietly lose those
    builds. The anchor is what survives, and the verified length is reported so
    a reader can see how much of the table was actually there.
    """
    data = pe.data
    for pattern in signature.patterns:
        anchor = pattern[: signature.min_match]
        offsets: list[int] = []
        start = 0
        while len(offsets) < MAX_OCCURRENCES:
            found = data.find(anchor, start)
            if found == -1:
                break
            offsets.append(found)
            start = found + 1
        if offsets:
            return tuple(offsets), _verified_length(data, offsets[0], pattern)
    return None


def _verified_length(data: bytes | object, offset: int, pattern: bytes) -> int:
    """How much of the full table is present at `offset`, at least `min_match`.

    Reported rather than required. "The first 64 bytes of the AES S-box are
    here" and "all 256 bytes are here" are different strengths of evidence, and
    flattening them would throw away something a reviewer wants.
    """
    tail = data[offset : offset + len(pattern)]  # type: ignore[index]
    if tail == pattern:
        return len(pattern)
    matched = 0
    for produced, expected in zip(tail, pattern, strict=False):
        if produced != expected:
            break
        matched += 1
    return matched


def _overlaps(start: int, end: int, spans: Sequence[tuple[int, int]]) -> bool:
    return any(start < span_end and span_start < end for span_start, span_end in spans)


def _finding(
    signature: ConstantSignature,
    offsets: tuple[int, ...],
    signatures: SignatureSet,
) -> Finding:
    full = len(signature.patterns[0])
    return Finding(
        asset_type=AssetType.ALGORITHM,
        algorithm=signature.algorithm,
        family=signature.family,
        primitive=signature.primitive,
        parameter_set=signature.parameter_set,
        oid=signature.oid,
        nist_quantum_level=signature.nist_quantum_level,
        confidence=signatures.confidence_for(signature.signature_class),
        evidence=(
            Evidence(
                detector=ConstantDetector.name,
                signature_id=signature.id,
                description=(
                    f"{signature.description or signature.id} "
                    f"({signature.min_match} of {full} bytes matched at anchor)"
                ),
                offsets=offsets,
            ),
        ),
    )


DETECTOR = register(ConstantDetector())
