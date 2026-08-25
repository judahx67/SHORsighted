"""Heuristic detector: embedded cryptographic material (FR-8).

Two very different claims live in one detector, and the difference matters.

Structural detection — DER and PEM — is near-free precision (D-7). Nothing
accidentally contains `-----BEGIN CERTIFICATE-----`, and a DER structure that
survives a length-consistency check is a DER structure. These findings are
worth acting on.

Entropy detection is the opposite, and the module is honest about it: it cannot
tell an embedded AES key from a compressed resource, because at 32 bytes those
look identical. It ships anyway because FR-8 asks for it and NFR-5 requires it
be *measured* rather than quietly dropped — but at the lowest confidence class
in the project, capped, and never as an `algorithm`.

Nothing here ever emits `AssetType.ALGORITHM`. This detector claims material
exists; it does not claim the binary can perform an operation, and D-5 keeps
those evaluated separately so a weak heuristic cannot dilute a strong number.

Nothing here ever puts bytes in a finding either. Offsets only — a CBOM that
quotes key material is itself a leak (non-goal 9).
"""

from collections.abc import Sequence

from shorsighted.core.model import AssetType, Evidence, Finding
from shorsighted.detectors.base import register
from shorsighted.pe.loader import LoadedPE, Section
from shorsighted.signatures.schema import EntropySettings, MaterialSignature, SignatureSet

MAX_HITS_PER_MARKER = 8

MIN_DER_LENGTH = 64
"""Below this a DER SEQUENCE is too small to be a certificate or key, and small
sequences are common in ordinary binary data."""

PEM_CLAIM_BYTES = 2048
"""How much of a PEM block to treat as accounted for. A banner carries no
length, and a typical certificate body is well under this."""

_EXECUTABLE = 0x20000000


class HeuristicDetector:
    """Find embedded certificates, keys, and key-shaped regions."""

    name = "heuristics"

    def scan(self, pe: LoadedPE, signatures: SignatureSet) -> Sequence[Finding]:
        findings: list[Finding] = []
        claimed: list[tuple[int, int]] = []

        for signature in signatures.material:
            offsets = _match(pe, signature)
            if not offsets:
                continue
            # Claim the whole structure, not just its first bytes. A certificate
            # is full of exactly the near-uniform data the entropy heuristic
            # looks for, and reporting its insides again as "something
            # high-entropy" tells a reader nothing they did not just read.
            claimed.extend(
                (offset, offset + _claimed_length(pe, offset, signature)) for offset in offsets
            )
            findings.append(_material_finding(signature, offsets, signatures))

        if signatures.entropy.enabled:
            claimed.extend(_known_table_spans(pe, signatures))
            findings.extend(_entropy_findings(pe, signatures, claimed))
        return findings


def _known_table_spans(pe: LoadedPE, signatures: SignatureSet) -> list[tuple[int, int]]:
    """Regions occupied by constant tables this project already recognises.

    An AES S-box is a permutation of 0..255, so every window of it has the
    maximum possible distinct-byte count — it is the most key-shaped thing in
    the file, and without this the entropy heuristic reports it as "possible key
    material" at the same offset the constant detector reported it as AES. Two
    findings, one blob, one of them wrong.

    This reads signature *data*, never another detector's *findings*, so D-13's
    independence still holds: the constant detector's raw output is untouched
    and remains separately evaluable. The cost is a second pass over the same
    anchors, which the NFR-1 benchmark leaves ample room for.
    """
    data = pe.data
    spans = []
    for signature in signatures.constants:
        for pattern in signature.patterns:
            anchor = pattern[: signature.min_match]
            start = 0
            while True:
                found = data.find(anchor, start)
                if found == -1:
                    break
                spans.append((found, found + len(pattern)))
                start = found + 1
    return spans


def _claimed_length(pe: LoadedPE, offset: int, signature: MaterialSignature) -> int:
    """How many bytes this hit accounts for.

    For DER the declared SEQUENCE length is exact. For a PEM banner there is no
    length to read, so the base64 body is bounded generously - overshooting
    suppresses a little more than necessary, which is the harmless direction.
    """
    declared = _der_sequence_length(pe.data, offset)
    if declared is not None:
        return declared + 4
    return max(len(signature.marker), PEM_CLAIM_BYTES)


def _match(pe: LoadedPE, signature: MaterialSignature) -> tuple[int, ...]:
    data = pe.data
    offsets: list[int] = []
    start = 0
    while len(offsets) < MAX_HITS_PER_MARKER:
        found = data.find(signature.marker, start)
        if found == -1:
            break
        start = found + 1
        if signature.structure is None or _validate(data, found, signature.structure):
            offsets.append(found)
    return tuple(offsets)


def _validate(data: bytes | object, offset: int, structure: str) -> bool:
    """Confirm a DER hit really is the structure it was matched as.

    A bare `30 82` occurs constantly in ordinary binary data, so without this
    the DER markers would be a false-positive generator rather than a detector.
    """
    if structure == "x509-certificate":
        return _is_x509_certificate(data, offset)
    if structure == "rsa-private-key":
        return _is_rsa_private_key(data, offset)
    return False


def _der_sequence_length(data: bytes | object, offset: int) -> int | None:
    """Length of a `30 82 xx xx` SEQUENCE header, if it is plausible."""
    header = data[offset : offset + 4]  # type: ignore[index]
    if len(header) < 4 or header[0] != 0x30 or header[1] != 0x82:
        return None
    length = int.from_bytes(header[2:4], "big")
    return length if length >= MIN_DER_LENGTH else None


def _is_x509_certificate(data: bytes | object, offset: int) -> bool:
    """Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, ... } (RFC 5280).

    Three checks, cheap and in order of how often they eliminate a candidate:
    the outer SEQUENCE has a plausible length, an inner SEQUENCE follows
    immediately, and the inner one fits inside the outer. That last consistency
    check is what random data almost never satisfies.
    """
    outer = _der_sequence_length(data, offset)
    if outer is None:
        return False

    # A v3 certificate opens tbsCertificate with the explicit version tag
    # [0] { INTEGER 2 }, but v1 certificates omit it entirely, so its absence
    # cannot be disqualifying and the length consistency carries the decision.
    inner = _der_sequence_length(data, offset + 4)
    return inner is not None and inner < outer


def _is_rsa_private_key(data: bytes | object, offset: int) -> bool:
    """RSAPrivateKey ::= SEQUENCE { version INTEGER 0, modulus INTEGER, ... }.

    The version INTEGER is `02 01 00` immediately after the SEQUENCE header,
    followed by a large INTEGER for the modulus. Distinctive enough that a false
    positive would be remarkable.
    """
    if _der_sequence_length(data, offset) is None:
        return False
    body = data[offset + 4 : offset + 11]  # type: ignore[index]
    return len(body) == 7 and bytes(body[:3]) == b"\x02\x01\x00" and body[3] == 0x02


def _material_finding(
    signature: MaterialSignature,
    offsets: tuple[int, ...],
    signatures: SignatureSet,
) -> Finding:
    return Finding(
        asset_type=AssetType(signature.asset_type),
        algorithm=None,
        family=signature.family,
        confidence=signatures.confidence_for(signature.signature_class),
        evidence=(
            Evidence(
                detector=HeuristicDetector.name,
                signature_id=signature.id,
                description=signature.description or signature.id,
                offsets=offsets,
            ),
        ),
    )


def _entropy_findings(
    pe: LoadedPE,
    signatures: SignatureSet,
    claimed: list[tuple[int, int]],
) -> list[Finding]:
    """Fixed-size regions that look like they could hold a symmetric key.

    Restricted to non-executable sections: compiled code is high-entropy by the
    standards of prose but nowhere near uniform, and scanning `.text` would
    produce noise proportional to binary size.

    Regions already explained by a certificate or key marker are skipped. A DER
    certificate is full of exactly this kind of data, and reporting the same
    bytes twice — once as a certificate, once as "something high-entropy" — adds
    nothing a reader can use.
    """
    settings = signatures.entropy
    regions: list[int] = []

    for section in pe.sections:
        if section.characteristics & _EXECUTABLE or not section.raw_size:
            continue
        regions.extend(_high_entropy_offsets(section, settings, claimed))
        if len(regions) >= settings.max_regions:
            break

    regions = regions[: settings.max_regions]
    if not regions:
        return []

    return [
        Finding(
            asset_type=AssetType.RELATED_MATERIAL,
            family="unidentified",
            confidence=signatures.confidence_for("entropy-region"),
            evidence=(
                Evidence(
                    detector=HeuristicDetector.name,
                    signature_id="entropy-region",
                    description=(
                        f"{settings.window} bytes of near-uniform data; could be a "
                        f"symmetric key, could equally be compressed data"
                    ),
                    offsets=tuple(regions),
                ),
            ),
        )
    ]


def _high_entropy_offsets(
    section: Section,
    settings: EntropySettings,
    claimed: list[tuple[int, int]],
) -> list[int]:
    """Non-overlapping windows with almost every byte distinct.

    Stepping by the window rather than by one byte: a sliding scan would report
    the same blob thirty-two times, and the offsets are meant to point a reader
    at places to look rather than to map a region exhaustively.
    """
    data = section.data
    window = settings.window
    found = []
    for start in range(0, len(data) - window + 1, window):
        chunk = data[start : start + window]
        if len(set(chunk)) < settings.min_distinct:
            continue
        offset = section.raw_offset + start
        if any(low <= offset < high for low, high in claimed):
            continue
        found.append(offset)
        if len(found) >= settings.max_regions:
            break
    return found


DETECTOR = register(HeuristicDetector())
