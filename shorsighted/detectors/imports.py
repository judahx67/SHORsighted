"""Import-table detector (FR-6).

The highest-precision detector, and the one with the narrowest claim. An import
proves the binary is *linked against* an implementation. It does not prove the
code ever runs (FR-13), and for the Windows providers it does not even prove
which algorithm — `BCryptEncrypt` is the same symbol whether the caller wants
AES or RSA.

That is what the second half of this module is for. CNG's algorithm arrives at
runtime as a wide string, so the name survives in the binary as `L"AES"`.
Pairing a generic provider import with a UTF-16 literal is what lets this
detector say "AES" instead of "cryptography, somehow", and it is the reason
FR-6's precision target is reachable on Windows binaries at all.
"""

from collections.abc import Sequence
from fnmatch import fnmatchcase

from shorsighted.core.model import AssetType, Evidence, Finding
from shorsighted.detectors.base import register
from shorsighted.pe.loader import LoadedPE
from shorsighted.signatures.schema import (
    ImportSignature,
    SignatureSet,
    StringSignature,
)


class ImportDetector:
    """Match the import table, then the UTF-16 strings its providers unlock."""

    name = "imports"

    def scan(self, pe: LoadedPE, signatures: SignatureSet) -> Sequence[Finding]:
        findings: list[Finding] = []
        providers: set[str] = set()

        for signature in signatures.imports:
            matched = _matching_symbols(pe, signature)
            if not matched:
                continue
            if signature.provides:
                providers.add(signature.provides)
            findings.append(_finding_from_import(signature, matched, signatures))

        findings.extend(_scan_strings(pe, signatures, providers))
        return findings


def _matching_symbols(pe: LoadedPE, signature: ImportSignature) -> list[str]:
    """Every symbol of this signature present in the file, in signature order.

    DLL names are matched case-insensitively as globs: import tables disagree
    about case, and OpenSSL alone ships as `libcrypto-3-x64.dll`,
    `libcrypto-1_1.dll`, and `libeay32.dll` depending on vintage and packager.
    """
    wanted = {symbol.casefold(): symbol for symbol in signature.symbols}
    pattern = signature.dll.casefold()
    found: dict[str, None] = {}

    for dll in pe.imports:
        if not fnmatchcase(dll.name.casefold(), pattern):
            continue
        for symbol in dll.symbols:
            # Ordinal-only imports carry no name. Legitimate, and simply not
            # something this detector can match on.
            if symbol.name is None:
                continue
            canonical = wanted.get(symbol.name.casefold())
            if canonical is not None:
                found[canonical] = None

    return [symbol for symbol in signature.symbols if symbol in found]


def _finding_from_import(
    signature: ImportSignature,
    matched: list[str],
    signatures: SignatureSet,
) -> Finding:
    evidence = tuple(
        Evidence(
            detector=ImportDetector.name,
            signature_id=signature.id,
            description=f"imports {symbol} from {signature.dll}",
            symbol=symbol,
        )
        for symbol in matched
    )
    return Finding(
        asset_type=AssetType.ALGORITHM,
        algorithm=signature.algorithm,
        family=signature.family,
        primitive=signature.primitive,
        parameter_set=signature.parameter_set,
        oid=signature.oid,
        nist_quantum_level=signature.nist_quantum_level,
        confidence=signatures.confidence_for(signature.signature_class),
        evidence=evidence,
    )


def _scan_strings(
    pe: LoadedPE,
    signatures: SignatureSet,
    providers: set[str],
) -> list[Finding]:
    """Report UTF-16 algorithm names, but only for providers actually present.

    Design §4 gates these on a provider import rather than reporting them bare.
    The gate is doing real work: a UTF-16 "AES" appears in binaries that merely
    mention the word — a settings dialog, a cipher-suite log line — and
    reporting those as algorithm findings would put FR-6's 0.98 precision
    target out of reach for the sake of recall nobody asked for.
    """
    findings = []
    for signature in signatures.strings:
        if not providers.issuperset(signature.requires):
            continue
        offsets = _find_all(pe, signature)
        if not offsets:
            continue

        confidence = signatures.confidence_for(signature.signature_class)
        if signature.requires:
            # Corroborated by the provider import that unlocked it. Same-detector
            # promotion, so per-detector evaluation stays intact (D-13).
            confidence = min(0.99, confidence + signatures.corroboration_bonus)

        findings.append(
            Finding(
                asset_type=AssetType.ALGORITHM,
                algorithm=signature.algorithm,
                family=signature.family,
                primitive=signature.primitive,
                parameter_set=signature.parameter_set,
                oid=signature.oid,
                nist_quantum_level=signature.nist_quantum_level,
                confidence=confidence,
                evidence=(
                    Evidence(
                        detector=ImportDetector.name,
                        signature_id=signature.id,
                        description=(
                            f'UTF-16 literal "{signature.value}" with '
                            f"{'/'.join(sorted(signature.requires))} provider imported"
                        ),
                        offsets=offsets,
                    ),
                ),
            )
        )
    return findings


DISCARDABLE = 0x02000000
"""IMAGE_SCN_MEM_DISCARDABLE.

The loader may throw these sections away once the image is mapped, so nothing
in them is readable by the running program. `.reloc` and the `.debug_*` /
COFF-long-name sections carry it.
"""


def _find_all(pe: LoadedPE, signature: StringSignature, limit: int = 16) -> tuple[int, ...]:
    """Offsets of a null-terminated UTF-16LE literal, capped at `limit`.

    The terminator is part of the needle. Without it, "SHA1" matches inside
    "SHA1_HMAC" and "AES" is barely better than a coin flip; with it, the match
    is a whole wide-string literal, which is what a BCRYPT_*_ALGORITHM constant
    actually is.

    Discardable sections are skipped, and that is not a micro-optimisation. The
    slice 10 corpus found `L"DH"` - six bytes with its terminator - occurring by
    chance in DWARF debug data in *every* debug build, handing a false "this
    binary does Diffie-Hellman" to twenty-three otherwise correct samples. A CNG
    algorithm name is read at runtime by `BCryptOpenAlgorithmProvider`, so it
    cannot live in a section the loader is free to discard: a match there is a
    coincidence by construction. Restricting the search is what makes short
    algorithm names safe to ship as signatures at all.

    ponytail: a literal can still match as the tail of a longer one - "AES" and
    its terminator also end "USEAES". The corpus did not produce one, so it
    stays measured rather than pre-solved.
    """
    needle = (signature.value + "\x00").encode("utf-16-le")
    offsets: list[int] = []
    for section in pe.sections:
        if section.characteristics & DISCARDABLE or not section.raw_size:
            continue
        data = section.data
        cursor = 0
        while len(offsets) < limit:
            found = data.find(needle, cursor)
            if found == -1:
                break
            offsets.append(section.raw_offset + found)
            cursor = found + 2
        if len(offsets) >= limit:
            break
    return tuple(sorted(offsets))


DETECTOR = register(ImportDetector())
