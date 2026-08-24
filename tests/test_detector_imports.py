"""Import detector (FR-6), tested against synthetic import tables.

Every fixture here is built in memory. No real binary is fetched, opened, or
scanned anywhere in this suite — a test that needed one would be a test nobody
could rerun on a clean machine, and test-plan §2 specifies synthetic tables for
exactly that reason.
"""

import pytest

from shorsighted.core.model import AssetType
from shorsighted.detectors.base import REGISTRY, Detector, register
from shorsighted.detectors.imports import DETECTOR
from shorsighted.pe.loader import load_bytes
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import (
    ImportSignature,
    SignatureSet,
    StringSignature,
)
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe


@pytest.fixture(scope="module")
def signatures() -> SignatureSet:
    return load_signatures()


def wide(*values: str) -> bytes:
    """The wide-string literals a CNG caller carries, terminators included."""
    return b"".join((value + "\x00").encode("utf-16-le") for value in values)


def scan(image: bytes, signatures: SignatureSet) -> dict[str, float]:
    """Findings as {family or algorithm: confidence}, which is what the
    assertions below actually care about."""
    findings = DETECTOR.scan(load_bytes(image), signatures)
    return {(f.algorithm or f.family or "?"): f.confidence for f in findings}


# --- matching the import table --------------------------------------------


def test_openssl_symbol_names_its_algorithm(signatures: SignatureSet) -> None:
    """AC-2's neighbour: a symbol like EVP_aes_256_gcm can only mean AES, so
    the finding is specific rather than a provider shrug."""
    found = scan(build_pe(imports=(("libcrypto-3-x64.dll", ("EVP_aes_256_gcm",)),)), signatures)
    assert found["AES"] == pytest.approx(0.95)


@pytest.mark.parametrize(
    "dll",
    ["libcrypto-3-x64.dll", "libcrypto-1_1.dll", "LIBCRYPTO-3-X64.DLL", "libcrypto.dll"],
)
def test_dll_globs_are_case_insensitive(signatures: SignatureSet, dll: str) -> None:
    """OpenSSL ships under several names and import tables disagree about case.
    Missing a binary over capitalisation would be a silent recall bug."""
    assert "AES" in scan(build_pe(imports=((dll, ("AES_encrypt",)),)), signatures)


def test_wrong_dll_does_not_match(signatures: SignatureSet) -> None:
    """The symbol alone is not enough: AES_encrypt exported by something that
    is not an OpenSSL build is a different claim."""
    assert scan(build_pe(imports=(("mystery.dll", ("AES_encrypt",)),)), signatures) == {}


def test_ordinal_only_imports_do_not_crash_or_match(signatures: SignatureSet) -> None:
    """Test-plan §2. An ordinal import carries no name, which is legitimate and
    simply not something this detector can act on."""
    assert scan(build_pe(imports=(("libcrypto-3-x64.dll", (7, 12)),)), signatures) == {}


def test_a_binary_with_no_crypto_imports_yields_nothing(signatures: SignatureSet) -> None:
    image = build_pe(
        sections=(SectionSpec(".text", b"\xc3" * 64, SCN_CODE),),
        imports=(("kernel32.dll", ("ExitProcess", "CreateFileW")),),
    )
    assert scan(image, signatures) == {}


def test_evidence_names_the_symbol_that_matched(signatures: SignatureSet) -> None:
    """US-3: a planner has to be able to defend a finding to a vendor, which
    means the report must say precisely what was seen."""
    findings = DETECTOR.scan(
        load_bytes(build_pe(imports=(("libcrypto-3-x64.dll", ("RSA_sign",)),))), signatures
    )
    evidence = findings[0].evidence[0]
    assert evidence.detector == "imports"
    assert evidence.signature_id == "openssl-rsa"
    assert evidence.symbol == "RSA_sign"
    assert "libcrypto" in evidence.description


def test_rsa_import_is_reported_quantum_broken(signatures: SignatureSet) -> None:
    findings = DETECTOR.scan(
        load_bytes(build_pe(imports=(("libcrypto-3-x64.dll", ("RSA_sign",)),))), signatures
    )
    assert findings[0].nist_quantum_level == 0
    assert findings[0].asset_type is AssetType.ALGORITHM


# --- the CNG corroboration rule (design §4) -------------------------------


def test_cng_import_alone_claims_the_provider_not_an_algorithm(
    signatures: SignatureSet,
) -> None:
    """BCryptEncrypt is the same symbol whether the caller wants AES or RSA.
    Claiming an algorithm here would be a fabrication."""
    found = scan(build_pe(imports=(("bcrypt.dll", ("BCryptEncrypt",)),)), signatures)
    assert found == {"CNG": pytest.approx(0.90)}


def test_utf16_string_without_a_provider_import_is_not_reported(
    signatures: SignatureSet,
) -> None:
    """The precision gate. A binary that merely contains the wide string "AES"
    — a settings dialog, a log line — is not a binary that does AES."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES", "SHA256", "RSA")),),
        imports=(("kernel32.dll", ("ExitProcess",)),),
    )
    assert scan(image, signatures) == {}


def test_provider_plus_string_names_the_algorithm(signatures: SignatureSet) -> None:
    """The rule that makes this detector useful on Windows: the import proves
    CNG, the string names what CNG was asked for."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES", "SHA256", "RSA")),),
        imports=(("bcrypt.dll", ("BCryptOpenAlgorithmProvider", "BCryptEncrypt")),),
    )
    found = scan(image, signatures)
    assert {"AES", "SHA-256", "RSA", "CNG"} <= set(found)
    # Promoted above the bare utf16-string class by the corroborating import.
    assert found["AES"] == pytest.approx(0.75)
    assert found["AES"] > signatures.confidence_for("utf16-string")


def test_ac1_shape_reports_correct_quantum_levels(signatures: SignatureSet) -> None:
    """AC-1 in miniature, on a synthetic stand-in: AES-GCM, SHA-256 and RSA via
    CNG must come back at levels 1, 2 and 0."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES", "SHA256", "RSA")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt", "BCryptCreateHash", "BCryptSignHash")),),
    )
    levels = {
        (f.algorithm or f.family): f.nist_quantum_level
        for f in DETECTOR.scan(load_bytes(image), signatures)
    }
    assert levels["AES"] == 1
    assert levels["SHA-256"] == 2
    assert levels["RSA"] == 0


def test_string_match_requires_the_null_terminator(signatures: SignatureSet) -> None:
    """Without the terminator, "SHA1" fires inside "SHA1_PRF" and a three-letter
    value like "AES" is close to a coin flip."""
    image = build_pe(
        sections=(SectionSpec(".rdata", "AESKEY".encode("utf-16-le")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    assert scan(image, signatures) == {"CNG": pytest.approx(0.90)}


def test_string_offsets_are_recorded(signatures: SignatureSet) -> None:
    """FR-12: offsets are what let a reader go and look for themselves."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    aes = next(f for f in DETECTOR.scan(load_bytes(image), signatures) if f.algorithm == "AES")
    offset = aes.evidence[0].offsets[0]
    assert image[offset : offset + 8] == wide("AES")


def test_repeated_strings_collect_multiple_offsets(signatures: SignatureSet) -> None:
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES") + b"\x00" * 16 + wide("AES")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    aes = next(f for f in DETECTOR.scan(load_bytes(image), signatures) if f.algorithm == "AES")
    assert len(aes.evidence[0].offsets) == 2


def test_capi_provider_unlocks_the_same_strings(signatures: SignatureSet) -> None:
    """advapi32 supplies the 'capi' token; the CNG strings require 'cng', so a
    CryptoAPI-only binary must not inherit them."""
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES")),),
        imports=(("advapi32.dll", ("CryptCreateHash",)),),
    )
    assert scan(image, signatures) == {"CryptoAPI": pytest.approx(0.90)}


# --- the registry ---------------------------------------------------------


def test_the_import_detector_satisfies_the_protocol() -> None:
    assert isinstance(DETECTOR, Detector)
    assert REGISTRY["imports"] is DETECTOR


def test_registering_a_duplicate_name_is_refused() -> None:
    """A silently overwritten detector would keep the scan working while
    quietly dropping a whole class of finding."""
    with pytest.raises(ValueError, match="already registered"):
        register(DETECTOR)


# --- confidence comes from data -------------------------------------------


def test_confidence_is_read_from_the_signature_set_not_hardcoded() -> None:
    """Design §4: these numbers are measured precision, recalibrated whenever
    signatures change. A detector that baked one in would silently ignore the
    next calibration."""
    custom = SignatureSet(
        imports=(
            ImportSignature(
                id="test-aes",
                signature_class="import-specific",
                dll="*.dll",
                symbols=("AES_encrypt",),
                family="AES",
            ),
        ),
        confidence={"import-specific": 0.11, "utf16-string": 0.22},
        corroboration_bonus=0.0,
    )
    found = scan(build_pe(imports=(("anything.dll", ("AES_encrypt",)),)), custom)
    assert found["AES"] == pytest.approx(0.11)


def test_corroboration_bonus_is_capped_at_the_ceiling() -> None:
    """Never 1.0: the tool is reasoning about a binary it did not build."""
    custom = SignatureSet(
        imports=(
            ImportSignature(
                id="p",
                signature_class="import-generic",
                dll="bcrypt.dll",
                symbols=("BCryptEncrypt",),
                provides="cng",
                family="CNG",
            ),
        ),
        strings=(
            StringSignature(
                id="s",
                signature_class="utf16-string",
                value="AES",
                requires=("cng",),
                family="AES",
                algorithm="AES",
            ),
        ),
        confidence={"import-generic": 0.9, "utf16-string": 0.98},
        corroboration_bonus=0.5,
    )
    image = build_pe(
        sections=(SectionSpec(".rdata", wide("AES")),),
        imports=(("bcrypt.dll", ("BCryptEncrypt",)),),
    )
    assert scan(image, custom)["AES"] == pytest.approx(0.99)
