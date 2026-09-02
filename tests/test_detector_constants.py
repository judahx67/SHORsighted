"""Constant detector (FR-7, AC-2), on synthetic binaries built in memory.

The headline case is a binary with no crypto imports at all — the shape that
statically linked OpenSSL produces, and the shape every source-reading CBOM
tool is blind to.
"""

import pytest

from shorsighted.detectors.base import REGISTRY, Detector
from shorsighted.detectors.constants import DETECTOR, MAX_OCCURRENCES
from shorsighted.pe.loader import load_bytes
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import ConstantSignature, SignatureSet
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe
from tools import derive_constants as derive

SBOX = derive.aes_sbox()
SHA256_IV_LE = b"".join(w.to_bytes(4, "little") for w in derive.sha2_words(8, 2, 32))
SHA256_IV_BE = b"".join(w.to_bytes(4, "big") for w in derive.sha2_words(8, 2, 32))
CRC32_TABLE = b"".join(w.to_bytes(4, "little") for w in derive.crc32_table())
FILLER = bytes(range(1, 17)) * 4


@pytest.fixture(scope="module")
def signatures() -> SignatureSet:
    return load_signatures()


def image_with(payload: bytes, *, imports: tuple[tuple[str, tuple[str, ...]], ...] = ()) -> bytes:
    return build_pe(
        machine="x64",
        sections=(SectionSpec(".text", b"\x90" * 64, SCN_CODE), SectionSpec(".rdata", payload)),
        imports=imports or (("kernel32.dll", ("ExitProcess",)),),
    )


def scan(image: bytes, signatures: SignatureSet) -> dict[str, float]:
    return {
        (f.algorithm or f.family or "?"): f.confidence
        for f in DETECTOR.scan(load_bytes(image), signatures)
    }


# --- AC-2: the differentiator ---------------------------------------------


def test_a_binary_with_no_crypto_imports_still_reports_aes(signatures: SignatureSet) -> None:
    """AC-2 in miniature. This is the case the whole project exists for: a
    statically linked implementation imports nothing, so the import table says
    "no cryptography" and the tables say otherwise."""
    found = scan(image_with(FILLER + SBOX + FILLER), signatures)
    assert found["AES"] == pytest.approx(signatures.confidence_for("unique-table"))


def test_aes_and_sha256_are_found_together(signatures: SignatureSet) -> None:
    found = scan(image_with(SBOX + FILLER + SHA256_IV_LE), signatures)
    assert {"AES", "SHA-256"} <= set(found)


def test_a_binary_without_constants_reports_nothing(signatures: SignatureSet) -> None:
    assert scan(image_with(bytes(range(256)) * 4), signatures) == {}


def test_quantum_levels_come_from_the_constant_data(signatures: SignatureSet) -> None:
    findings = DETECTOR.scan(load_bytes(image_with(SBOX + FILLER + SHA256_IV_LE)), signatures)
    levels = {(f.algorithm or f.family): f.nist_quantum_level for f in findings}
    assert levels["AES"] == 1
    assert levels["SHA-256"] == 2


def test_curve_constants_are_reported_quantum_broken(signatures: SignatureSet) -> None:
    """The migration planner's headline: a P-256 parameter in .rdata means
    elliptic curve cryptography, which Shor breaks outright."""
    p256_b = derive.P256["b"].to_bytes(32, "big")
    findings = DETECTOR.scan(load_bytes(image_with(FILLER + p256_b + FILLER)), signatures)
    assert findings
    assert all(f.nist_quantum_level == 0 for f in findings)
    assert any(f.parameter_set == "P-256" for f in findings)


def test_chacha20_sigma_is_found(signatures: SignatureSet) -> None:
    found = scan(image_with(FILLER + b"expand 32-byte k" + FILLER), signatures)
    assert "ChaCha20" in found


# --- offsets and evidence -------------------------------------------------


def test_the_reported_offset_points_at_the_table(signatures: SignatureSet) -> None:
    """FR-12: an offset that does not land on the constant is worse than no
    offset, because someone will go and look."""
    image = image_with(FILLER + SBOX + FILLER)
    finding = DETECTOR.scan(load_bytes(image), signatures)[0]
    offset = finding.evidence[0].offsets[0]
    assert image[offset : offset + 64] == SBOX[:64]


def test_evidence_reports_how_much_of_the_table_matched(signatures: SignatureSet) -> None:
    """ "The first 64 bytes are here" and "all 256 are here" are different
    strengths of evidence, and the description says which."""
    finding = DETECTOR.scan(load_bytes(image_with(SBOX)), signatures)[0]
    assert "of 256 bytes matched" in finding.evidence[0].description


def test_repeated_tables_collect_multiple_offsets(signatures: SignatureSet) -> None:
    """Encrypt and decrypt paths often carry their own copy."""
    image = image_with(SBOX + FILLER + SBOX)
    finding = next(f for f in DETECTOR.scan(load_bytes(image), signatures) if f.family == "AES")
    assert len(finding.evidence[0].offsets) >= 2


def test_occurrences_are_capped(signatures: SignatureSet) -> None:
    """A pathological file must not produce an unbounded CBOM."""
    image = image_with(SBOX * (MAX_OCCURRENCES + 5))
    finding = next(f for f in DETECTOR.scan(load_bytes(image), signatures) if f.family == "AES")
    assert len(finding.evidence[0].offsets) <= MAX_OCCURRENCES


# --- endianness (design §4) -----------------------------------------------


@pytest.mark.parametrize("layout", ["little", "big"], ids=["le-contiguous", "be-contiguous"])
def test_word_tables_are_found_in_either_byte_order(signatures: SignatureSet, layout: str) -> None:
    """SHA-256's IV is eight 32-bit words. A little-endian build stores them one
    way; a compiler that kept them in the order the standard prints stores them
    the other. Both occur, so both are searched."""
    payload = SHA256_IV_LE if layout == "little" else SHA256_IV_BE
    assert "SHA-256" in scan(image_with(FILLER + payload + FILLER), signatures)


def test_the_two_layouts_differ(signatures: SignatureSet) -> None:
    """Guards the test above from passing vacuously."""
    assert SHA256_IV_LE != SHA256_IV_BE


# --- anchoring ------------------------------------------------------------


def test_a_truncated_table_still_matches_at_the_anchor(signatures: SignatureSet) -> None:
    """A compiler may emit only the part of a table its implementation uses.
    Requiring all 256 bytes would lose those builds."""
    assert "AES" in scan(image_with(FILLER + SBOX[:80] + FILLER), signatures)


def test_a_table_shorter_than_the_anchor_does_not_match(signatures: SignatureSet) -> None:
    assert scan(image_with(FILLER + SBOX[:32] + FILLER), signatures) == {}


def test_a_flipped_byte_inside_the_anchor_kills_the_match(signatures: SignatureSet) -> None:
    """Test-plan §2. The anchor must be matched exactly, or the signature is
    matching noise rather than a table."""
    damaged = bytearray(SBOX)
    damaged[10] ^= 0xFF
    assert scan(image_with(FILLER + bytes(damaged) + FILLER), signatures) == {}


def test_a_flipped_byte_past_the_anchor_still_matches(signatures: SignatureSet) -> None:
    """Beyond the anchor, damage lowers the reported match length rather than
    discarding the evidence."""
    damaged = bytearray(SBOX)
    damaged[200] ^= 0xFF
    assert "AES" in scan(image_with(FILLER + bytes(damaged) + FILLER), signatures)


# --- suppressors (design §4) ----------------------------------------------


def test_a_crc32_table_is_never_reported(signatures: SignatureSet) -> None:
    """It is not cryptography. Reporting it would be noise, and reporting it as
    crypto would be wrong."""
    assert scan(image_with(FILLER + CRC32_TABLE + FILLER), signatures) == {}


def test_a_crc32_table_does_not_suppress_crypto_elsewhere(signatures: SignatureSet) -> None:
    """Suppression is regional. A CRC table in .rdata must not delete an AES
    S-box sitting a kilobyte away."""
    found = scan(image_with(CRC32_TABLE + FILLER + SBOX), signatures)
    assert "AES" in found


def test_a_suppressor_vetoes_an_overlapping_claim() -> None:
    """The rule itself, on a synthetic pair: a crypto signature whose match
    lands inside a suppressed region is dropped before it can be reported."""
    shared = bytes(range(64)) * 2
    custom = SignatureSet(
        constants=(
            ConstantSignature(
                id="fake-crypto",
                signature_class="unique-table",
                patterns=(shared,),
                min_match=32,
                family="Fake",
                algorithm="Fake",
            ),
            ConstantSignature(
                id="fake-confusable",
                signature_class="unique-table",
                patterns=(shared,),
                min_match=32,
                suppresses=True,
                family="NotCrypto",
            ),
        ),
        confidence={"unique-table": 0.9},
    )
    assert scan(image_with(FILLER + shared + FILLER), custom) == {}


# --- wiring ---------------------------------------------------------------


def test_the_constant_detector_satisfies_the_protocol() -> None:
    assert isinstance(DETECTOR, Detector)
    assert REGISTRY["constants"] is DETECTOR


def test_confidence_comes_from_the_signature_set() -> None:
    custom = SignatureSet(
        constants=(
            ConstantSignature(
                id="t",
                signature_class="unique-table",
                patterns=(SBOX,),
                min_match=64,
                family="AES",
                algorithm="AES",
            ),
        ),
        confidence={"unique-table": 0.42},
    )
    assert scan(image_with(SBOX), custom)["AES"] == pytest.approx(0.42)


def test_scanning_an_empty_signature_set_is_not_an_error() -> None:
    assert DETECTOR.scan(load_bytes(image_with(SBOX)), SignatureSet()) == []


# --- every shipped signature is exercised (AC-6) ---------------------------

_REPORTABLE = [s for s in load_signatures().constants if not s.suppresses]


@pytest.mark.parametrize("shipped", _REPORTABLE, ids=lambda s: s.id)
def test_every_shipped_constant_is_reachable(
    shipped: ConstantSignature, signatures: SignatureSet
) -> None:
    """A signature that can never fire is worse than a missing one: it reads as
    coverage and detects nothing. The schema already rejects an anchor longer
    than its pattern, but nothing else proves the datum survives the whole path
    — every expanded layout, and the suppressor pass, which is regional and
    could veto a real table whose bytes overlap a confusable's.

    This is the check behind the contributor promise: add a table to
    `signatures/data/constants/`, and CI answers whether it is detectable
    before anyone reviews the hex.
    """
    for layout, pattern in enumerate(shipped.patterns):
        image = image_with(FILLER + pattern + FILLER)
        matched = {
            e.signature_id for f in DETECTOR.scan(load_bytes(image), signatures) for e in f.evidence
        }
        assert shipped.id in matched, f"layout {layout} of {shipped.id} matches nothing"
