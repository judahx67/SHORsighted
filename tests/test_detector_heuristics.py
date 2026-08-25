"""Heuristic detector (FR-8, AC-3): embedded certificates and key material.

Two claims of very different quality live here, and the tests treat them
differently. Structural DER/PEM detection is held to a real precision bar.
Entropy detection is not — NFR-5 sets no minimum for it — so the tests pin its
*behaviour* (it never claims an algorithm, it stays capped, it defers to
structure) rather than pretending it is accurate.

The known false positive is asserted as a false positive rather than silenced.
"""

import dataclasses
import os

import pytest

from shorsighted.core.model import AssetType
from shorsighted.detectors.base import REGISTRY, Detector
from shorsighted.detectors.heuristics import DETECTOR, MIN_DER_LENGTH
from shorsighted.pe.loader import load_bytes
from shorsighted.signatures.loader import load_signatures
from shorsighted.signatures.schema import EntropySettings, SignatureSet
from tests.fixtures.build import SCN_CODE, SectionSpec, build_pe

CODE = b"\x55\x8b\xec\x83\xec" * 200
LOW_ENTROPY = b"\x00\x01\x02\x03" * 64


@pytest.fixture(scope="module")
def signatures() -> SignatureSet:
    return load_signatures()


@pytest.fixture(scope="module")
def noisy(signatures: SignatureSet) -> SignatureSet:
    """The shipped signatures with the entropy heuristic switched back on.

    It ships off: the slice 10 corpus measured it at 4 true positives against
    100 false ones, and a detector that fires on every binary carries no
    information. The behaviour is still supported and still has to be correct
    for anyone who turns it on, so the tests below exercise it explicitly rather
    than inheriting a default that would make them pass vacuously.
    """
    return dataclasses.replace(
        signatures, entropy=dataclasses.replace(signatures.entropy, enabled=True)
    )


def test_entropy_ships_disabled(signatures: SignatureSet) -> None:
    """The corpus turned this off and it must stay off until it is fixed.

    A regression here would put a 0.038-precision heuristic in front of every
    user by default, which is the one change in this project that could turn
    the headline precision into a lie.
    """
    assert signatures.entropy.enabled is False


def der_certificate(body_size: int = 512) -> bytes:
    """A structurally valid X.509 shell: SEQUENCE wrapping tbsCertificate.

    Contents are filler because only the structure is under test — which is the
    point of D-7, that certificates are found by shape rather than by entropy.
    """
    body = bytes(range(256)) * (body_size // 256 + 1)
    body = body[:body_size]
    inner = b"\x30\x82" + len(body).to_bytes(2, "big") + body
    return b"\x30\x82" + (len(inner) + 8).to_bytes(2, "big") + inner + b"\x00" * 8


def der_rsa_private_key() -> bytes:
    body = b"\x02\x01\x00" + b"\x02\x82\x01\x01\x00" + os.urandom(256)
    return b"\x30\x82" + len(body).to_bytes(2, "big") + body


def image_with(payload: bytes) -> bytes:
    return build_pe(
        machine="x64",
        sections=(SectionSpec(".text", CODE, SCN_CODE), SectionSpec(".rdata", payload)),
        imports=(("kernel32.dll", ("ExitProcess", "ReadFile", "WriteFile")),),
    )


def scan(image: bytes, signatures: SignatureSet) -> dict[str, AssetType]:
    return {(f.family or "?"): f.asset_type for f in DETECTOR.scan(load_bytes(image), signatures)}


# --- AC-3: embedded certificates ------------------------------------------


def test_a_der_certificate_is_found(signatures: SignatureSet) -> None:
    """AC-3: a binary with an embedded DER certificate yields a certificate
    asset with offset evidence."""
    found = scan(image_with(LOW_ENTROPY + der_certificate() + LOW_ENTROPY), signatures)
    assert found["X.509"] is AssetType.CERTIFICATE


def test_the_certificate_offset_points_at_the_structure(signatures: SignatureSet) -> None:
    image = image_with(LOW_ENTROPY + der_certificate() + LOW_ENTROPY)
    finding = next(f for f in DETECTOR.scan(load_bytes(image), signatures) if f.family == "X.509")
    offset = finding.evidence[0].offsets[0]
    assert image[offset : offset + 2] == b"\x30\x82"


def test_a_pem_certificate_is_found(signatures: SignatureSet) -> None:
    pem = b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----\n"
    assert scan(image_with(LOW_ENTROPY + pem), signatures)["X.509"] is AssetType.CERTIFICATE


@pytest.mark.parametrize(
    ("banner", "family"),
    [
        (b"-----BEGIN RSA PRIVATE KEY-----", "RSA"),
        (b"-----BEGIN EC PRIVATE KEY-----", "ECC"),
        (b"-----BEGIN PRIVATE KEY-----", "PKCS#8"),
        (b"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH"),
    ],
)
def test_pem_private_keys_are_reported_as_material(
    signatures: SignatureSet, banner: bytes, family: str
) -> None:
    found = scan(image_with(LOW_ENTROPY + banner + b"\nAAAA\n"), signatures)
    assert found[family] is AssetType.RELATED_MATERIAL


def test_a_der_rsa_private_key_is_found(signatures: SignatureSet) -> None:
    found = scan(image_with(LOW_ENTROPY + der_rsa_private_key() + LOW_ENTROPY), signatures)
    assert found["RSA"] is AssetType.RELATED_MATERIAL


# --- structure is what makes DER detection work ---------------------------


def test_a_bare_der_tag_is_not_a_certificate(signatures: SignatureSet) -> None:
    """`30 82` occurs constantly in ordinary binary data. Without the structural
    check these markers would be a false-positive generator."""
    assert "X.509" not in scan(image_with(b"\x30\x82" + LOW_ENTROPY), signatures)


def test_an_inner_length_larger_than_the_outer_is_rejected(signatures: SignatureSet) -> None:
    """The consistency check that random data almost never satisfies: a
    tbsCertificate cannot be bigger than the certificate containing it."""
    inner = b"\x30\x82" + (4000).to_bytes(2, "big") + b"\x00" * 200
    broken = b"\x30\x82" + (len(inner)).to_bytes(2, "big") + inner
    assert "X.509" not in scan(image_with(LOW_ENTROPY + broken), signatures)


def test_a_sequence_too_small_to_be_a_certificate_is_rejected(
    signatures: SignatureSet,
) -> None:
    tiny = b"\x30\x82" + (MIN_DER_LENGTH - 2).to_bytes(2, "big") + b"\x00" * 40
    assert "X.509" not in scan(image_with(LOW_ENTROPY + tiny), signatures)


def test_a_binary_with_no_material_reports_none(signatures: SignatureSet) -> None:
    assert scan(image_with(LOW_ENTROPY), signatures) == {}


# --- FR-8: never an algorithm ---------------------------------------------


def test_no_heuristic_finding_is_ever_an_algorithm(signatures: SignatureSet) -> None:
    """FR-8 and D-5. This detector claims material exists; it never claims the
    binary can perform an operation, and conflating those would let a
    low-precision heuristic dilute the headline algorithm precision."""
    payload = LOW_ENTROPY + der_certificate() + der_rsa_private_key() + os.urandom(256)
    for finding in DETECTOR.scan(load_bytes(image_with(payload)), signatures):
        assert finding.asset_type is not AssetType.ALGORITHM


def test_no_finding_carries_key_bytes(signatures: SignatureSet) -> None:
    """Non-goal 9: a CBOM that quotes key material is itself a leak. Findings
    are describable in offsets and names alone."""
    secret = os.urandom(64)
    image = image_with(LOW_ENTROPY + der_rsa_private_key() + secret)
    for finding in DETECTOR.scan(load_bytes(image), signatures):
        for item in finding.evidence:
            assert secret[:8].hex() not in item.description
            assert item.symbol is None


# --- entropy: the honest weak one -----------------------------------------


def test_high_entropy_data_is_reported_as_unidentified_material(
    noisy: SignatureSet,
) -> None:
    found = scan(image_with(LOW_ENTROPY + os.urandom(512) + LOW_ENTROPY), noisy)
    assert found["unidentified"] is AssetType.RELATED_MATERIAL


def test_compressed_data_is_the_documented_false_positive(
    noisy: SignatureSet,
) -> None:
    """Asserted AS a false positive rather than silenced (test-plan §2).

    Compressed data and a symmetric key are indistinguishable at 32 bytes. The
    heuristic fires on both, which is a limitation to measure and publish, not
    a bug to hide.
    """
    import zlib

    compressed = zlib.compress(os.urandom(4096), level=9)
    found = scan(image_with(LOW_ENTROPY + compressed), noisy)
    assert "unidentified" in found, "the known false positive should still fire"


def test_entropy_findings_are_capped(noisy: SignatureSet) -> None:
    findings = DETECTOR.scan(load_bytes(image_with(os.urandom(8192))), noisy)
    entropy = next(f for f in findings if f.family == "unidentified")
    assert len(entropy.evidence[0].offsets) <= noisy.entropy.max_regions


def test_entropy_does_not_re_report_the_inside_of_a_certificate(
    noisy: SignatureSet,
) -> None:
    """A certificate is full of exactly the near-uniform data this heuristic
    looks for. Naming the same bytes twice tells a reader nothing."""
    findings = DETECTOR.scan(
        load_bytes(image_with(LOW_ENTROPY + der_certificate(1024) + LOW_ENTROPY)), noisy
    )
    families = {f.family for f in findings}
    assert "X.509" in families
    assert "unidentified" not in families


def test_executable_sections_are_not_scanned_for_entropy(
    noisy: SignatureSet,
) -> None:
    """Compiled code is high-entropy by the standards of prose. Scanning .text
    would produce noise proportional to binary size."""
    image = build_pe(
        sections=(SectionSpec(".text", os.urandom(8192), SCN_CODE),),
        imports=(("kernel32.dll", ("ExitProcess",)),),
    )
    assert "unidentified" not in scan(image, noisy)


def test_entropy_can_be_switched_off_in_data() -> None:
    """A user who finds the heuristic too noisy should not need a release."""
    quiet = SignatureSet(
        entropy=EntropySettings(enabled=False),
        confidence={"entropy-region": 0.3, "der-structure": 0.85},
    )
    assert DETECTOR.scan(load_bytes(image_with(os.urandom(2048))), quiet) == []


def test_entropy_window_is_configurable() -> None:
    strict = SignatureSet(
        entropy=EntropySettings(window=64, min_distinct=64),
        confidence={"entropy-region": 0.3},
    )
    # 64 distinct values in every 64-byte window is a bar ordinary data misses.
    assert DETECTOR.scan(load_bytes(image_with(LOW_ENTROPY * 4)), strict) == []


def test_entropy_confidence_is_the_lowest_class(noisy: SignatureSet) -> None:
    findings = DETECTOR.scan(load_bytes(image_with(os.urandom(2048))), noisy)
    entropy = next(f for f in findings if f.family == "unidentified")
    assert entropy.confidence == noisy.confidence_for("entropy-region")
    assert entropy.confidence < noisy.confidence_for("der-structure")


# --- wiring ---------------------------------------------------------------


def test_the_heuristic_detector_satisfies_the_protocol() -> None:
    assert isinstance(DETECTOR, Detector)
    assert REGISTRY["heuristics"] is DETECTOR


def test_scanning_with_no_material_signatures_is_not_an_error() -> None:
    empty = SignatureSet(entropy=EntropySettings(enabled=False))
    assert DETECTOR.scan(load_bytes(image_with(LOW_ENTROPY)), empty) == []


def test_entropy_does_not_re_report_a_known_constant_table(
    signatures: SignatureSet,
) -> None:
    """An AES S-box is a permutation of 0..255, so it is the most key-shaped
    thing in any binary. Without this the same offset gets reported twice: once
    correctly as AES, once as "possible key material"."""
    from tools.derive_constants import aes_sbox

    findings = DETECTOR.scan(
        load_bytes(image_with(LOW_ENTROPY + aes_sbox() + LOW_ENTROPY)), signatures
    )
    assert "unidentified" not in {f.family for f in findings}


def test_entropy_still_fires_on_data_that_is_not_a_known_table(
    noisy: SignatureSet,
) -> None:
    """Guards the test above from passing by disabling the heuristic entirely."""
    found = scan(image_with(LOW_ENTROPY + os.urandom(512) + LOW_ENTROPY), noisy)
    assert "unidentified" in found
