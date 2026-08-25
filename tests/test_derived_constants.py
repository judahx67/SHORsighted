"""Prove the shipped constant tables are correct.

A wrong byte in a constant table is the worst bug this project can have,
because it does not fail: the signature simply never matches, and the tool
quietly loses recall for that algorithm in every binary, forever. No user
report would ever surface it.

So the tables are not merely re-derived here — that would only prove the
generator agrees with itself. Where an independent oracle exists it is used:
`zlib.crc32` for the CRC table, and a SHA-256 implementation driven by our own
derived constants, checked against `hashlib`. If the IV or round constants were
wrong by a single bit, the digest of b"abc" would not match and this fails.
"""

import hashlib
import tomllib
import zlib
from pathlib import Path
from typing import Any

import pytest

from shorsighted.signatures.loader import DATA_DIR, load_signatures
from tools import derive_constants as derive


def shipped(filename: str) -> list[dict[str, Any]]:
    path = DATA_DIR / filename
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    signatures: list[dict[str, Any]] = document["signature"]
    return signatures


def by_id(filename: str, signature_id: str) -> dict[str, Any]:
    return next(s for s in shipped(filename) if s["id"] == signature_id)


# --- independent oracles --------------------------------------------------


def test_crc32_table_reproduces_zlib() -> None:
    """zlib computes CRC-32 without our table. Driving the standard algorithm
    with our derived table must land on the same value."""
    table = derive.crc32_table()
    message = b"the quick brown fox jumps over the lazy dog, twice"

    crc = 0xFFFFFFFF
    for byte in message:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    assert crc ^ 0xFFFFFFFF == zlib.crc32(message)


def test_sha256_constants_reproduce_hashlib() -> None:
    """A full SHA-256, driven entirely by our derived IV and round constants,
    checked against the standard library.

    This is the decisive test for the SHA-2 signatures. Any error in the eight
    initial hash values or the sixty-four round constants changes the digest.
    """
    initial = derive.sha2_words(8, 2, 32)
    rounds = derive.sha2_words(64, 3, 32)
    mask = 0xFFFFFFFF

    def rotr(value: int, count: int) -> int:
        return ((value >> count) | (value << (32 - count))) & mask

    message = b"abc"
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += (len(message) * 8).to_bytes(8, "big")

    state = list(initial)
    for start in range(0, len(padded), 64):
        block = padded[start : start + 64]
        w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & mask)

        a, b, c, d, e, f, g, h = state
        for i in range(64):
            s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            choose = (e & f) ^ (~e & mask & g)
            temp1 = (h + s1 + choose + rounds[i] + w[i]) & mask
            s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + majority) & mask
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & mask, c, b, a, (temp1 + temp2) & mask
        state = [(x + y) & mask for x, y in zip(state, (a, b, c, d, e, f, g, h), strict=True)]

    digest = b"".join(word.to_bytes(4, "big") for word in state)
    assert digest == hashlib.sha256(message).digest()


def test_aes_sbox_is_a_permutation() -> None:
    """A substitution box that is not a bijection is not an S-box. This catches
    any derivation error that collapses two inputs onto one output."""
    sbox = derive.aes_sbox()
    assert len(set(sbox)) == 256


def test_aes_inverse_sbox_inverts_the_forward_one() -> None:
    sbox = derive.aes_sbox()
    inverse = derive.aes_inverse_sbox(sbox)
    assert all(inverse[sbox[i]] == i for i in range(256))


def test_aes_te0_is_consistent_with_the_sbox() -> None:
    """Te0[i] packs (2*s, s, s, 3*s) in GF(2^8) for s = sbox[i]. Checking the
    relation rather than the bytes means this stays true if the S-box changes."""
    sbox = derive.aes_sbox()
    te0 = derive.aes_te0(sbox)
    for i in range(256):
        s = sbox[i]
        assert tuple(te0[i * 4 : i * 4 + 4]) == (
            derive._gf_mul(s, 2),
            s,
            s,
            derive._gf_mul(s, 3),
        )


def test_curve_generators_lie_on_their_curves() -> None:
    """The check that makes stating published curve constants defensible: one
    wrong hex digit in p, b, Gx or Gy breaks y^2 = x^3 - 3x + b (mod p)."""
    derive.check_weierstrass(derive.P256, "P-256")
    derive.check_weierstrass(derive.P384, "P-384")


def test_curve25519_prime_is_two_to_the_255_minus_19() -> None:
    assert derive.CURVE25519_P == 2**255 - 19


def test_integer_roots_agree_with_exact_powers() -> None:
    """`frac_root_bits` relies on `_iroot`; a floor-off-by-one there would shift
    every SHA-2 round constant."""
    for value in (2, 7, 1000, 999999):
        for root in (2, 3):
            assert derive._iroot(value**root, root) == value
            assert derive._iroot(value**root - 1, root) == value - 1


# --- the shipped files match the derivation -------------------------------


def test_shipped_aes_matches_the_derivation() -> None:
    sbox = derive.aes_sbox()
    assert by_id("constants/aes.toml", "aes-sbox-fwd")["pattern"] == sbox.hex()
    assert (
        by_id("constants/aes.toml", "aes-sbox-inv")["pattern"]
        == derive.aes_inverse_sbox(sbox).hex()
    )
    assert by_id("constants/aes.toml", "aes-te0")["pattern"] == derive.aes_te0(sbox).hex()


def test_shipped_sha2_matches_the_derivation() -> None:
    assert by_id("constants/sha2.toml", "sha256-iv")["words"] == [
        f"{w:08x}" for w in derive.sha2_words(8, 2, 32)
    ]
    assert by_id("constants/sha2.toml", "sha256-k")["words"] == [
        f"{w:08x}" for w in derive.sha2_words(64, 3, 32)
    ]
    assert by_id("constants/sha2.toml", "sha512-k")["words"] == [
        f"{w:016x}" for w in derive.sha2_words(80, 3, 64)
    ]


def test_shipped_crc32_matches_the_derivation() -> None:
    expected = b"".join(word.to_bytes(4, "little") for word in derive.crc32_table())
    assert by_id("confusables.toml", "crc32-table")["pattern"] == expected.hex()


def test_shipped_md5_matches_the_derivation() -> None:
    assert by_id("constants/legacy-hashes.toml", "md5-t-table")["words"] == [
        f"{w:08x}" for w in derive.md5_table()
    ]


def test_shipped_keccak_matches_the_derivation() -> None:
    assert by_id("constants/sha3.toml", "keccak-round-constants")["words"] == [
        f"{w:016x}" for w in derive.keccak_round_constants()
    ]


# --- properties of the shipped set ----------------------------------------


def test_only_confusables_suppress() -> None:
    """A suppressor is never reported. One accidentally set on a real algorithm
    would silently delete that algorithm from every report."""
    for signature in load_signatures().constants:
        if signature.suppresses:
            assert signature.family == "CRC-32", f"{signature.id} suppresses unexpectedly"


def test_every_constant_signature_has_a_description() -> None:
    """Descriptions reach the user in the evidence column, and the provenance of
    a byte table is exactly what a reviewer needs (FR-12)."""
    for signature in load_signatures().constants:
        assert signature.description, f"{signature.id} has no description"


def test_curve_constants_are_all_quantum_broken() -> None:
    for signature in load_signatures().constants:
        if signature.family == "ECC":
            assert signature.nist_quantum_level == 0


def test_anchors_are_long_enough_to_be_distinctive() -> None:
    """A short anchor is a false-positive generator: 4 bytes of a table will
    match somewhere in almost any large binary by chance alone."""
    for signature in load_signatures().constants:
        assert signature.min_match >= 16, f"{signature.id} anchor is too short"


@pytest.mark.parametrize("filename", ["constants/aes.toml", "constants/sha2.toml"])
def test_generated_files_warn_against_hand_editing(filename: str) -> None:
    text = (DATA_DIR / filename).read_text(encoding="utf-8")
    assert "Do not hand-edit" in text
    assert "derive_constants" in text


def test_generator_output_is_stable(tmp_path: Path) -> None:
    """Regenerating must produce exactly what is committed, or the committed
    files and the derivation have drifted apart."""
    for name, builder in (
        ("constants/aes.toml", derive.build_aes),
        ("constants/sha2.toml", derive.build_sha2),
        ("constants/sha3.toml", derive.build_sha3),
        ("constants/curves.toml", derive.build_curves),
        ("constants/stream.toml", derive.build_stream_ciphers),
        ("constants/legacy-hashes.toml", derive.build_legacy_hashes),
        ("confusables.toml", derive.build_confusables),
    ):
        assert builder() == (DATA_DIR / name).read_text(encoding="utf-8"), (
            f"{name} differs from the generator. Run `python -m tools.derive_constants`."
        )
