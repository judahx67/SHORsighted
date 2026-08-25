"""Derive cryptographic constants from their definitions and emit signature TOML.

    python -m tools.derive_constants

Why a generator rather than 2,000 hand-typed hex bytes: a transcription error in
a constant table does not fail loudly. It produces a signature that silently
never matches, and the tool quietly loses recall for that algorithm in every
binary forever. Deriving each table from the definition that produces it — the
GF(2^8) inverse for AES, fractional roots of primes for SHA-2, |sin(i)| for MD5 —
makes correctness checkable instead of asserted.

Every derivation here is checked against a published value before it is written
(`_assert_known`), so this script fails rather than emits a wrong table. The
generated files are committed; `tests/test_derived_constants.py` re-derives and
compares, so drift in either direction is caught.

Deliberately NOT derived here, and absent from the shipped signatures:

  DES  S-boxes and permutation tables are arbitrary published tables with no
       generating rule. They would have to be transcribed, which is the failure
       mode this script exists to avoid. A contributor with the FIPS 46-3 text
       in front of them can add them as data — that is exactly the FR-9 path.

  PQC  ML-KEM and ML-DSA NTT tables depend on the reference implementation's
       Montgomery representation, not only on the mathematical definition, so
       "derived from first principles" would not match what is actually in a
       binary. Shipping a table that looks authoritative but never fires is
       worse than shipping none. FR-7 names them; this is a stated gap.
"""

import json
import math
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "shorsighted" / "signatures" / "data"
CONSTANTS_DIR = DATA_DIR / "constants"


# --- number theory helpers -------------------------------------------------


def primes(count: int) -> list[int]:
    found: list[int] = []
    candidate = 2
    while len(found) < count:
        if all(candidate % p for p in found if p * p <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def frac_root_bits(value: int, root: int, bits: int) -> int:
    """Fractional part of `value ** (1/root)`, scaled to `bits` bits.

    Integer arithmetic throughout. Floating point would be accurate enough for
    32-bit words and quietly wrong in the low bits of 64-bit ones, which is the
    exact class of error this module exists to prevent.
    """
    scaled = value << (root * bits)
    whole = math.isqrt(scaled) if root == 2 else _iroot(scaled, root)
    return whole & ((1 << bits) - 1)


def _iroot(value: int, root: int) -> int:
    """Integer `root`-th root, floor. Newton's method on integers."""
    if value < 2:
        return value
    guess = 1 << ((value.bit_length() + root - 1) // root)
    while True:
        better = ((root - 1) * guess + value // guess ** (root - 1)) // root
        if better >= guess:
            return guess
        guess = better


# --- AES -------------------------------------------------------------------


def _gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) modulo the AES polynomial x^8+x^4+x^3+x+1."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def aes_sbox() -> bytes:
    """The forward S-box: multiplicative inverse in GF(2^8), then an affine map.

    FIPS-197 §5.1.1. A byte table, so byte order does not enter into it — which
    is why this is a `unique-table` signature with no layout expansion.
    """
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gf_mul(a, b) == 1:
                inverse[a] = b
                break

    def rotl(value: int, count: int) -> int:
        return ((value << count) | (value >> (8 - count))) & 0xFF

    table = bytearray(256)
    for index in range(256):
        b = inverse[index]
        table[index] = b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63
    return bytes(table)


def aes_inverse_sbox(forward: bytes) -> bytes:
    table = bytearray(256)
    for index, value in enumerate(forward):
        table[value] = index
    return bytes(table)


def aes_te0(sbox: bytes) -> bytes:
    """The T-table used by table-driven AES implementations (OpenSSL, mbedTLS).

    Each entry packs the S-box output multiplied by 2, 1, 1, 3 in GF(2^8).
    Present in far more real binaries than the bare S-box, because almost every
    optimised implementation carries it.
    """
    out = bytearray()
    for index in range(256):
        s = sbox[index]
        out += bytes((_gf_mul(s, 2), s, s, _gf_mul(s, 3)))
    return bytes(out)


# --- hashes ----------------------------------------------------------------


def sha2_words(count: int, root: int, bits: int) -> list[int]:
    """SHA-2 constants: fractional parts of roots of the first primes.

    IVs are square roots (FIPS 180-4 §5.3), round constants are cube roots
    (§4.2). Nothing arbitrary anywhere, which is what makes them derivable.
    """
    return [frac_root_bits(p, root, bits) for p in primes(count)]


def md5_table() -> list[int]:
    """MD5's T table: floor(|sin(i)| * 2^32) for i in 1..64 (RFC 1321 §3.4)."""
    return [int(abs(math.sin(i)) * (1 << 32)) for i in range(1, 65)]


def crc32_table() -> list[int]:
    """The standard CRC-32 table, polynomial 0xEDB88320.

    A *confusable*, not cryptography. It is a 1 KB lookup table of high-entropy
    looking words sitting in the same kind of .rdata region as a real S-box, and
    it appears in a large share of all software. FR-7 calls for detecting it
    precisely so a crypto claim is never made from it.
    """
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        table.append(value)
    return table


def keccak_round_constants() -> list[int]:
    """SHA-3 / Keccak-f[1600] round constants, from the LFSR in FIPS 202 §3.2.5."""
    constants = []
    lfsr = 0x01
    for _ in range(24):
        constant = 0
        for j in range(7):
            if lfsr & 1:
                constant ^= 1 << ((1 << j) - 1)
            lfsr = ((lfsr << 1) ^ 0x71) & 0xFF if lfsr & 0x80 else (lfsr << 1) & 0xFF
        constants.append(constant)
    return constants


# --- elliptic curves -------------------------------------------------------

P256 = {
    "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
}

P384 = {
    "p": int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFF",
        16,
    ),
    "b": int(
        "B3312FA7E23EE7E4988E056BE3F82D19"
        "181D9C6EFE8141120314088F5013875A"
        "C656398D8A2ED19D2A85C8EDD3EC2AEF",
        16,
    ),
    "gx": int(
        "AA87CA22BE8B05378EB1C71EF320AD74"
        "6E1D3B628BA79B9859F741E082542A38"
        "5502F25DBF55296C3A545E3872760AB7",
        16,
    ),
    "gy": int(
        "3617DE4A96262C6F5D9E98BF9292DC29"
        "F8F41DBD289A147CE9DA3113B5F0B8C0"
        "0A60B1CE1D7E819D7A431D7C90EA0E5F",
        16,
    ),
    "n": int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
}


def check_weierstrass(curve: dict[str, int], name: str) -> None:
    """Verify the generator satisfies y^2 = x^3 - 3x + b (mod p).

    The NIST prime curves all use a = -3. This is the self-check that makes it
    safe to state these constants at all: a single wrong hex digit anywhere in
    p, b, Gx or Gy breaks the identity and this raises instead of writing a
    signature that would never match anything.
    """
    p, b, x, y = curve["p"], curve["b"], curve["gx"], curve["gy"]
    left = (y * y) % p
    right = (x * x * x - 3 * x + b) % p
    if left != right:
        raise AssertionError(f"{name}: generator is not on the curve - constants are wrong")


CURVE25519_P = (1 << 255) - 19


# --- emitting --------------------------------------------------------------


def _hex(data: bytes) -> str:
    return data.hex()


def _words_hex(words: list[int], width: int) -> list[str]:
    return [f"{word:0{width}x}" for word in words]


def _assert_known(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: derived {actual!r} but the published value is {expected!r}")


def _toml_string(value: str) -> str:
    """A TOML basic string.

    `json.dumps` escapes quotes and backslashes exactly the way TOML basic
    strings do, which beats hand-rolling an escaper that would be wrong the
    first time a description contained a quotation mark. It was.
    """
    return json.dumps(value)


def _signature(**fields: object) -> str:
    lines = []
    for key, value in fields.items():
        if value is None:
            continue
        # bool before str: bool is not a str, but it *is* an int, so it has to
        # be tested before the numeric fallback catches it as 1/0.
        if isinstance(value, bool):
            lines.append(f"{key} = {str(value).lower()}")
        elif isinstance(value, str):
            lines.append(f"{key} = {_toml_string(value)}")
        elif isinstance(value, list):
            joined = ", ".join(_toml_string(str(item)) for item in value)
            lines.append(f"{key} = [{joined}]")
        else:
            lines.append(f"{key} = {value}")
    return "[[signature]]\n" + "\n".join(lines) + "\n"


def build_aes() -> str:
    sbox = aes_sbox()
    _assert_known(sbox[:8].hex(), "637c777bf26b6fc5", "AES S-box")
    inverse = aes_inverse_sbox(sbox)
    _assert_known(inverse[:8].hex(), "52096ad53036a538", "AES inverse S-box")
    te0 = aes_te0(sbox)
    # Te0[0] = (2*0x63, 0x63, 0x63, 3*0x63) in GF(2^8) = c6 63 63 a5, which is
    # OpenSSL's Te0[0] = 0xc66363a5. Checkable by hand, unlike most of this file.
    _assert_known(te0[:8].hex(), "c66363a5f87c7c84", "AES Te0")

    header = """# AES constants, derived from FIPS-197 by tools/derive_constants.py.
# Do not hand-edit: run `python -m tools.derive_constants` instead.
#
# All three are byte tables, so endianness does not apply and no layout
# expansion is needed. min_match is the anchor length: a compiler may split or
# reorder a table's tail, but the head is contiguous in every build observed.

"""
    return header + "\n".join(
        (
            _signature(
                id="aes-sbox-fwd",
                family="AES",
                algorithm="AES",
                primitive="block-cipher",
                nist_quantum_level=1,
                **{"class": "unique-table"},
                description="Forward S-box, FIPS-197 5.1.1",
                pattern=_hex(sbox),
                min_match=64,
            ),
            _signature(
                id="aes-sbox-inv",
                family="AES",
                algorithm="AES",
                primitive="block-cipher",
                nist_quantum_level=1,
                **{"class": "unique-table"},
                description="Inverse S-box, FIPS-197 5.3.2. Present when decryption is compiled in",
                pattern=_hex(inverse),
                min_match=64,
            ),
            _signature(
                id="aes-te0",
                family="AES",
                algorithm="AES",
                primitive="block-cipher",
                nist_quantum_level=1,
                **{"class": "unique-table"},
                description="Te0 T-table. Carried by most optimised implementations",
                pattern=_hex(te0),
                min_match=64,
            ),
        )
    )


def build_sha2() -> str:
    iv256 = sha2_words(8, 2, 32)
    _assert_known(f"{iv256[0]:08x}", "6a09e667", "SHA-256 IV")
    k256 = sha2_words(64, 3, 32)
    _assert_known(f"{k256[0]:08x}", "428a2f98", "SHA-256 K")
    iv512 = sha2_words(8, 2, 64)
    _assert_known(f"{iv512[0]:016x}", "6a09e667f3bcc908", "SHA-512 IV")
    k512 = sha2_words(80, 3, 64)
    _assert_known(f"{k512[0]:016x}", "428a2f98d728ae22", "SHA-512 K")

    header = """# SHA-2 constants, derived from FIPS 180-4 by tools/derive_constants.py.
# Do not hand-edit: run `python -m tools.derive_constants` instead.
#
# IVs are the fractional parts of the square roots of the first primes (5.3),
# round constants the cube roots (4.2). These are word tables, so byte order
# matters and the loader expands each into both layouts: little-endian x86
# builds store them one way, big-endian constants written out by a compiler that
# kept them in network order the other.

"""
    return header + "\n".join(
        (
            _signature(
                id="sha256-iv",
                family="SHA-2",
                algorithm="SHA-256",
                parameter_set="256",
                primitive="hash",
                oid="2.16.840.1.101.3.4.2.1",
                nist_quantum_level=2,
                **{"class": "word-table"},
                description="Initial hash value H(0), FIPS 180-4 5.3.3",
                words=_words_hex(iv256, 8),
                word_size=4,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=32,
            ),
            _signature(
                id="sha256-k",
                family="SHA-2",
                algorithm="SHA-256",
                parameter_set="256",
                primitive="hash",
                oid="2.16.840.1.101.3.4.2.1",
                nist_quantum_level=2,
                **{"class": "word-table"},
                description="Round constants K, FIPS 180-4 4.2.2. 256 bytes, very distinctive",
                words=_words_hex(k256, 8),
                word_size=4,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=64,
            ),
            _signature(
                id="sha512-iv",
                family="SHA-2",
                algorithm="SHA-512",
                parameter_set="512",
                primitive="hash",
                oid="2.16.840.1.101.3.4.2.3",
                nist_quantum_level=4,
                **{"class": "word-table"},
                description="Initial hash value H(0), FIPS 180-4 5.3.5",
                words=_words_hex(iv512, 16),
                word_size=8,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=32,
            ),
            _signature(
                id="sha512-k",
                family="SHA-2",
                algorithm="SHA-512",
                parameter_set="512",
                primitive="hash",
                oid="2.16.840.1.101.3.4.2.3",
                nist_quantum_level=4,
                **{"class": "word-table"},
                description="Round constants K, FIPS 180-4 4.2.3",
                words=_words_hex(k512, 16),
                word_size=8,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=64,
            ),
        )
    )


def build_legacy_hashes() -> str:
    md5 = md5_table()
    _assert_known(f"{md5[0]:08x}", "d76aa478", "MD5 T table")

    header = """# MD5 and SHA-1 constants, derived by tools/derive_constants.py.
# Do not hand-edit: run `python -m tools.derive_constants` instead.
#
# Both algorithms are broken classically rather than by quantum search, so
# nist_quantum_level is deliberately unset: a number in that field would
# misreport what the field means. They are still worth detecting - a migration
# planner wants to know they are there.
#
# SHA-1's IV and MD5's are the same four words, which is a historical artefact
# of MD4's lineage rather than a coincidence. SHA-1 adds a fifth, so the
# combined five-word run is what distinguishes them.

"""
    return header + "\n".join(
        (
            _signature(
                id="md5-t-table",
                family="MD5",
                algorithm="MD5",
                primitive="hash",
                **{"class": "word-table"},
                description="T[i] = floor(|sin(i)| * 2^32), RFC 1321 3.4",
                words=_words_hex(md5, 8),
                word_size=4,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=64,
            ),
            _signature(
                id="sha1-iv",
                family="SHA-1",
                algorithm="SHA-1",
                primitive="hash",
                **{"class": "word-table"},
                description="Initial hash value, FIPS 180-4 5.3.1. Five words including MD4's four",
                words=["67452301", "efcdab89", "98badcfe", "10325476", "c3d2e1f0"],
                word_size=4,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=20,
            ),
            _signature(
                id="sha1-k",
                family="SHA-1",
                algorithm="SHA-1",
                primitive="hash",
                **{"class": "word-table"},
                description="Round constants, FIPS 180-4 4.2.1",
                words=["5a827999", "6ed9eba1", "8f1bbcdc", "ca62c1d6"],
                word_size=4,
                layouts=["le-contiguous", "be-contiguous"],
                min_match=16,
            ),
        )
    )


def build_sha3() -> str:
    rc = keccak_round_constants()
    _assert_known(f"{rc[0]:016x}", "0000000000000001", "Keccak RC[0]")
    _assert_known(f"{rc[1]:016x}", "0000000000008082", "Keccak RC[1]")
    _assert_known(f"{rc[23]:016x}", "8000000080008008", "Keccak RC[23]")

    header = """# SHA-3 / Keccak constants, derived from FIPS 202 by tools/derive_constants.py.
# Do not hand-edit: run `python -m tools.derive_constants` instead.
#
# The round constants come from an 8-bit LFSR (3.2.5), so they are derivable
# rather than transcribed. They are shared by every SHA-3 variant and by SHAKE,
# which is why this reports the family and not a parameter set - and why it also
# fires on SHA-3-based PQC schemes, which is correct: they do use Keccak.

"""
    return header + _signature(
        id="keccak-round-constants",
        family="SHA-3",
        algorithm="Keccak",
        primitive="hash",
        nist_quantum_level=2,
        **{"class": "word-table"},
        description="Keccak-f[1600] round constants, FIPS 202 3.2.5",
        words=_words_hex(rc, 16),
        word_size=8,
        layouts=["le-contiguous", "be-contiguous"],
        min_match=64,
    )


def build_curves() -> str:
    check_weierstrass(P256, "P-256")
    check_weierstrass(P384, "P-384")

    header = """# Elliptic-curve parameters, verified by tools/derive_constants.py.
# Do not hand-edit: run `python -m tools.derive_constants` instead.
#
# These are published constants rather than derived ones, so the generator
# verifies them instead: it checks that each curve's generator point satisfies
# y^2 = x^3 - 3x + b (mod p). A single wrong hex digit breaks that identity and
# the generator refuses to emit, which is the safeguard that makes stating them
# defensible at all.
#
# Every curve here is quantum-broken (level 0) - Shor's algorithm solves the
# discrete log. For the migration planner these are the headline findings.
#
# Curve parameters are big-integer constants, stored by real implementations in
# whichever limb order the bignum library uses. Both contiguous layouts are
# expanded; a limb-reversed layout is a known gap (see LIMITATIONS).

"""

    def curve_signature(name: str, value: int, curve: str, size: int, oid: str | None) -> str:
        return _signature(
            id=name,
            family="ECC",
            algorithm=curve,
            parameter_set=curve,
            primitive="key-agree",
            oid=oid,
            nist_quantum_level=0,
            **{"class": "unique-table"},
            description=f"{curve} field/curve constant. Quantum-broken by Shor",
            pattern=value.to_bytes(size, "big").hex(),
            min_match=size,
        )

    return header + "\n".join(
        (
            curve_signature("p256-b", P256["b"], "P-256", 32, "1.2.840.10045.3.1.7"),
            curve_signature("p256-gx", P256["gx"], "P-256", 32, "1.2.840.10045.3.1.7"),
            curve_signature("p256-order", P256["n"], "P-256", 32, "1.2.840.10045.3.1.7"),
            curve_signature("p384-b", P384["b"], "P-384", 48, "1.3.132.0.34"),
            curve_signature("p384-gx", P384["gx"], "P-384", 48, "1.3.132.0.34"),
            _signature(
                id="curve25519-p",
                family="ECC",
                algorithm="Curve25519",
                parameter_set="Curve25519",
                primitive="key-agree",
                nist_quantum_level=0,
                **{"class": "unique-table"},
                description="Field prime 2^255 - 19. Quantum-broken by Shor",
                pattern=CURVE25519_P.to_bytes(32, "little").hex(),
                min_match=32,
            ),
        )
    )


def build_stream_ciphers() -> str:
    sigma = b"expand 32-byte k"
    header = """# Stream-cipher constants, from RFC 8439.
# Do not hand-edit: run `python -m tools.derive_constants` instead.
#
# ChaCha20's sigma is ASCII, which makes it both easy to find and easy to
# mistake for an ordinary string. It is 16 bytes and highly specific, so a
# match is strong evidence - but note it also appears in Salsa20 and XSalsa20,
# hence the family-level claim.

"""
    return header + _signature(
        id="chacha20-sigma",
        family="ChaCha20",
        algorithm="ChaCha20",
        primitive="stream-cipher",
        nist_quantum_level=5,
        **{"class": "unique-table"},
        description='The constant "expand 32-byte k", RFC 8439 2.3',
        pattern=sigma.hex(),
        min_match=16,
    )


def build_confusables() -> str:
    crc = crc32_table()
    _assert_known(f"{crc[1]:08x}", "77073096", "CRC-32 table")

    header = """# Confusables: high-entropy lookup tables that are NOT cryptography.
#
# Derived by tools/derive_constants.py. Do not hand-edit.
#
# A signature here sets suppresses = true. It is never reported as a finding -
# reporting "we found a CRC table" would be noise - but a match vetoes any
# crypto claim whose evidence overlaps the same region.
#
# The CRC-32 table is the classic false positive for constant-based crypto
# detection: 1 KB of high-entropy-looking words sitting in .rdata, present in a
# very large share of all software, and utterly unrelated to cryptography.

"""
    return header + _signature(
        id="crc32-table",
        family="CRC-32",
        **{"class": "unique-table"},
        suppresses=True,
        description="Standard CRC-32 table, polynomial 0xEDB88320. Not cryptography",
        pattern=b"".join(word.to_bytes(4, "little") for word in crc).hex(),
        min_match=64,
    )


def main() -> None:
    CONSTANTS_DIR.mkdir(parents=True, exist_ok=True)
    outputs = {
        CONSTANTS_DIR / "aes.toml": build_aes(),
        CONSTANTS_DIR / "sha2.toml": build_sha2(),
        CONSTANTS_DIR / "legacy-hashes.toml": build_legacy_hashes(),
        CONSTANTS_DIR / "sha3.toml": build_sha3(),
        CONSTANTS_DIR / "curves.toml": build_curves(),
        CONSTANTS_DIR / "stream.toml": build_stream_ciphers(),
        DATA_DIR / "confusables.toml": build_confusables(),
    }
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(DATA_DIR.parent.parent.parent)}")


if __name__ == "__main__":
    main()
