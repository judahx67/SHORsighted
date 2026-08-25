/* NIST P-256 stored as little-endian 64-bit limbs. WE MISS THIS.
 *
 * This is how a bignum library that works in machine words actually keeps
 * curve parameters, and it is a different byte sequence from the octet-string
 * form our signatures carry. Compare static_p256.c, which we do find.
 *
 * The gap is fixable - expand curve patterns into limb layouts the way word
 * tables already are - and is recorded rather than hidden.
 * Expected findings: none. Ground truth: ECC/P-256. */
#include <stdint.h>
#include "_sink.h"

/* b, as four 64-bit limbs, least significant first. */
static const uint64_t P256_B[4] = {
0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL, 0xb3ebbd55769886bcULL, 0x5ac635d8aa3a93e7ULL};

/* Gx, same layout. */
static const uint64_t P256_GX[4] = {
0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL, 0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL};

int main(int argc, char **argv) {
    uint64_t acc[4];
    int i;
    (void)argv;
    for (i = 0; i < 4; i++) acc[i] = P256_B[i] ^ P256_GX[i] ^ (uint64_t)seed_byte(argc);
    sink(acc, sizeof acc);
    return 0;
}
