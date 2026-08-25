/* AES with the S-box computed at startup instead of stored. WE MISS THIS.
 *
 * The table is built from the multiplicative inverse in GF(2^8), so the binary
 * contains the *derivation* and never the table. Constant detection has
 * nothing to match; import detection has nothing to read. This is the honest
 * ceiling of static byte analysis and belongs in LIMITATIONS.md, not in a
 * footnote.
 *
 * The fix is a disassembly-based detector, which is roadmap v0.3 and a much
 * bigger tool than this one. Expected findings: none. Ground truth: AES. */
#include <stdint.h>
#include <string.h>
#include "_sink.h"

static uint8_t sbox[256];

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = (uint8_t)((a << 1) ^ ((a >> 7) * 0x1b));
        b >>= 1;
    }
    return p;
}

static void build_sbox(void) {
    uint8_t inverse[256];
    int i, j;
    inverse[0] = 0;
    for (i = 1; i < 256; i++)
        for (j = 1; j < 256; j++)
            if (gmul((uint8_t)i, (uint8_t)j) == 1) { inverse[i] = (uint8_t)j; break; }
    for (i = 0; i < 256; i++) {
        uint8_t x = inverse[i], s = x;
        int r;
        for (r = 0; r < 4; r++) { s = (uint8_t)((s << 1) | (s >> 7)); x ^= s; }
        sbox[i] = (uint8_t)(x ^ 0x63);
    }
}

int main(int argc, char **argv) {
    uint8_t block[16];
    int i;
    (void)argv;
    build_sbox();
    for (i = 0; i < 16; i++) block[i] = sbox[(seed_byte(argc) + i) & 0xff];
    sink(block, sizeof block);
    return 0;
}
