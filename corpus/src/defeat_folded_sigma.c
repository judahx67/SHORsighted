/* ChaCha20 whose sigma the optimiser folded away. WE MISS THIS AT -O2.
 *
 * Identical to static_chacha20.c except the constant is copied with memcpy
 * rather than read through a volatile pointer. At -O0 the sixteen bytes sit in
 * .rdata and we find them; at -O2 the compiler turns them into four immediate
 * moves and there is nothing left in the file to match.
 *
 * No evasion, no obfuscation - just -O2. Short constants are fragile in a way
 * a 256-byte S-box is not, and this is the sample that measures how fragile.
 * Ground truth: ChaCha20, at every optimisation level. */
#include <stdint.h>
#include <string.h>
#include "_sink.h"

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

int main(int argc, char **argv) {
    uint32_t state[16];
    int i;
    (void)argv;
    memcpy(state, "expand 32-byte k", 16);
    for (i = 4; i < 16; i++) state[i] = (uint32_t)seed_byte(argc) * (uint32_t)(i + 7);
    for (i = 0; i < 16; i++) state[i] = ROL(state[i], 7) ^ state[(i + 1) & 15];
    sink(state, sizeof state);
    return 0;
}
