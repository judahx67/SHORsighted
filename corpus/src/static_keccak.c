/* Statically linked Keccak-f[1600] permutation (FIPS 202). Labels: SHA-3.
 * The 24 round constants are an LFSR sequence and appear in every SHA-3,
 * SHAKE, and Keccak implementation - including the ones inside post-quantum
 * schemes, which is why finding them says "SHA-3 family" and not more. */
#include <stdint.h>
#include <string.h>
#include "_sink.h"

static const uint64_t RC[24] = {
0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};

static const int RHO[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int PI[24]  = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

#define ROL64(x,n) (((x) << (n)) | ((x) >> (64 - (n))))

int main(int argc, char **argv) {
    uint64_t a[25], b[5], t;
    int round, i, j;
    (void)argv;
    for (i = 0; i < 25; i++) a[i] = (uint64_t)seed_byte(argc) * (uint64_t)(i + 1);
    for (round = 0; round < 24; round++) {
        for (i = 0; i < 5; i++) b[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20];
        for (i = 0; i < 5; i++) {
            t = b[(i+4)%5] ^ ROL64(b[(i+1)%5], 1);
            for (j = 0; j < 25; j += 5) a[i+j] ^= t;
        }
        t = a[1];
        for (i = 0; i < 24; i++) { j = PI[i]; b[0] = a[j]; a[j] = ROL64(t, RHO[i]); t = b[0]; }
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) b[i] = a[j+i];
            for (i = 0; i < 5; i++) a[j+i] = b[i] ^ (~b[(i+1)%5] & b[(i+2)%5]);
        }
        a[0] ^= RC[round];
    }
    sink(a, sizeof a);
    return 0;
}
