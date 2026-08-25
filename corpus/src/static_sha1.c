/* Statically linked SHA-1 (FIPS 180-4). Labels: SHA-1 by constants.
 * Only two short tables - a 20-byte IV and four round constants - so this is
 * the corpus's weakest constant signal and a fair test of whether min_match
 * anchoring holds up when there is not much to anchor to. */
#include <stdint.h>
#include <string.h>
#include "_sink.h"

static const uint32_t IV[5] = {0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
static const uint32_t K[4]  = {0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6};

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

int main(int argc, char **argv) {
    uint32_t h[5], w[80], a,b,c,d,e;
    int i;
    (void)argv;
    memcpy(h, IV, sizeof h);
    for (i = 0; i < 16; i++) w[i] = (uint32_t)seed_byte(argc) * (uint32_t)(i + 1);
    for (i = 16; i < 80; i++) w[i] = ROL(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k = K[i/20];
        if (i < 20)      f = (b & c) | (~b & d);
        else if (i < 40) f = b ^ c ^ d;
        else if (i < 60) f = (b & c) | (b & d) | (c & d);
        else             f = b ^ c ^ d;
        { uint32_t t = ROL(a,5) + f + e + k + w[i];
          e = d; d = c; c = ROL(b,30); b = a; a = t; }
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
    sink(h, sizeof h);
    return 0;
}
