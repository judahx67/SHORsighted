/* Statically linked ChaCha20 (RFC 8439). Labels: ChaCha20 by constants.
 *
 * The whole signal is sixteen ASCII bytes, "expand 32-byte k". Short, but the
 * phrase does not occur by accident. Note it is shared with Salsa20 and
 * XSalsa20, which is why the signature claims the family and not the cipher.
 *
 * The sigma is read through a volatile pointer. Without that, -O2 folds the
 * sixteen bytes into immediate operands and the constant simply is not in the
 * file any more - which is real, and is why defeat_folded_sigma.c exists to
 * measure it separately instead of quietly turning this sample into a miss. */
#include <stdint.h>
#include <string.h>
#include "_sink.h"

static const char sigma[17] = "expand 32-byte k";

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a,b,c,d) \
    a += b; d ^= a; d = ROL(d,16); \
    c += d; b ^= c; b = ROL(b,12); \
    a += b; d ^= a; d = ROL(d, 8); \
    c += d; b ^= c; b = ROL(b, 7);

int main(int argc, char **argv) {
    const volatile char *source = sigma;
    uint32_t state[16], work[16];
    int i;
    (void)argv;
    for (i = 0; i < 16; i++) ((unsigned char *)state)[i] = (unsigned char)source[i];
    for (i = 4; i < 16; i++) state[i] = (uint32_t)seed_byte(argc) * (uint32_t)(i + 7);
    memcpy(work, state, sizeof work);
    for (i = 0; i < 10; i++) {
        QR(work[0], work[4], work[ 8], work[12])
        QR(work[1], work[5], work[ 9], work[13])
        QR(work[2], work[6], work[10], work[14])
        QR(work[3], work[7], work[11], work[15])
        QR(work[0], work[5], work[10], work[15])
        QR(work[1], work[6], work[11], work[12])
        QR(work[2], work[7], work[ 8], work[13])
        QR(work[3], work[4], work[ 9], work[14])
    }
    for (i = 0; i < 16; i++) work[i] += state[i];
    sink(work, sizeof work);
    return 0;
}
