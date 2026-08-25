/* CRC-32, the classic false positive for constant-based crypto detection.
 *
 * A kilobyte of high-entropy-looking words in .rdata, present in a very large
 * share of all software, and not cryptography. The confusables suppressor
 * exists for exactly this file; if it stops working, this sample is where it
 * shows. Expected findings: none. */
#include <stdint.h>
#include "_sink.h"

static uint32_t table[256];
static int built = 0;

static void build(void) {
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
        table[i] = c;
    }
    built = 1;
}

int main(int argc, char **argv) {
    uint32_t crc = 0xffffffffu;
    unsigned char data[64];
    int i;
    (void)argv;
    if (!built) build();
    for (i = 0; i < 64; i++) data[i] = (unsigned char)(seed_byte(argc) + i);
    for (i = 0; i < 64; i++) crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    crc ^= 0xffffffffu;
    sink(&crc, sizeof crc);
    return 0;
}
