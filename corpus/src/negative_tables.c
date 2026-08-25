/* Lookup tables that are not cryptography: a base64 alphabet, a fixed-point
 * sine table, a UTF-8 length table.
 *
 * Table-driven does not mean cryptographic, and a detector that cannot tell
 * the difference is a nuisance generator. Expected findings: none.
 *
 * The sine table is deliberately provocative - MD5's T constants are also
 * derived from sines, and this is the nearest honest confusable to them. */
#include <stdint.h>
#include "_sink.h"

static const char b64[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint16_t sine_q15[64] = {
0,804,1608,2410,3212,4011,4808,5602,6393,7179,7962,8739,9512,10278,11039,11793,
12539,13279,14010,14732,15446,16151,16846,17530,18204,18868,19519,20159,20787,21403,22005,22594,
23170,23731,24279,24811,25329,25832,26319,26790,27245,27683,28105,28510,28898,29268,29621,29956,
30273,30571,30852,31113,31356,31580,31785,31971,32137,32285,32412,32521,32609,32678,32728,32757};

static const uint8_t utf8_len[16] = {1,1,1,1,1,1,1,1,0,0,0,0,2,2,3,4};

int main(int argc, char **argv) {
    unsigned char out[64];
    int i;
    (void)argv;
    for (i = 0; i < 64; i++)
        out[i] = (unsigned char)(b64[(seed_byte(argc) + i) & 63]
                                 ^ (sine_q15[i & 63] >> 8)
                                 ^ utf8_len[i & 15]);
    sink(out, sizeof out);
    return 0;
}
