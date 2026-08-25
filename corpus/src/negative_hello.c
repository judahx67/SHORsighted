/* The control. No cryptography of any kind.
 *
 * Anything found here is a false positive by construction - including whatever
 * the C runtime drags in, which is part of the measurement rather than an
 * excuse. If mingw's startup code contains something we call cryptography, the
 * eval should say so. */
#include "_sink.h"

int main(int argc, char **argv) {
    char buffer[64];
    int i;
    (void)argv;
    for (i = 0; i < 64; i++) buffer[i] = (char)('a' + ((seed_byte(argc) + i) % 26));
    sink(buffer, sizeof buffer);
    return 0;
}
