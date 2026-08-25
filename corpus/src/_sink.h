/* Keep the optimiser honest.
 *
 * Every corpus sample must still contain the cryptography it is labelled with
 * after -O2. A table nobody reads is dead code, and a result nobody prints is a
 * dead store; either one lets the compiler delete the very thing the sample
 * exists to demonstrate, and the eval would then measure our build script
 * rather than the detector.
 *
 * So: input comes from argc (unknowable at compile time) and output goes
 * through sink(), which the compiler cannot see through. */
#ifndef CORPUS_SINK_H
#define CORPUS_SINK_H
#include <stdio.h>
#include <stddef.h>

static void sink(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    unsigned long acc = 0;
    size_t i;
    for (i = 0; i < len; i++) acc = acc * 31u + p[i];
    printf("%08lx\n", acc);
}

/* A seed the compiler cannot fold away. */
static unsigned char seed_byte(int argc) { return (unsigned char)(argc * 37 + 11); }

#endif
