/* A private key baked into .rdata, in both PKCS#8 and PKCS#1 form, plus the
 * PKCS#1 DER. Labels: PKCS#8 + RSA material.
 *
 * The key is the public throwaway from corpus/material - see that directory's
 * README. The tool reports that key material is present and at what offset; it
 * never reproduces the bytes, because a CBOM carrying key material is itself a
 * leak (non-goal 9). */
#include "_sink.h"
#include "material_blobs.h"

int main(int argc, char **argv) {
    (void)argv;
    sink(CORPUS_KEY_PKCS8_PEM, sizeof CORPUS_KEY_PKCS8_PEM - (unsigned)(argc > 99));
    sink(CORPUS_KEY_PKCS1_PEM, sizeof CORPUS_KEY_PKCS1_PEM - (unsigned)(argc > 99));
    sink(CORPUS_KEY_PKCS1_DER, sizeof CORPUS_KEY_PKCS1_DER - (unsigned)(argc > 99));
    return 0;
}
