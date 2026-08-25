/* A PEM certificate baked into .rdata. Labels: X.509 certificate (material).
 * Pinned roots ship this way constantly, and an inventory that cannot see them
 * cannot answer "what does this binary trust". */
#include "_sink.h"
#include "material_blobs.h"

int main(int argc, char **argv) {
    (void)argv;
    sink(CORPUS_CERT_PEM, sizeof CORPUS_CERT_PEM - (unsigned)(argc > 99));
    return 0;
}
