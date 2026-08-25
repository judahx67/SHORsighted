/* A DER certificate baked into .rdata. Labels: X.509 certificate (material).
 * No banner text to find here - the only signal is the DER structure itself,
 * which is what the length-consistency validator in the heuristic detector is
 * for (D-7). */
#include "_sink.h"
#include "material_blobs.h"

int main(int argc, char **argv) {
    (void)argv;
    sink(CORPUS_CERT_DER, sizeof CORPUS_CERT_DER - (unsigned)(argc > 99));
    return 0;
}
