/* CNG ECDSA P-256. Labels: CNG + ECDSA/P-256 (quantum level 0) + SHA-2/256. */
#include <windows.h>
#include <bcrypt.h>
#include "_sink.h"

int main(int argc, char **argv) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    unsigned char digest[32], sig[128];
    ULONG written = 0;
    int i;
    (void)argv;

    for (i = 0; i < 32; i++) digest[i] = (unsigned char)(seed_byte(argc) * i);

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0) != 0) return 1;
    if (BCryptGenerateKeyPair(alg, &key, 256, 0) != 0) return 1;
    if (BCryptFinalizeKeyPair(key, 0) != 0) return 1;
    if (BCryptSignHash(key, NULL, digest, sizeof digest, sig, sizeof sig, &written, 0) != 0) return 1;

    sink(sig, written);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}
