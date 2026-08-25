/* CNG RSA signing. Labels: CNG + RSA (quantum level 0) + SHA-2/256. */
#include <windows.h>
#include <bcrypt.h>
#include "_sink.h"

int main(int argc, char **argv) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    unsigned char digest[32], sig[512];
    ULONG written = 0;
    BCRYPT_PKCS1_PADDING_INFO padding;
    int i;
    (void)argv;

    padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    for (i = 0; i < 32; i++) digest[i] = (unsigned char)(seed_byte(argc) + i);

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0) != 0) return 1;
    if (BCryptGenerateKeyPair(alg, &key, 2048, 0) != 0) return 1;
    if (BCryptFinalizeKeyPair(key, 0) != 0) return 1;
    if (BCryptSignHash(key, &padding, digest, sizeof digest, sig, sizeof sig,
                       &written, BCRYPT_PAD_PKCS1) != 0) return 1;

    sink(sig, written);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}
