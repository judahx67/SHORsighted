/* CNG SHA-256. Labels: CNG + SHA-2/256 (via L"SHA256"). */
#include <windows.h>
#include <bcrypt.h>
#include "_sink.h"

int main(int argc, char **argv) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char message[64], digest[32];
    int i;
    (void)argv;

    for (i = 0; i < 64; i++) message[i] = (unsigned char)(seed_byte(argc) ^ i);

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return 1;
    if (BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0) != 0) return 1;
    if (BCryptHashData(hash, message, sizeof message, 0) != 0) return 1;
    if (BCryptFinishHash(hash, digest, sizeof digest, 0) != 0) return 1;

    sink(digest, sizeof digest);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}
