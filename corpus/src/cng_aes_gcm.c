/* CNG AES-GCM. Labels: CNG (import-generic) + AES (utf16-string corroborated).
 * The algorithm name reaches the binary as BCRYPT_AES_ALGORITHM = L"AES",
 * which is the whole reason design §4's corroboration rule exists. */
#include <windows.h>
#include <bcrypt.h>
#include "_sink.h"

int main(int argc, char **argv) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    unsigned char keybytes[16], iv[12], pt[32], ct[64];
    ULONG written = 0;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    unsigned char tag[16];
    int i;
    (void)argv;

    for (i = 0; i < 16; i++) keybytes[i] = (unsigned char)(seed_byte(argc) + i);
    for (i = 0; i < 12; i++) iv[i] = (unsigned char)i;
    for (i = 0; i < 32; i++) pt[i] = (unsigned char)(i ^ argc);

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 1;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) return 1;
    if (BCryptGenerateSymmetricKey(alg, &key, NULL, 0, keybytes, sizeof keybytes, 0) != 0) return 1;

    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = iv; info.cbNonce = sizeof iv;
    info.pbTag = tag;  info.cbTag = sizeof tag;

    if (BCryptEncrypt(key, pt, sizeof pt, &info, NULL, 0, ct, sizeof ct, &written, 0) != 0) return 1;

    sink(ct, written);
    sink(tag, sizeof tag);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}
