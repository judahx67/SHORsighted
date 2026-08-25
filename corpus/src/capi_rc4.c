/* Legacy CryptoAPI RC4. Labels: CryptoAPI. Same integer-constant limitation as
 * capi_md5.c — the API is generic and the algorithm never appears as text. */
#include <windows.h>
#include <wincrypt.h>
#include "_sink.h"

int main(int argc, char **argv) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    HCRYPTKEY key = 0;
    unsigned char secret[16], buffer[32];
    DWORD len = sizeof buffer;
    int i;
    (void)argv;

    for (i = 0; i < 16; i++) secret[i] = (unsigned char)(seed_byte(argc) ^ i);
    for (i = 0; i < 32; i++) buffer[i] = (unsigned char)i;

    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 1;
    if (!CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash)) return 1;
    if (!CryptHashData(hash, secret, sizeof secret, 0)) return 1;
    if (!CryptDeriveKey(prov, CALG_RC4, hash, 0, &key)) return 1;
    if (!CryptEncrypt(key, 0, TRUE, 0, buffer, &len, sizeof buffer)) return 1;

    sink(buffer, len);
    CryptDestroyKey(key);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return 0;
}
