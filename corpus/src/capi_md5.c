/* Legacy CryptoAPI MD5 via advapi32. Labels: CryptoAPI.
 *
 * No algorithm label: CALG_MD5 is a 32-bit integer constant compiled into an
 * instruction, not a string in .rdata, so nothing in the file names the
 * algorithm. That is a real limitation of import-based detection on the legacy
 * API and the corpus records it as one rather than papering over it. */
#include <windows.h>
#include <wincrypt.h>
#include "_sink.h"

int main(int argc, char **argv) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    unsigned char message[32], digest[16];
    DWORD len = sizeof digest;
    int i;
    (void)argv;

    for (i = 0; i < 32; i++) message[i] = (unsigned char)(seed_byte(argc) + i);

    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 1;
    if (!CryptCreateHash(prov, CALG_MD5, 0, 0, &hash)) return 1;
    if (!CryptHashData(hash, message, sizeof message, 0)) return 1;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &len, 0)) return 1;

    sink(digest, len);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return 0;
}
