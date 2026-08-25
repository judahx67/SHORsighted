# Corpus material — PUBLIC THROWAWAY KEYS ♡

**Every private key in this directory is public. It is in a git repository on
the internet. Never use it for anything.**

It exists so `corpus/src/embedded_*.c` can bake real cryptographic material
into a real binary, so the heuristic detector (FR-8, AC-3) can be evaluated
against the genuine article rather than against a hand-forged imitation that
might happen to satisfy our own validator.

| File | What it is |
|---|---|
| `cert.pem` / `cert.der` | Self-signed X.509 v3 certificate, RSA-2048, SHA-256 |
| `key.pem` | The matching private key, PKCS#8 (`BEGIN PRIVATE KEY`) |
| `rsa-key.pem` / `rsa-key.der` | The same key, PKCS#1 (`BEGIN RSA PRIVATE KEY`) |

Regenerate with `./regenerate.sh` — but there is no reason to. The bytes are
committed precisely so the corpus builds with `zig cc` alone and needs no
OpenSSL.
