#!/bin/sh
# Regenerate the throwaway corpus material. Needs OpenSSL; the corpus build
# does not — that is the point of committing the output.
set -eu
cd "$(dirname "$0")"
openssl genrsa -out key-pkcs1.pem 2048
openssl pkcs8 -topk8 -nocrypt -in key-pkcs1.pem -out key.pem
mv key-pkcs1.pem rsa-key.pem
openssl rsa -in rsa-key.pem -traditional -outform DER -out rsa-key.der
MSYS2_ARG_CONV_EXCL='*' openssl req -x509 -key key.pem -out cert.pem -days 36500 \
  -subj "/CN=SHORsighted corpus throwaway/O=NOT A REAL KEY"
openssl x509 -in cert.pem -outform DER -out cert.der
