#!/bin/sh
# tests/run.sh — fixture generation + unit + integration (invoked by make test)
set -eu
cd "$(dirname "$0")"
MODE="${1:-NORMAL}"
mkdir -p tmp

if ! command -v openssl >/dev/null 2>&1; then
    echo "FATAL: openssl is required for test fixtures" >&2
    exit 1
fi

# Unit-test CA fixture (valid PEM, bad base64, and a whitelisted symlink)
openssl req -x509 -newkey rsa:2048 -nodes -keyout tmp/unit-ca.key \
    -out tmp/ca.pem -days 3650 -subj '/CN=miniddns Unit Test CA' >/dev/null 2>&1
printf '%s\n' '-----BEGIN CERTIFICATE-----' '!!!not-base64!!!' \
    '-----END CERTIFICATE-----' > tmp/bad.pem
mkdir -p ca
cp tmp/ca.pem ca/ca-certificates.crt
cp tmp/ca.pem ca/test-ca.pem
chmod 0644 ca/ca-certificates.crt ca/test-ca.pem
ln -sf test-ca.pem ca/test-ca-link.pem
cleanup() { rm -rf "$PWD/ca"; }
trap cleanup EXIT INT TERM

if [ "$MODE" = "ASAN" ]; then
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 ./build/unit
    echo "ASan build: integration tests skipped (LD_PRELOAD conflicts with sanitizer runtime)"
else
    ./build/unit
    python3 integration.py
fi
