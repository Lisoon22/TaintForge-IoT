#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$PROJECT_ROOT/samples/c2_record_client.c"
OUTPUT="$PROJECT_ROOT/samples/c2_record_client_x86_64"

if ! command -v gcc >/dev/null 2>&1; then
    echo "[-] gcc was not found" >&2
    exit 1
fi

echo "[+] Building static x86_64 network client"

gcc \
    -static \
    -O2 \
    -Wall \
    -Wextra \
    -Werror \
    -o "$OUTPUT" \
    "$SOURCE"

chmod 0755 "$OUTPUT"

echo "[+] Built: $OUTPUT"
file "$OUTPUT"

if ! file "$OUTPUT" | grep -q "statically linked"; then
    echo "[-] Result is not statically linked" >&2
    exit 1
fi
