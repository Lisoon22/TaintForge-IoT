#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$PROJECT_ROOT/samples/phase2_demo_i386.S"
OBJECT="$PROJECT_ROOT/build/phase2_demo_i386.o"
OUTPUT="$PROJECT_ROOT/samples/phase2_demo_i386"

for tool in as ld file readelf; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[-] Required build tool is missing: $tool" >&2
        exit 1
    fi
done

mkdir -p "$PROJECT_ROOT/build"

as --32 -o "$OBJECT" "$SOURCE"
ld -m elf_i386 -nostdlib -o "$OUTPUT" "$OBJECT"
chmod 0755 "$OUTPUT"

ELF_HEADER="$(LC_ALL=C readelf -hW "$OUTPUT")"
if ! grep -Eq 'Class:[[:space:]]+ELF32' <<<"$ELF_HEADER" \
    || ! grep -Eq 'Data:[[:space:]]+2.s complement, little endian' <<<"$ELF_HEADER" \
    || ! grep -Eq 'Type:[[:space:]]+EXEC' <<<"$ELF_HEADER" \
    || ! grep -Eq 'Machine:[[:space:]]+Intel 80386' <<<"$ELF_HEADER"; then
    echo "[-] Demo target is not an ELF32 little-endian i386 executable" >&2
    LC_ALL=C file "$OUTPUT" >&2 || true
    printf '%s\n' "$ELF_HEADER" >&2
    exit 1
fi

if readelf -lW "$OUTPUT" | grep -q INTERP; then
    echo "[-] Demo target unexpectedly contains PT_INTERP" >&2
    exit 1
fi

echo "[+] Built reproducible Phase 2 demo target: $OUTPUT"
file "$OUTPUT"
