#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

OUT_DIR="${1:-workdir/c2_record_e2e}"
MOCK_LOG="$OUT_DIR/mock_c2.log"
MOCK_PID=""

cleanup() {
    local exit_code=$?

    if [[ -n "$MOCK_PID" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi

    exit "$exit_code"
}
trap cleanup EXIT INT TERM

required_files=(
    "scripts/run_sample.py"
    "scripts/mock_c2_server.py"
    "scripts/start_c2_record_broker.py"
    "taintforge_env/c2_record_policy.py"
    "taintforge_env/c2_record_broker.py"
    "examples/c2_record_e2e_taint.json"
    "examples/c2_record_e2e_policy.json"
)

for path in "${required_files[@]}"; do
    if [[ ! -f "$path" ]]; then
        echo "[-] Missing required file: $path" >&2
        echo "[-] Install Step 5A and Step 5B first" >&2
        exit 1
    fi
done

if [[ ! -x samples/c2_record_client_x86_64 ]]; then
    "$PROJECT_ROOT/scripts/build_c2_record_client.sh"
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

echo "[+] Starting local mock C2 on 127.0.0.1:49001"

PYTHONPATH=. python scripts/mock_c2_server.py \
    --bind-ip 127.0.0.1 \
    --port 49001 \
    --response-hex 776f726c64 \
    >"$MOCK_LOG" 2>&1 &

MOCK_PID=$!

python - "$MOCK_PID" <<'PY'
import os
import socket
import sys
import time

pid = int(sys.argv[1])
deadline = time.monotonic() + 5.0

while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except OSError:
        raise SystemExit(
            "mock C2 process exited before becoming ready"
        )

    try:
        with socket.create_connection(
            ("127.0.0.1", 49001),
            timeout=0.2,
        ):
            pass
    except OSError:
        time.sleep(0.1)
        continue

    raise SystemExit(0)

raise SystemExit("timed out waiting for mock C2")
PY

echo "[+] Running full Phase 2 pipeline in brokered_record mode"

PYTHONPATH=. python scripts/run_sample.py \
    --taint examples/c2_record_e2e_taint.json \
    --binary samples/c2_record_client_x86_64 \
    --out "$OUT_DIR" \
    --network brokered_record \
    --record-policy examples/c2_record_e2e_policy.json \
    --timeout 30

echo "[+] Validating the captured session"

PYTHONPATH=. python \
    scripts/validate_c2_record_capture.py \
    --out "$OUT_DIR"

echo
echo "[+] End-to-end local recording test passed"
echo "    output: $OUT_DIR"
echo "    mock log: $MOCK_LOG"

find "$OUT_DIR/captures" \
    -maxdepth 4 \
    -type f \
    -print \
    | sort
