from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class SandboxRunConfig:
    rootfs: str
    guest_binary_path: str
    qemu_required: bool
    qemu_guest_path: str | None
    timeout_seconds: int = 60
    network_mode: str = "none"


class SandboxRunnerError(RuntimeError):
    pass


def load_runtime_config(path: str | Path) -> dict:
    source = Path(path)
    if not source.is_file():
        raise SandboxRunnerError(f"runtime.json not found: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxRunnerError(f"invalid runtime.json: {exc}") from exc
    if not isinstance(raw, dict):
        raise SandboxRunnerError("runtime.json must contain an object")
    return raw


def build_sandbox_run_config(
    runtime_config_path: str | Path,
    timeout_seconds: int = 60,
    network_mode: str = "none",
) -> SandboxRunConfig:
    if timeout_seconds <= 0:
        raise SandboxRunnerError("timeout_seconds must be positive")
    if network_mode != "none":
        raise SandboxRunnerError(
            f"unsupported disconnected sandbox mode: {network_mode}"
        )

    raw = load_runtime_config(runtime_config_path)
    guest_binary = raw.get("guest_binary_path")
    if not isinstance(guest_binary, str) or not guest_binary.startswith("/"):
        raise SandboxRunnerError("runtime guest_binary_path must be absolute")

    qemu_required = bool(raw.get("qemu_required"))
    if qemu_required:
        raise SandboxRunnerError(
            "legacy disconnected runner cannot inject QEMU safely; "
            "use run_prebuilt_iteration.py for foreign architectures"
        )

    return SandboxRunConfig(
        rootfs=str(raw["rootfs"]),
        guest_binary_path=guest_binary,
        qemu_required=False,
        qemu_guest_path=None,
        timeout_seconds=timeout_seconds,
        network_mode=network_mode,
    )


def generate_run_sandbox_script(
    config: SandboxRunConfig,
    out_path: str | Path,
) -> None:
    if config.network_mode != "none":
        raise SandboxRunnerError(
            f"unsupported disconnected sandbox mode: {config.network_mode}"
        )
    if config.qemu_required:
        raise SandboxRunnerError(
            "QEMU execution is not supported by the legacy disconnected runner"
        )

    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    guest_binary = shlex.quote(config.guest_binary_path)

    script = f'''#!/usr/bin/env bash
set -euo pipefail

ROOTFS="$(cd "$(dirname "$0")/rootfs" && pwd)"
LOG_DIR="$(cd "$(dirname "$0")/logs" && pwd)"
GUEST_BINARY={guest_binary}
TIMEOUT_SECONDS={config.timeout_seconds}

STATUS_PATH="$LOG_DIR/runtime_status.json"
SECURITY_STATUS_PATH="$LOG_DIR/security_status.json"
STDOUT_PATH="$LOG_DIR/runtime_stdout.log"
STDERR_PATH="$LOG_DIR/runtime_stderr.log"
STRACE_PREFIX="$LOG_DIR/strace"

mkdir -p "$LOG_DIR"
: > "$STDOUT_PATH"
: > "$STDERR_PATH"
rm -f "$STATUS_PATH" "$SECURITY_STATUS_PATH"

PRIVILEGED=()
if [[ "$EUID" -ne 0 ]]; then
  PRIVILEGED=(sudo)
fi

START_EPOCH="$(date +%s)"
START_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

set +e
timeout --signal=TERM --kill-after=5s "${{TIMEOUT_SECONDS}}s" \
  "${{PRIVILEGED[@]}}" unshare \
    --mount \
    --pid \
    --fork \
    --uts \
    --ipc \
    --net \
    --kill-child=SIGKILL \
    -- \
    /bin/bash -c '
      set -euo pipefail

      ROOTFS="$1"
      LOG_DIR="$2"
      GUEST_BINARY="$3"
      STRACE_PREFIX="$4"

      mount --make-rprivate /
      ip link set lo up
      hostname taintforge-iot

      ulimit -t 30
      ulimit -v 524288
      ulimit -n 256
      ulimit -f 10240
      ulimit -u 256 2>/dev/null || true
      umask 077

      GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
      cat > "$LOG_DIR/security_status.json" <<EOF
{{
  "generated_at_utc": "$GENERATED_AT",
  "isolation_ready": true,
  "chroot": true,
  "network_namespace": true,
  "network_mode": "none",
  "network_connected": false,
  "network_default_deny": true,
  "pid_namespace": true,
  "mount_namespace": true,
  "uts_namespace": true,
  "ipc_namespace": true,
  "user_namespace": false,
  "mount_propagation": "private",
  "sandbox_hostname": "taintforge-iot",
  "proc_mode": "static_rootfs_stubs",
  "strace_enabled": true,
  "resource_limits": {{
    "cpu_seconds": 30,
    "virtual_memory_kb": 524288,
    "open_files": 256,
    "processes": 256,
    "file_size_blocks": 10240
  }},
  "limitations": [
    "sample runs as UID 0 inside the namespaces",
    "no user namespace",
    "no seccomp filter",
    "chroot and namespaces are not a virtual machine boundary"
  ]
}}
EOF

      exec strace -ff -yy -s 4096 -o "$STRACE_PREFIX" \
        env -i PATH=/usr/bin:/bin HOME=/ LANG=C LC_ALL=C \
        chroot "$ROOTFS" "$GUEST_BINARY"
    ' bash "$ROOTFS" "$LOG_DIR" "$GUEST_BINARY" "$STRACE_PREFIX" \
    > "$STDOUT_PATH" 2> "$STDERR_PATH"
EXIT_CODE="$?"
set -e

END_EPOCH="$(date +%s)"
END_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
DURATION_SECONDS="$((END_EPOCH - START_EPOCH))"

TIMED_OUT=false
if [[ "$EXIT_CODE" -eq 124 || "$EXIT_CODE" -eq 137 ]]; then
  TIMED_OUT=true
fi

ISOLATION_READY=false
if [[ -f "$SECURITY_STATUS_PATH" ]]; then
  ISOLATION_READY=true
fi

cat > "$STATUS_PATH" <<EOF
{{
  "command": "unshare --mount --pid --uts --ipc --net chroot $ROOTFS $GUEST_BINARY",
  "network_mode": "none",
  "network_connected": false,
  "rootfs": "$ROOTFS",
  "guest_command": "$GUEST_BINARY",
  "exit_code": $EXIT_CODE,
  "timed_out": $TIMED_OUT,
  "timeout_seconds": $TIMEOUT_SECONDS,
  "started_at_utc": "$START_UTC",
  "finished_at_utc": "$END_UTC",
  "duration_seconds": $DURATION_SECONDS,
  "isolation_ready": $ISOLATION_READY,
  "stdout_path": "$STDOUT_PATH",
  "stderr_path": "$STDERR_PATH",
  "strace_enabled": true,
  "strace_prefix": "$STRACE_PREFIX"
}}
EOF

if [[ "$ISOLATION_READY" != true ]]; then
  exit 125
fi

exit 0
'''

    destination.write_text(script, encoding="utf-8")
    destination.chmod(0o755)
