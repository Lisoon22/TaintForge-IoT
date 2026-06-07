from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class SandboxRunConfig:
    rootfs: str
    guest_binary_path: str
    qemu_required: bool
    qemu_guest_path: str | None
    timeout_seconds: int = 60


class SandboxRunnerError(RuntimeError):
    pass


def load_runtime_config(path: str | Path) -> dict:
    path = Path(path)

    if not path.exists():
        raise SandboxRunnerError(f"runtime.json not found: {path}")

    return json.loads(path.read_text(encoding="utf-8"))


def build_sandbox_run_config(runtime_config_path: str | Path, timeout_seconds: int = 60) -> SandboxRunConfig:
    raw = load_runtime_config(runtime_config_path)

    return SandboxRunConfig(rootfs=raw["rootfs"], guest_binary_path=raw["guest_binary_path"], qemu_required=bool(raw["qemu_required"]), qemu_guest_path=raw.get("qemu_guest_path"), timeout_seconds=timeout_seconds)


def generate_run_sandbox_script(config: SandboxRunConfig,out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if config.qemu_required:
        if not config.qemu_guest_path:
            raise SandboxRunnerError("qemu_required=true but qemu_guest_path is missing")

        exec_part = f'{config.qemu_guest_path} {config.guest_binary_path}'
    else:
        exec_part = config.guest_binary_path

    script = f"""#!/usr/bin/env bash
set -euo pipefail

ROOTFS="$(cd "$(dirname "$0")/rootfs" && pwd)"
LOG_DIR="$(cd "$(dirname "$0")/logs" && pwd)"

mkdir -p "$LOG_DIR"

ulimit -t 30
ulimit -v 262144
ulimit -n 64
ulimit -u 64
ulimit -f 10240

echo " Starting sandbox"
echo " ROOTFS=$ROOTFS"
echo " Command: chroot $ROOTFS {exec_part}"

timeout --kill-after=5s {config.timeout_seconds}s \\
  sudo chroot "$ROOTFS" {exec_part} \\
  > "$LOG_DIR/runtime_stdout.log" \\
  2> "$LOG_DIR/runtime_stderr.log"

echo " Finished"
echo " stdout: $LOG_DIR/runtime_stdout.log"
echo " stderr: $LOG_DIR/runtime_stderr.log"
"""

    out_path.write_text(script, encoding="utf-8")
    out_path.chmod(0o755)
