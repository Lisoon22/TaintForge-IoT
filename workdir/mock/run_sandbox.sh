#!/usr/bin/env bash
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
echo " Command: chroot $ROOTFS /bin/unpacked.elf"

timeout --kill-after=5s 60s \
  sudo chroot "$ROOTFS" /bin/unpacked.elf \
  > "$LOG_DIR/runtime_stdout.log" \
  2> "$LOG_DIR/runtime_stderr.log"

echo " Finished"
echo " stdout: $LOG_DIR/runtime_stdout.log"
echo " stderr: $LOG_DIR/runtime_stderr.log"
