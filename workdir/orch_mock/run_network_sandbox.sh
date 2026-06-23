#!/usr/bin/env bash
set -euo pipefail

NS="tf-iot-ns"
VETH_HOST="tf-veth-host"
VETH_NS="tf-veth-ns"

HOST_IP="10.10.0.1"
HOST_CIDR="10.10.0.1/24"
NS_IP="10.10.0.2"
NS_CIDR="10.10.0.2/24"

ROOTFS="$(cd "$(dirname "$0")/rootfs" && pwd)"
LOG_DIR="$(cd "$(dirname "$0")/logs" && pwd)"

mkdir -p "$LOG_DIR"

cleanup() {
  set +e
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del "$VETH_HOST" 2>/dev/null
  set -e
}

setup_netns() {
  cleanup

  echo "[+] Creating network namespace: $NS"
  sudo ip netns add "$NS"

  echo "[+] Creating veth pair: $VETH_HOST <-> $VETH_NS"
  sudo ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

  echo "[+] Moving $VETH_NS into namespace $NS"
  sudo ip link set "$VETH_NS" netns "$NS"

  echo "[+] Configuring host side: $HOST_CIDR"
  sudo ip addr add "$HOST_CIDR" dev "$VETH_HOST"
  sudo ip link set "$VETH_HOST" up

  echo "[+] Configuring namespace side: $NS_CIDR"
  sudo ip netns exec "$NS" ip addr add "$NS_CIDR" dev "$VETH_NS"
  sudo ip netns exec "$NS" ip link set "$VETH_NS" up
  sudo ip netns exec "$NS" ip link set lo up

  echo "[+] Adding default route inside namespace"
  sudo ip netns exec "$NS" ip route add default via "$HOST_IP"

  echo "[+] Applying iptables rules inside namespace"

  sudo ip netns exec "$NS" iptables -F
  sudo ip netns exec "$NS" iptables -t nat -F

  # Default-deny outbound traffic from malware namespace.
  sudo ip netns exec "$NS" iptables -P OUTPUT DROP
  sudo ip netns exec "$NS" iptables -P INPUT DROP
  sudo ip netns exec "$NS" iptables -P FORWARD DROP

  # Allow loopback.
  sudo ip netns exec "$NS" iptables -A OUTPUT -o lo -j ACCEPT
  sudo ip netns exec "$NS" iptables -A INPUT -i lo -j ACCEPT

  # Allow established traffic.
  sudo ip netns exec "$NS" iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo ip netns exec "$NS" iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Known endpoint redirects.
  sudo ip netns exec "$NS" iptables -t nat -A OUTPUT -p tcp -d 185.62.190.0 --dport 48101 -j DNAT --to-destination 10.10.0.1:48101

# Known endpoint allow rules.
  sudo ip netns exec "$NS" iptables -A OUTPUT -p tcp -d 10.10.0.1 --dport 48101 -j ACCEPT
  sudo ip netns exec "$NS" iptables -A INPUT -p tcp -s 10.10.0.1 --sport 48101 -j ACCEPT

# Catch-all unknown TCP redirect.
  # Transparent catch-all chains.
  sudo ip netns exec "$NS" iptables -t nat -N TF_TCP_CATCHALL 2>/dev/null || true
  sudo ip netns exec "$NS" iptables -t nat -N TF_UDP_CATCHALL 2>/dev/null || true
  sudo ip netns exec "$NS" iptables -t nat -F TF_TCP_CATCHALL
  sudo ip netns exec "$NS" iptables -t nat -F TF_UDP_CATCHALL
  # Do not redirect traffic to fake gateway.
  sudo ip netns exec "$NS" iptables -t nat -A TF_TCP_CATCHALL -d 10.10.0.1 -j RETURN
  sudo ip netns exec "$NS" iptables -t nat -A TF_UDP_CATCHALL -d 10.10.0.1 -j RETURN
  # Do not redirect loopback traffic.
  sudo ip netns exec "$NS" iptables -t nat -A TF_TCP_CATCHALL -d 127.0.0.0/8 -j RETURN
  sudo ip netns exec "$NS" iptables -t nat -A TF_UDP_CATCHALL -d 127.0.0.0/8 -j RETURN
  # Unknown TCP -> local transparent TCP logger.
  sudo ip netns exec "$NS" iptables -t nat -A TF_TCP_CATCHALL -p tcp -j REDIRECT --to-ports 40000
  # All unknown UDP -> local transparent UDP logger.
  sudo ip netns exec "$NS" iptables -t nat -A TF_UDP_CATCHALL -p udp -j REDIRECT --to-ports 40001
  # Attach catch-all chains after known endpoint DNAT rules.
  sudo ip netns exec "$NS" iptables -t nat -A OUTPUT -p tcp -j TF_TCP_CATCHALL
  sudo ip netns exec "$NS" iptables -t nat -A OUTPUT -p udp -j TF_UDP_CATCHALL
  # Allow unknown TCP/UDP attempts that are redirected by nat OUTPUT.
  sudo ip netns exec "$NS" iptables -A OUTPUT -p tcp ! -d 10.10.0.1 -j ACCEPT
  sudo ip netns exec "$NS" iptables -A OUTPUT -p udp ! -d 10.10.0.1 -j ACCEPT
  # Allow redirected local TCP/UDP traffic explicitly.
  sudo ip netns exec "$NS" iptables -A OUTPUT -p tcp --dport 40000 -j ACCEPT
  sudo ip netns exec "$NS" iptables -A INPUT -p tcp --sport 40000 -j ACCEPT
  sudo ip netns exec "$NS" iptables -A OUTPUT -p udp --dport 40001 -j ACCEPT
  sudo ip netns exec "$NS" iptables -A INPUT -p udp --sport 40001 -j ACCEPT
}

run_sample() {
  echo "[+] Starting sample in hardened controlled sandbox"
  echo "[+] ROOTFS=$ROOTFS"
  echo "[+] Namespace=$NS"
  echo "[+] Command inside chroot: /bin/unpacked.elf"

  STATUS_PATH="$LOG_DIR/runtime_status.json"
  SECURITY_STATUS_PATH="$LOG_DIR/security_status.json"
  RESOURCE_LIMITS_PATH="$LOG_DIR/resource_limits.txt"
  STDOUT_PATH="$LOG_DIR/runtime_stdout.log"
  STDERR_PATH="$LOG_DIR/runtime_stderr.log"
  STRACE_PREFIX="$LOG_DIR/strace"

  START_EPOCH="$(date +%s)"
  START_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  STRACE_ENABLED=false
  TRACE_MODE="plain"

  if command -v strace >/dev/null 2>&1; then
    STRACE_ENABLED=true
    TRACE_MODE="strace"
  fi

  rm -f "$SECURITY_STATUS_PATH"
  rm -f "$RESOURCE_LIMITS_PATH"

  set +e

  timeout --kill-after=5s 60s \
    sudo ip netns exec "$NS" \
      unshare \
        --fork \
        --pid \
        --mount \
        --uts \
        --ipc \
        --kill-child=SIGKILL \
        /bin/bash -c '
          set -euo pipefail

          ROOTFS="$1"
          LOG_DIR="$2"
          TRACE_MODE="$3"
          shift 3

          # Prevent mounts made in this namespace from propagating
          # back into the host mount namespace.
          mount --make-rprivate /

          # Fake device identity inside the private UTS namespace.
          hostname taintforge-iot

          # These limits are applied after sudo/ip/unshare.
          # Therefore they affect strace and the malware process tree,
          # not the privileged host-side wrappers.
          ulimit -t 30
          ulimit -v 524288
          ulimit -n 256
          ulimit -f 10240

          # RLIMIT_NPROC is best-effort for UID 0.
          ulimit -u 256 2>/dev/null || true

          umask 077

          ulimit -a > "$LOG_DIR/resource_limits.txt" 2>&1 || true

          STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

          cat > "$LOG_DIR/security_status.json" <<EOF
{
  "generated_at_utc": "$STARTED_AT",
  "isolation_ready": true,
  "network_namespace": true,
  "pid_namespace": true,
  "mount_namespace": true,
  "uts_namespace": true,
  "ipc_namespace": true,
  "user_namespace": false,
  "mount_propagation": "private",
  "sandbox_hostname": "taintforge-iot",
  "proc_mode": "static_rootfs_stubs",
  "strace_enabled": $([ "$TRACE_MODE" = "strace" ] && echo true || echo false),
  "resource_limits": {
    "cpu_seconds": 30,
    "virtual_memory_kb": 524288,
    "open_files": 256,
    "processes": 256,
    "processes_enforcement": "best_effort_for_uid_0",
    "file_size_blocks": 10240
  },
  "limitations": [
    "malware still runs as UID 0 inside chroot",
    "no user namespace",
    "no seccomp filter",
    "no cgroup memory or process enforcement",
    "chroot and namespaces are not a virtual machine boundary"
  ]
}
EOF

          if [ "$TRACE_MODE" = "strace" ]; then
            exec strace -ff \
              -o "$LOG_DIR/strace" \
              -s 256 \
              -e trace=%file,%process,%network,ptrace,mmap,mprotect \
              chroot "$ROOTFS" "$@"
          fi

          exec chroot "$ROOTFS" "$@"
        ' bash "$ROOTFS" "$LOG_DIR" "$TRACE_MODE" /bin/unpacked.elf

  EXIT_CODE="$?"

  set -e

  END_EPOCH="$(date +%s)"
  END_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  DURATION_SECONDS="$((END_EPOCH - START_EPOCH))"

  TIMED_OUT=false
  if [ "$EXIT_CODE" -eq 124 ] || [ "$EXIT_CODE" -eq 137 ]; then
    TIMED_OUT=true
  fi

  ISOLATION_READY=false
  if [ -f "$SECURITY_STATUS_PATH" ]; then
    ISOLATION_READY=true
  fi

  cat > "$STATUS_PATH" <<EOF
{
  "command": "sudo ip netns exec $NS unshare --pid --mount --uts --ipc chroot $ROOTFS /bin/unpacked.elf",
  "namespace": "$NS",
  "rootfs": "$ROOTFS",
  "guest_command": "/bin/unpacked.elf",
  "exit_code": $EXIT_CODE,
  "timed_out": $TIMED_OUT,
  "timeout_seconds": 60,
  "started_at_utc": "$START_UTC",
  "finished_at_utc": "$END_UTC",
  "duration_seconds": $DURATION_SECONDS,
  "stdout_path": "$STDOUT_PATH",
  "stderr_path": "$STDERR_PATH",
  "strace_enabled": $STRACE_ENABLED,
  "strace_prefix": "$STRACE_PREFIX",
  "isolation_ready": $ISOLATION_READY,
  "security_status_path": "$SECURITY_STATUS_PATH",
  "resource_limits_path": "$RESOURCE_LIMITS_PATH"
}
EOF

  echo "[+] Finished"
  echo "[+] exit code: $EXIT_CODE"
  echo "[+] timed out: $TIMED_OUT"
  echo "[+] isolation ready: $ISOLATION_READY"
  echo "[+] status: $STATUS_PATH"
  echo "[+] security status: $SECURITY_STATUS_PATH"
  echo "[+] stdout: $STDOUT_PATH"
  echo "[+] stderr: $STDERR_PATH"

  return "$EXIT_CODE"
}


case "${1:-run}" in
  setup)
    setup_netns
    echo "[+] Network namespace is ready."
    echo "[+] Now start mini-FakeNet in another terminal."
    ;;

  run)
    run_sample
    ;;

  cleanup)
    cleanup
    echo "[+] Cleaned up."
    ;;

  full)
    setup_netns
    echo "[+] Network namespace is ready."
    echo "[!] Start mini-FakeNet separately before running sample if not already running."
    run_sample
    cleanup
    ;;

  *)
    echo "Usage: $0 {setup|run|cleanup|full}"
    exit 1
    ;;
esac
