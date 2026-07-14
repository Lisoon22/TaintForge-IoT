from __future__ import annotations
import shlex
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class NetworkSandboxConfig:
    rootfs: str
    guest_binary_path: str
    qemu_required: bool
    qemu_guest_path: str | None

    namespace_name: str
    veth_host: str
    veth_ns: str

    host_ip: str
    host_cidr: str
    ns_ip: str
    ns_cidr: str

    timeout_seconds: int


    cpu_limit_seconds: int = 30
    virtual_memory_kb: int = 524288
    open_files_limit: int = 256
    process_limit: int = 256
    file_size_blocks: int = 10240

class NetworkSandboxRunnerError(RuntimeError):
    pass


def load_json(path: str | Path) -> dict:
    path = Path(path)

    if not path.exists():
        raise NetworkSandboxRunnerError(f"File not found: {path}")

    return json.loads(path.read_text(encoding="utf-8"))


def build_network_sandbox_config(
    runtime_config_path: str | Path,
    namespace_name: str = "tf-iot-ns",
    timeout_seconds: int = 60,
) -> NetworkSandboxConfig:
    runtime = load_json(runtime_config_path)

    return NetworkSandboxConfig(
        rootfs=runtime["rootfs"],
        guest_binary_path=runtime["guest_binary_path"],
        qemu_required=bool(runtime["qemu_required"]),
        qemu_guest_path=runtime.get("qemu_guest_path"),
        namespace_name=namespace_name,
        veth_host="tf-veth-host",
        veth_ns="tf-veth-ns",
        host_ip="10.10.0.1",
        host_cidr="10.10.0.1/24",
        ns_ip="10.10.0.2",
        ns_cidr="10.10.0.2/24",
        timeout_seconds=timeout_seconds,
    )


def generate_network_sandbox_script(
    config: NetworkSandboxConfig,
    network_policy_path: str | Path,
    out_path: str | Path,
) -> None:
    policy = load_json(network_policy_path)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if config.qemu_required:
        if not config.qemu_guest_path:
            raise NetworkSandboxRunnerError(
                "qemu_required=true but qemu_guest_path is missing"
            )

        guest_argv = [
            config.qemu_guest_path,
            config.guest_binary_path,
        ]
    else:
        guest_argv = [
            config.guest_binary_path,
        ]

    exec_part = " ".join(
        shlex.quote(argument)
        for argument in guest_argv
    )

    dnat_rules = build_dnat_rules(policy=policy, host_ip=config.host_ip)

    allow_rules = build_allow_rules(policy=policy, host_ip=config.host_ip)

    catch_all_rules = build_catch_all_rules(policy=policy, host_ip=config.host_ip)

    script = f"""#!/usr/bin/env bash
set -euo pipefail

NS="{config.namespace_name}"
VETH_HOST="{config.veth_host}"
VETH_NS="{config.veth_ns}"

HOST_IP="{config.host_ip}"
HOST_CIDR="{config.host_cidr}"
NS_IP="{config.ns_ip}"
NS_CIDR="{config.ns_cidr}"

ROOTFS="$(cd "$(dirname "$0")/rootfs" && pwd)"
LOG_DIR="$(cd "$(dirname "$0")/logs" && pwd)"

mkdir -p "$LOG_DIR"

cleanup() {{
  set +e
  sudo ip netns del "$NS" 2>/dev/null
  sudo ip link del "$VETH_HOST" 2>/dev/null
  set -e
}}

setup_netns() {{
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
{dnat_rules}

# Known endpoint allow rules.
{allow_rules}

# Catch-all unknown TCP redirect.
{catch_all_rules}
}}

run_sample() {{
  echo "[+] Starting sample in hardened controlled sandbox"
  echo "[+] ROOTFS=$ROOTFS"
  echo "[+] Namespace=$NS"
  echo "[+] Command inside chroot: {exec_part}"

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

  # Create output files even if sudo, unshare or chroot fails
  # before the guest process starts.
  : > "$STDOUT_PATH"
  : > "$STDERR_PATH"

  set +e

  timeout --kill-after=5s {config.timeout_seconds}s \\
    sudo ip netns exec "$NS" \\
      unshare \\
        --fork \\
        --pid \\
        --mount \\
        --uts \\
        --ipc \\
        --kill-child=SIGKILL \\
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
          ulimit -t {config.cpu_limit_seconds}
          ulimit -v {config.virtual_memory_kb}
          ulimit -n {config.open_files_limit}
          ulimit -f {config.file_size_blocks}

          # RLIMIT_NPROC is best-effort for UID 0.
          ulimit -u {config.process_limit} 2>/dev/null || true

          umask 077

          ulimit -a > "$LOG_DIR/resource_limits.txt" 2>&1 || true

          STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

          cat > "$LOG_DIR/security_status.json" <<EOF
{{
  "generated_at_utc": "$STARTED_AT",
  "isolation_ready": true,
  "chroot": true,
  "network_namespace": true,
  "pid_namespace": true,
  "mount_namespace": true,
  "uts_namespace": true,
  "ipc_namespace": true,
  "user_namespace": false,
  "network_default_deny": true,
  "mount_propagation": "private",
  "sandbox_hostname": "taintforge-iot",
  "proc_mode": "static_rootfs_stubs",
  "strace_enabled": $([ "$TRACE_MODE" = "strace" ] && echo true || echo false),
  "resource_limits": {{
    "cpu_seconds": {config.cpu_limit_seconds},
    "virtual_memory_kb": {config.virtual_memory_kb},
    "open_files": {config.open_files_limit},
    "processes": {config.process_limit},
    "processes_enforcement": "best_effort_for_uid_0",
    "file_size_blocks": {config.file_size_blocks}
  }},
  "limitations": [
    "malware still runs as UID 0 inside chroot",
    "no user namespace",
    "no seccomp filter",
    "no cgroup memory or process enforcement",
    "chroot and namespaces are not a virtual machine boundary"
  ]
}}
EOF

          if [ "$TRACE_MODE" = "strace" ]; then
            exec strace -ff \\
              -o "$LOG_DIR/strace" \\
              -s 256 \\
              -e trace=%file,%process,%network,ptrace,mmap,mprotect \\
              chroot "$ROOTFS" "$@"
          fi

          exec chroot "$ROOTFS" "$@"
        ' bash "$ROOTFS" "$LOG_DIR" "$TRACE_MODE" {exec_part} \
    >"$STDOUT_PATH" 2>"$STDERR_PATH"

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
{{
  "command": "sudo ip netns exec $NS unshare --pid --mount --uts --ipc chroot $ROOTFS {exec_part}",
  "namespace": "$NS",
  "rootfs": "$ROOTFS",
  "guest_command": "{exec_part}",
  "exit_code": $EXIT_CODE,
  "timed_out": $TIMED_OUT,
  "timeout_seconds": {config.timeout_seconds},
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
}}
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
}}


case "${{1:-run}}" in
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
    echo "Usage: $0 {{setup|run|cleanup|full}}"
    exit 1
    ;;
esac
"""

    out_path.write_text(script, encoding="utf-8")
    out_path.chmod(0o755)


def build_dnat_rules(policy: dict, host_ip: str) -> str:
    lines: list[str] = []

    for service in policy.get("services", []):
        if service.get("service_type") != "tcp":
            continue

        remote_ip = service.get("remote_ip")
        remote_port = service.get("remote_port")
        bind_port = service.get("bind_port")

        if not remote_ip or not remote_port or not bind_port:
            continue

        lines.append(
            "  sudo ip netns exec \"$NS\" iptables -t nat -A OUTPUT "
            f"-p tcp -d {remote_ip} --dport {remote_port} "
            f"-j DNAT --to-destination {host_ip}:{bind_port}"
        )

    return "\n".join(lines)


def build_allow_rules(policy: dict, host_ip: str) -> str:
    lines: list[str] = []

    for service in policy.get("services", []):
        if service.get("service_type") != "tcp":
            continue

        bind_port = service.get("bind_port")

        if not bind_port:
            continue

        lines.append(
            "  sudo ip netns exec \"$NS\" iptables -A OUTPUT "
            f"-p tcp -d {host_ip} --dport {bind_port} "
            "-j ACCEPT"
        )

        lines.append(
            "  sudo ip netns exec \"$NS\" iptables -A INPUT "
            f"-p tcp -s {host_ip} --sport {bind_port} "
            "-j ACCEPT"
        )

    return "\n".join(lines)

def build_catch_all_rules(policy: dict, host_ip: str) -> str:
    catch_all = policy.get("catch_all", {})

    if not catch_all.get("enabled", False):
        return ""

    tcp_bind_port = int(catch_all.get("tcp_bind_port", 40000))
    udp_bind_port = int(catch_all.get("udp_bind_port", 40001))

    lines: list[str] = []

    lines.append("  # Transparent catch-all chains.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -N TF_TCP_CATCHALL "
        "2>/dev/null || true"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -N TF_UDP_CATCHALL "
        "2>/dev/null || true"
    )

    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -F TF_TCP_CATCHALL"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -F TF_UDP_CATCHALL"
    )

    lines.append("  # Do not redirect traffic to fake gateway.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A TF_TCP_CATCHALL "
        f"-d {host_ip} -j RETURN"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A TF_UDP_CATCHALL "
        f"-d {host_ip} -j RETURN"
    )

    lines.append("  # Do not redirect loopback traffic.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A TF_TCP_CATCHALL "
        "-d 127.0.0.0/8 -j RETURN"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A TF_UDP_CATCHALL "
        "-d 127.0.0.0/8 -j RETURN"
    )

    lines.append("  # Unknown TCP -> local transparent TCP logger.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A TF_TCP_CATCHALL "
        "-p tcp "
        f"-j REDIRECT --to-ports {tcp_bind_port}"
    )

    lines.append("  # All unknown UDP -> local transparent UDP logger.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A TF_UDP_CATCHALL "
        "-p udp "
        f"-j REDIRECT --to-ports {udp_bind_port}"
    )

    lines.append("  # Attach catch-all chains after known endpoint DNAT rules.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A OUTPUT "
        "-p tcp -j TF_TCP_CATCHALL"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -t nat -A OUTPUT "
        "-p udp -j TF_UDP_CATCHALL"
    )

    lines.append("  # Allow unknown TCP/UDP attempts that are redirected by nat OUTPUT.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -A OUTPUT "
        f"-p tcp ! -d {host_ip} "
        "-j ACCEPT"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -A OUTPUT "
        f"-p udp ! -d {host_ip} "
        "-j ACCEPT"
    )

    lines.append("  # Allow redirected local TCP/UDP traffic explicitly.")
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -A OUTPUT "
        f"-p tcp --dport {tcp_bind_port} "
        "-j ACCEPT"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -A INPUT "
        f"-p tcp --sport {tcp_bind_port} "
        "-j ACCEPT"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -A OUTPUT "
        f"-p udp --dport {udp_bind_port} "
        "-j ACCEPT"
    )
    lines.append(
        "  sudo ip netns exec \"$NS\" iptables -A INPUT "
        f"-p udp --sport {udp_bind_port} "
        "-j ACCEPT"
    )

    return "\n".join(lines)
