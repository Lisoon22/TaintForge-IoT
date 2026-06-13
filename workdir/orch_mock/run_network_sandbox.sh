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
  echo "[+] Starting sample in controlled network sandbox"
  echo "[+] ROOTFS=$ROOTFS"
  echo "[+] Namespace=$NS"
  echo "[+] Command inside chroot: /bin/unpacked.elf"

    # Resource limits are intentionally not applied here in Orchestrator v1.
  # Applying ulimit before sudo/ip/chroot also limits wrapper processes and
  # can break fork/exec before the sample starts.
  #
  # Later this should be replaced with cgroups/prlimit/seccomp applied only
  # to the malware process tree.


  timeout --kill-after=5s 60s \
    sudo ip netns exec "$NS" \
      chroot "$ROOTFS" /bin/unpacked.elf \
    > "$LOG_DIR/runtime_stdout.log" \
    2> "$LOG_DIR/runtime_stderr.log"

  echo "[+] Finished"
  echo "[+] stdout: $LOG_DIR/runtime_stdout.log"
  echo "[+] stderr: $LOG_DIR/runtime_stderr.log"
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
