# TaintForge-IoT Phase 2 Run Report

Generated at UTC: `2026-06-15T22:19:53.077386+00:00`
Output directory: `workdir/test_stat_net`

## Runtime

- Architecture: `x86`
- RootFS: `workdir/test_stat_net/rootfs`
- Host binary: `samples/test_stat`
- Guest binary: `/bin/unpacked.elf`
- QEMU required: `False`
- QEMU guest path: `None`
- Libraries OK: `True`

### Runtime status

- Exit code: `255`
- Timed out: `False`
- Timeout seconds: `60`
- Duration seconds: `0`
- Started at UTC: `2026-06-15T22:00:34Z`
- Finished at UTC: `2026-06-15T22:00:34Z`
- Command: `sudo ip netns exec tf-iot-ns chroot /home/lisoon/taintforge/workdir/test_stat_net/rootfs /bin/unpacked.elf`

### Host binary metadata

- Exists: `True`
- Size: `337628` bytes
- SHA256: `0569944931f33c70438b3487cafd04f6d2568119bad0f88e71d940d6d4eb9c88`

## Libraries

- Requirements: `0`
- Resolved: `0`
- Missing: `0`

## Network

- Mode: `local_test`
- Allow internet: `False`
- Known services: `0`
- Total events: `0`
- Known TCP events: `0`
- Unknown TCP events: `0`
- UDP datagrams: `0`
- DNS datagrams: `0`

### Observed targets

- Known TCP targets: `[]`
- Unknown TCP targets: `[]`
- UDP targets: `[]`

### Network attempts from malware syscalls

| Syscall | Target | Result |
|---|---|---|
| `connect` | `127.0.0.1:80` | `-1 ECONNREFUSED (Connection refused)` |

### Event types

- No network events recorded.

## Syscalls

- Total syscall events: `21`
- High-risk events: `0`

### Syscalls by category

- `filesystem`: `6`
- `memory`: `11`
- `network`: `2`
- `other`: `1`
- `process`: `1`

### Top syscalls

- `mmap`: `8`
- `mprotect`: `3`
- `chdir`: `1`
- `execve`: `1`
- `open`: `1`
- `readlink`: `1`
- `readlinkat`: `1`
- `openat`: `1`
- `socket`: `1`
- `connect`: `1`
- `exit_group`: `1`
- `exit`: `1`

### Observed malware filesystem paths

- `/`
- `/bin/unpacked.elf`
- `/proc/self/exe`
- `/tmp/testfile.txt`

### High-risk syscall events

- No high-risk syscall events recorded.

## Artifacts

- Payload files: `0`

## Security model

- `chroot_enabled`: `True`
- `network_namespace_enabled`: `True`
- `iptables_default_deny_expected`: `True`
- `host_ip_forwarding_expected`: `False`
- `allow_internet`: `False`
- `known_endpoint_dnat`: `True`
- `tcp_catch_all_redirect`: `True`
- `udp_catch_all_redirect`: `True`
- `resource_limits`: `disabled_in_v1_timeout_only`

## Runtime stdout preview

```text

```

## Runtime stderr preview

```text
Cannot open network namespace "tf-iot-ns": No such file or directory

```

## Network self-test stdout preview

```text

```
