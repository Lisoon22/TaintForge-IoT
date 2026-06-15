# TaintForge-IoT Phase 2 Run Report

Generated at UTC: `2026-06-15T22:05:13.847905+00:00`
Output directory: `workdir/test_stat_net_selftest`

## Runtime

- Architecture: `x86`
- RootFS: `workdir/test_stat_net_selftest/rootfs`
- Host binary: `samples/test_stat`
- Guest binary: `/bin/unpacked.elf`
- QEMU required: `False`
- QEMU guest path: `None`
- Libraries OK: `True`

### Runtime status

- Exit code: `0`
- Timed out: `False`
- Timeout seconds: `60`
- Duration seconds: `0`
- Started at UTC: `2026-06-15T22:05:13Z`
- Finished at UTC: `2026-06-15T22:05:13Z`
- Command: `sudo ip netns exec tf-iot-ns chroot /home/lisoon/taintforge/workdir/test_stat_net_selftest/rootfs /bin/unpacked.elf`

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
- Total events: `6`
- Known TCP events: `0`
- Unknown TCP events: `4`
- UDP datagrams: `2`
- DNS datagrams: `1`

### Observed targets

- Known TCP targets: `[]`
- Unknown TCP targets: `['91.200.10.5:5555']`
- UDP targets: `['1.2.3.4:9999', '8.8.8.8:53']`

### Event types

- `tcp_connection_close`: `1`
- `tcp_connection_open`: `1`
- `tcp_data`: `1`
- `tcp_response`: `1`
- `udp_datagram`: `2`

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

- Payload files: `3`

| File | Size | SHA256 |
|---|---:|---|
| `logs/catchall_tcp_91_200_10_5_5555_conn_1.bin` | 17 | `edd51a1653cf3d9c842d92d39e8c524e60a93fa860eecdeb20185f230de20051` |
| `logs/dns_udp_8_8_8_8_53_dgram_2.bin` | 16 | `165fa948be2b7e54631d9e574e5931e28a09b002fa19437998d62299d66f91d1` |
| `logs/udp_udp_1_2_3_4_9999_dgram_1.bin` | 13 | `ff0b68f5c8cefbc338da4ead9bfe082a2e57b68301ec4b3f5e4ad59779ae508e` |

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
привет

```

## Runtime stderr preview

```text

```

## Network self-test stdout preview

```text
[self-test] No known TCP target in policy; skipping known TCP test
[self-test] TCP unknown -> 91.200.10.5:5555
[self-test] TCP unknown response=4f4b0a
[self-test] UDP generic -> 1.2.3.4:9999
[self-test] UDP dns-like -> 8.8.8.8:53

```
