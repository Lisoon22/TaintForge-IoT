# TaintForge-IoT Phase 2 Run Report

Generated at UTC: `2026-06-15T21:48:27.507253+00:00`
Output directory: `workdir/test_stat`

## Runtime

- Architecture: `x86`
- RootFS: `workdir/test_stat/rootfs`
- Host binary: `samples/test_stat`
- Guest binary: `/bin/unpacked.elf`
- QEMU required: `False`
- QEMU guest path: `None`
- Libraries OK: `True`

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

### Event types

- No network events recorded.

## Syscalls

- Total syscall events: `51`
- High-risk events: `0`

### Syscalls by category

- `filesystem`: `6`
- `memory`: `22`
- `network`: `2`
- `other`: `20`
- `process`: `1`

### Top syscalls

- `mmap`: `8`
- `brk`: `6`
- `close`: `5`
- `munmap`: `4`
- `write`: `3`
- `mprotect`: `3`
- `memfd_create`: `2`
- `ftruncate`: `2`
- `chdir`: `1`
- `execve`: `1`
- `open`: `1`
- `readlink`: `1`
- `msync`: `1`
- `mmap2`: `1`
- `set_thread_area`: `1`
- `set_tid_address`: `1`
- `set_robust_list`: `1`
- `rseq`: `1`
- `ugetrlimit`: `1`
- `getrandom`: `1`

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
привет

```

## Runtime stderr preview

```text

```

## Network self-test stdout preview

```text

```
