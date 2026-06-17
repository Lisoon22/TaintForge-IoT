# TaintForge-IoT Phase 2 Run Report

Generated at UTC: `2026-06-17T21:38:23.110927+00:00`
Output directory: `workdir/orch_mock`

## Runtime

- Architecture: `x86_64`
- RootFS: `workdir/orch_mock/rootfs`
- Host binary: `samples/ls_x86_64`
- Guest binary: `/bin/unpacked.elf`
- QEMU required: `False`
- QEMU guest path: `None`
- Libraries OK: `True`

### Runtime status

- Exit code: `0`
- Timed out: `False`
- Timeout seconds: `60`
- Duration seconds: `0`
- Started at UTC: `2026-06-17T21:38:22Z`
- Finished at UTC: `2026-06-17T21:38:22Z`
- Command: `sudo ip netns exec tf-iot-ns chroot /home/lisoon/taintforge/workdir/orch_mock/rootfs /bin/unpacked.elf`

### Host binary metadata

- Exists: `True`
- Size: `162472` bytes
- SHA256: `5840bd1ad992bbb96dc0037c39b44177294c3bb8e6bfdfcec7814c92af1e5bde`

## Libraries

- Requirements: `4`
- Resolved: `4`
- Missing: `0`

### Resolved libraries

| Name | Kind | Guest path | Source path |
|---|---|---|---|
| ld-linux-x86-64.so.2 | interpreter | `/lib64/ld-linux-x86-64.so.2` | `/home/lisoon/taintforge/sysroots/x86_64/lib64/ld-linux-x86-64.so.2` |
| libc.so.6 | needed | `/usr/lib/libc.so.6` | `/home/lisoon/taintforge/sysroots/x86_64/usr/lib/libc.so.6` |
| libcap.so.2 | needed | `/usr/lib/libcap.so.2` | `/home/lisoon/taintforge/sysroots/x86_64/usr/lib/libcap.so.2` |
| libpthread.so.0 | runtime_library | `/usr/lib/libpthread.so.0` | `/home/lisoon/taintforge/sysroots/x86_64/usr/lib/libpthread.so.0` |

## Network

- Mode: `local_test`
- Allow internet: `False`
- Known services: `1`
- Total events: `0`
- Known TCP events: `0`
- Unknown TCP events: `0`
- UDP datagrams: `0`
- DNS datagrams: `0`
- DNS responses sent: `0`
- DNS queries: `[]`

### Known services

| Role | Remote | Local bind | Protocol hint |
|---|---|---|---|
| c2_binary | `185.62.190.0:48101` | `10.10.0.1:48101` | c2_binary |

### Observed targets

- Known TCP targets: `[]`
- Unknown TCP targets: `[]`
- UDP targets: `[]`

### Network attempts from malware syscalls

- No network attempts recorded from malware syscalls.

### Observed HTTP requests

- No HTTP requests recorded.

### Event types

- No network events recorded.

## Syscalls

- Total syscall events: `36`
- High-risk events: `0`

### Syscalls by category

- `filesystem`: `19`
- `memory`: `15`
- `other`: `1`
- `process`: `1`

### Top syscalls

- `openat`: `14`
- `mmap`: `11`
- `mprotect`: `4`
- `newfstatat`: `2`
- `chdir`: `1`
- `execve`: `1`
- `access`: `1`
- `exit_group`: `1`
- `exit`: `1`

### Observed malware filesystem paths

- `.`
- `/`
- `/bin/unpacked.elf`
- `/etc/ld.so.cache`
- `/etc/ld.so.preload`
- `/usr/lib/glibc-hwcaps/x86-64-v2/`
- `/usr/lib/glibc-hwcaps/x86-64-v2/libcap.so.2`
- `/usr/lib/glibc-hwcaps/x86-64-v3/`
- `/usr/lib/glibc-hwcaps/x86-64-v3/libcap.so.2`
- `/usr/lib/libc.so.6`
- `/usr/lib/libcap.so.2`
- `/usr/lib/locale/en.UTF-8/LC_IDENTIFICATION`
- `/usr/lib/locale/en.utf8/LC_IDENTIFICATION`
- `/usr/lib/locale/en/LC_IDENTIFICATION`
- `/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION`
- `/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION`
- `/usr/lib/locale/en_US/LC_IDENTIFICATION`
- `/usr/lib/locale/locale-archive`
- `/usr/share/locale/locale.alias`

### High-risk syscall events

- No high-risk syscall events recorded.

## Filesystem mutations

- Created files/entries: `0`
- Modified files/entries: `0`
- Deleted files/entries: `0`

### Created entries

- No created entries.

### Modified entries

- No modified entries.

### Deleted entries

- No deleted entries.

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
bin
dev
etc
lib
lib64
proc
tmp
usr
var

```

## Runtime stderr preview

```text

```

## Network self-test stdout preview

```text
[self-test] TCP known -> 185.62.190.0:48101
[self-test] TCP known response=00000000
[self-test] TCP unknown -> 91.200.10.5:5555
[self-test] TCP unknown response=4f4b0a
[self-test] TCP http -> 93.184.216.34:80
[self-test] TCP http response=485454502f312e3120323030204f4b0d0a436f6e74656e742d547970653a20746578742f706c61696e0d0a436f6e6e656374696f6e3a20636c6f73650d0a436f6e74656e742d4c656e6774683a2033330d0a0d0a5461696e74466f7267652d496f542066616b65204854545020736572766963650a
[self-test] UDP generic -> 1.2.3.4:9999
[self-test] UDP dns-like -> 8.8.8.8:53
[self-test] UDP dns-like response_from=8.8.8.8:53 response=123481800001000100000000076578616d706c6503636f6d0000010001c00c000100010000003c00040a0a0001

```
