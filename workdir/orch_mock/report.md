# TaintForge-IoT Phase 2 Run Report

Generated at UTC: `2026-06-13T21:41:49.508790+00:00`
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
- Started at UTC: `2026-06-13T21:41:49Z`
- Finished at UTC: `2026-06-13T21:41:49Z`
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
| ld-linux-x86-64.so.2 | interpreter | `/lib64/ld-linux-x86-64.so.2` | `sysroots/x86_64/lib64/ld-linux-x86-64.so.2` |
| libc.so.6 | needed | `/usr/lib/libc.so.6` | `sysroots/x86_64/usr/lib/libc.so.6` |
| libcap.so.2 | needed | `/usr/lib/libcap.so.2` | `sysroots/x86_64/usr/lib/libcap.so.2` |
| libpthread.so.0 | runtime_library | `/usr/lib/libpthread.so.0` | `sysroots/x86_64/usr/lib/libpthread.so.0` |

## Network

- Mode: `local_test`
- Allow internet: `False`
- Known services: `1`
- Total events: `10`
- Known TCP events: `4`
- Unknown TCP events: `4`
- UDP datagrams: `2`
- DNS datagrams: `1`

### Known services

| Role | Remote | Local bind | Protocol hint |
|---|---|---|---|
| c2_binary | `185.62.190.0:48101` | `10.10.0.1:48101` | c2_binary |

### Observed targets

- Known TCP targets: `['185.62.190.0:48101']`
- Unknown TCP targets: `['91.200.10.5:5555']`
- UDP targets: `['1.2.3.4:9999', '8.8.8.8:53']`

### Event types

- `tcp_connection_close`: `2`
- `tcp_connection_open`: `2`
- `tcp_data`: `2`
- `tcp_response`: `2`
- `udp_datagram`: `2`

## Artifacts

- Payload files: `4`

| File | Size | SHA256 |
|---|---:|---|
| `logs/catchall_tcp_91_200_10_5_5555_conn_1.bin` | 17 | `edd51a1653cf3d9c842d92d39e8c524e60a93fa860eecdeb20185f230de20051` |
| `logs/dns_udp_8_8_8_8_53_dgram_2.bin` | 16 | `165fa948be2b7e54631d9e574e5931e28a09b002fa19437998d62299d66f91d1` |
| `logs/tcp_48101_conn_1.bin` | 15 | `b4f77b4fd378b4eb2f65f1c089234e38c31aa61f46baa0f2aa8faafeca0c0bcb` |
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
[self-test] UDP generic -> 1.2.3.4:9999
[self-test] UDP dns-like -> 8.8.8.8:53

```
