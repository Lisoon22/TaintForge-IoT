# TaintForge-IoT

**Reverse-Assisted Hybrid Fuzzing with Taint-Guided Minimal Environment Modeling for IoT Malware Analysis**

TaintForge-IoT is a research prototype for connecting dynamic unpacking and
environment-dependency extraction with controlled re-execution, runtime
observation, and environment synthesis.

The repository is under active development. The current unified launcher is an
MVP integration path for **statically linked Linux i386 ELF files**.

The canonical demonstration is a reproducible scientific experiment, not only
a launcher smoke test. It compares an empty-contract baseline with a
dependency-guided Phase 2 environment and requires an explicit target-state
oracle to confirm success.

> [!IMPORTANT]
> The temporary unified pipeline does not yet execute `unpacked.bin` as a
> restored process snapshot. Phase 1 produces a raw dump and metadata, while
> Phase 2 currently re-executes the original static ELF using the metadata as an
> environment seed. The generated report records this limitation explicitly.

## Current pipeline

```text
static Linux i386 ELF
        |
        v
Phase 1: QEMU plugin
  - memory-page tracking
  - OEP candidate detection
  - file/network dependency logging
  - unpacked.bin
  - unpacked.json
        |
        v
temporary compatibility adapter
  - normalizes Phase 1 event-oriented JSON
  - writes phase2_input.json
  - records lossy transformations in bridge_audit.json
        |
        v
Phase 2: environment reconstruction
  - minimal rootfs
  - network namespace and local responders
  - controlled execution
  - syscall and network observations
  - rootfs before/after diff
  - runtime requirements
  - passive repair plan
  - report.json / report.md
        |
        v
pipeline_report.json / pipeline_report.md
```

## Supported MVP input

The unified launcher currently accepts only:

- Linux ELF;
- ELF32;
- little-endian;
- Intel 80386;
- statically linked binaries without `PT_INTERP`.

Use the following command to verify a sample:

```bash
file samples/test_stat
readelf -hW samples/test_stat
readelf -lW samples/test_stat | grep INTERP || true
```

Dynamic binaries, ARM, AArch64, MIPS, x86-64, fixed-address snapshot replay,
and register restoration are not supported by this temporary launcher.

## Scientific static Phase 2 demo

The demo tests the following scoped claim:

> For the controlled static i386 target, the dependency contract observed in
> Phase 1 enables Phase 2 to synthesize a trace-relative sufficient environment
> that reaches an analyst-defined behavioral milestone, while the empty-contract
> baseline does not.

It does **not** claim that the generated environment is subset-minimal, that
the raw `unpacked.bin` is executable, or that the local responder implements a
real malware C2 protocol.

Run the complete experiment from a clean checkout:

```bash
make doctor
make test
make demo-static
```

Optional launcher arguments can be forwarded without editing the Makefile. For
example:

```bash
make demo-static DEMO_ARGS='--qemu-source /home/user/qemu --repetitions 5'
```

The demo automatically:

1. builds a libc-independent static ELF32 i386 target;
2. runs an empty-contract baseline in disconnected private namespaces;
3. runs Phase 1 under `qemu-i386` and retains `unpacked.bin` and
   `unpacked.json`;
4. synthesizes the Phase 2 filesystem and controlled network environment;
5. evaluates a versioned target-state specification;
6. repeats Phase 2 three times as a small stability check;
7. writes `workdir/phase2_static_demo/demo_summary.json` and
   `demo_summary.md`.

The target milestone is emitted only after both of these requirements are
satisfied:

- `/tmp/taintforge-phase2-demo.ready` exists inside the synthesized rootfs;
- `connect(198.51.100.10:48101)` succeeds through the controlled local
  responder.

`198.51.100.0/24` is the TEST-NET-2 documentation range. Controlled mode does
not forward the sample to that address on the Internet.

## Safety

Run unknown malware only inside a dedicated analysis VM or isolated research
machine.

The Phase 1 wrapper creates a new network namespace by default and executes
QEMU with the invoking user's UID/GID. Phase 2 uses its existing chroot and
network-namespace mechanisms. These controls reduce exposure but are not a
substitute for a disposable host VM.

Never use `--phase1-isolation none` for an untrusted sample.

## Requirements

### Runtime tools

The current pipeline expects:

```text
python
gcc
pkg-config
qemu-i386 or qemu-i386-static
readelf
sudo
strace
timeout
chroot
mount
unshare
ip
iptables
ss
conntrack
jq
```

The Phase 1 plugin build also requires:

```text
glib-2.0 development files
Capstone development files
the system QEMU plugin header (/usr/include/qemu-plugin.h)
```

A configured QEMU source/build tree is only a fallback when the system plugin header is unavailable or a custom QEMU build is required.

On Arch Linux, a typical package set is:

```bash
sudo pacman -S --needed \
  base-devel \
  python \
  qemu-user \
  qemu-common \
  glib2 \
  capstone \
  strace \
  iproute2 \
  iptables \
  conntrack-tools \
  jq
```

The preferred Arch Linux setup uses the system header:

```text
/usr/include/qemu-plugin.h
```

If that header is absent, the wrapper falls back to a configured QEMU source/build tree selected through `--qemu-source`, `TAINTFORGE_QEMU_SOURCE`, `QEMU_SRC`, or the conventional `~/qemu` path.

## Repository setup

Clone the repository and enter it:

```bash
git clone https://github.com/Lisoon22/TaintForge-IoT.git
cd TaintForge-IoT
```

Check the launcher:

```bash
PYTHONPATH=. python scripts/run_static_pipeline.py --help
```

## Phase 1 plugin

The repository currently has no complete Makefile target for the plugin, so the
unified launcher builds it automatically when no usable `.so` exists.

The generated file is:

```text
build/qemu_unpacker.so
```

The build log is:

```text
build/qemu_unpacker.build.log
```

### Automatic build

Assuming the QEMU source/build tree is at `~/qemu`, no `--plugin` argument is
required:

```bash
PYTHONPATH=. python scripts/run_static_pipeline.py \
  samples/test_stat \
  --out workdir/full_pipeline_test_stat \
  --network none \
  --force
```

To select another QEMU tree:

```bash
PYTHONPATH=. python scripts/run_static_pipeline.py \
  samples/test_stat \
  --qemu-source /home/user/qemu \
  --out workdir/full_pipeline_test_stat \
  --network none \
  --force
```

### Manual build

The equivalent current build command is:

```bash
cd TaintForge-IoT

mkdir -p build

gcc \
  -fPIC \
  -shared \
  -O2 \
  -g \
  -Wall \
  -Wextra \
  -I"$HOME/qemu/include" \
  -I"$HOME/qemu/build" \
  -I./unpacker \
  unpacker/qemu_unpacker.c \
  unpacker/dta.c \
  unpacker/trace.c \
  unpacker/dse.c \
  unpacker/dse_lift_x86.c \
  -o build/qemu_unpacker.so \
  $(pkg-config --cflags --libs glib-2.0 capstone)
```

Verify it:

```bash
test -f build/qemu_unpacker.so
file build/qemu_unpacker.so
ldd build/qemu_unpacker.so
```

Then run with an explicit path:

```bash
PYTHONPATH=. python scripts/run_static_pipeline.py \
  samples/test_stat \
  --plugin "$(realpath build/qemu_unpacker.so)" \
  --out workdir/full_pipeline_test_stat \
  --network none \
  --force
```

## Quick start

For the scientific baseline/full/stability experiment, prefer `make demo-static`.
The commands below remain useful for lower-level diagnostics.

### Stable smoke test without network emulation

```bash
cd TaintForge-IoT

PYTHONPATH=. python scripts/run_static_pipeline.py \
  samples/test_stat \
  --out workdir/report_demo_static \
  --phase1-timeout 20 \
  --phase2-timeout 30 \
  --network none \
  --force
```

### Full current network path for non-loopback dependencies

```bash
cd TaintForge-IoT

PYTHONPATH=. python scripts/run_static_pipeline.py \
  samples/test_stat \
  --out workdir/report_demo_static_net \
  --phase1-timeout 20 \
  --phase2-timeout 60 \
  --network auto \
  --self-test-network \
  --force
```

`--network auto` selects the existing Phase 2 mode from the normalized network
dependencies. For a sample with no network dependencies, the effective mode may
be `none`.

`none` now means a disconnected private network namespace. It is not an alias
for the host network. Runtime evidence is written to `runtime_status.json` and
`security_status.json`.

### Explicit prebuilt plugin

```bash
PYTHONPATH=. python scripts/run_static_pipeline.py \
  samples/test_stat \
  --plugin /absolute/path/to/qemu_unpacker.so \
  --out workdir/report_demo_static \
  --network none \
  --force
```

## Unified launcher options

```bash
PYTHONPATH=. python scripts/run_static_pipeline.py --help
```

Important options:

```text
--plugin PATH
    Use an existing Phase 1 plugin.

--qemu-source PATH
    QEMU source/build tree used to compile the plugin.

--no-auto-build-plugin
    Fail instead of compiling the plugin automatically.

--qemu PATH_OR_NAME
    Override qemu-i386.

--phase1-timeout SECONDS
    Limit Phase 1 execution.

--phase2-timeout SECONDS
    Limit controlled Phase 2 execution.

--network auto|none|emulated|controlled
    Select the existing Phase 2 network mode.

--self-test-network
    Validate the Phase 2 network infrastructure before the malware run.

--sysroot PATH
    Use an explicit Phase 2 sysroot.

--allow-missing-libraries
    Forward the existing Phase 2 option.

--phase1-isolation netns|none
    Keep `netns` for untrusted samples.

--no-privileged-bind-workaround
    Disable temporary handling for known services on privileged ports.

--force
    Replace an existing output directory.
```



## Loopback network dependencies

A destination such as `127.0.0.1:80` has special semantics inside a network
namespace. From a process running in `tf-iot-ns`, `127.0.0.1` refers to the
namespace's own loopback interface, not to the host-side emulator bound to
`10.10.0.1`.

The current Phase 2 host-side known-service model therefore cannot emulate a
loopback endpoint merely by creating a service on `10.10.0.1:<port>`. A
known-target self-test aimed at `127.0.0.1:<port>` would remain inside the
namespace and time out.

Launcher version `0.4.0` handles this at the compatibility boundary:

- loopback endpoints are preserved in `bridge_audit.json`;
- they are listed as `unsupported_loopback_endpoints`;
- they are not promoted to host-side known services;
- when `--network auto` discovers only loopback endpoints, the effective Phase 2
  mode becomes `none`;
- `--self-test-network` is disabled for that fallback;
- runtime strace still records the malware's real loopback connection attempt;
- `pipeline_report.json` records both requested and effective network modes.

Example decision:

```json
{
  "requested_network": "auto",
  "effective_network": "none",
  "requested_self_test": true,
  "effective_self_test": false,
  "emulatable_dependencies": 0,
  "unsupported_loopback_endpoints": [
    {
      "ip": "127.0.0.1",
      "port": 80,
      "type": "tcp"
    }
  ]
}
```

This is appropriate for the current reporting MVP. The final network
architecture should add a namespace-local responder or proxy for loopback
services so original loopback semantics can be preserved.

## Privileged known-service ports

Phase 2 preserves the original destination port when it creates a known TCP
service. For example, a dependency on `127.0.0.1:80` produces a local listener
on `10.10.0.1:80`.

The known-service emulator runs as the invoking user. On Linux, ports below
`net.ipv4.ip_unprivileged_port_start` cannot normally be bound by that process.
Launcher version `0.3.0` and later handles this as a temporary compatibility workaround:

1. it reads the current `net.ipv4.ip_unprivileged_port_start`;
2. it finds the lowest known TCP service port;
3. when necessary, it temporarily lowers the threshold to that port;
4. it runs Phase 2;
5. it restores the original value in a `finally` block, including failure paths;
6. it records the operation in `pipeline_report.json`.

Example output:

```text
[!] Phase 2 known-service emulator needs a privileged host port: 80
[+] Temporarily setting net.ipv4.ip_unprivileged_port_start=80
[+] Restoring net.ipv4.ip_unprivileged_port_start=1024
```

Disable this workaround with:

```bash
--no-privileged-bind-workaround
```

This is an MVP wrapper workaround, not the final network-policy design. The
proper long-term solution is to preserve the remote port while selecting a
separate non-privileged local bind port and expressing that mapping explicitly
in the network policy.

## Output structure

A successful run produces:

```text
workdir/report_demo_static/
├── pipeline_report.json
├── pipeline_report.md
├── phase2_input.json
├── bridge_audit.json
├── logs/
│   ├── phase1_stdout.log
│   ├── phase1_stderr.log
│   ├── phase2_stdout.log
│   └── phase2_stderr.log
├── phase1/
│   ├── unpacked.bin
│   └── unpacked.json
└── phase2/
    ├── report.json
    ├── report.md
    ├── rootfs/
    ├── logs/
    │   ├── runtime_stdout.log
    │   ├── runtime_stderr.log
    │   ├── syscall_events.jsonl
    │   └── network_events.jsonl
    └── config/
        ├── runtime.json
        ├── rootfs_before.json
        ├── rootfs_after.json
        ├── rootfs_diff.json
        ├── runtime_requirements.json
        ├── repair_plan.json
        ├── target_state_evaluation.json
        └── observation_lifecycle.json
```

The exact Phase 2 artifact set depends on which current development patches are
installed in the checkout.

## Reading results

Unified human-readable report:

```bash
cat workdir/report_demo_static/pipeline_report.md
```

Unified machine-readable report:

```bash
jq . workdir/report_demo_static/pipeline_report.json
```

Raw Phase 1 metadata:

```bash
jq . workdir/report_demo_static/phase1/unpacked.json
```

Compatibility conversion audit:

```bash
jq . workdir/report_demo_static/bridge_audit.json
```

Phase 2 report:

```bash
cat workdir/report_demo_static/phase2/report.md
jq . workdir/report_demo_static/phase2/report.json
```

Observed runtime requirements:

```bash
jq . \
  workdir/report_demo_static/phase2/config/runtime_requirements.json
```

Passive repair plan:

```bash
jq . \
  workdir/report_demo_static/phase2/config/repair_plan.json
```

Only automatic repair candidates:

```bash
jq '
  .decisions[]
  | select(.automatic_allowed == true)
' workdir/report_demo_static/phase2/config/repair_plan.json
```

## Running Phase 2 directly

The existing Phase 2 launcher remains available:

```bash
PYTHONPATH=. python scripts/run_sample.py \
  --taint examples/unpacked.json \
  --binary samples/test_stat \
  --out workdir/test_stat_phase2 \
  --network none \
  --timeout 30
```

## Tests

Run the Python test suite:

```bash
make test
```

Check the unified launcher syntax:

```bash
python -m py_compile scripts/run_static_pipeline.py
```

## Troubleshooting

### `Could not find the compiled QEMU plugin`

The current launcher builds the plugin automatically. Check:

```bash
ls -l build/qemu_unpacker.so
cat build/qemu_unpacker.build.log
```

If the QEMU tree is not `~/qemu`, pass it:

```bash
--qemu-source /absolute/path/to/qemu
```

### `configured QEMU source/build tree was not found`

Check:

```bash
test -d "$HOME/qemu/include"
test -d "$HOME/qemu/build"
find "$HOME/qemu/include" -name 'qemu-plugin.h' -print
```

Then pass the correct root:

```bash
--qemu-source "$HOME/qemu"
```

### `pkg-config could not resolve glib-2.0 or capstone`

Check:

```bash
pkg-config --cflags --libs glib-2.0 capstone
```

On Arch Linux:

```bash
sudo pacman -S --needed glib2 capstone pkgconf
```

### `Neither qemu-i386 nor qemu-i386-static was found`

Check:

```bash
command -v qemu-i386
command -v qemu-i386-static
```

Install QEMU user-mode emulation or pass the executable:

```bash
--qemu /absolute/path/to/qemu-i386
```

### Output directory already exists

Use a new path or add:

```bash
--force
```

### Phase 1 did not produce `unpacked.json`

Inspect:

```bash
tail -n 100 workdir/<run>/logs/phase1_stderr.log
tail -n 100 workdir/<run>/logs/phase1_stdout.log
```

Verify the plugin directly:

```bash
PROJECT_ROOT="$(pwd)"
mkdir -p /tmp/tf-phase1-smoke
cd /tmp/tf-phase1-smoke

qemu-i386 \
  -plugin "$PROJECT_ROOT/build/qemu_unpacker.so" \
  "$PROJECT_ROOT/samples/test_stat"

ls -l unpacked.bin unpacked.json
```

### Phase 2 failed

Inspect:

```bash
tail -n 100 workdir/<run>/logs/phase2_stdout.log
tail -n 100 workdir/<run>/logs/phase2_stderr.log
```

## Current limitations

The current unified wrapper is intended for integration demonstrations and
progress reporting. It does not yet provide:

- execution of the raw Phase 1 memory dump;
- fixed-address snapshot replay;
- register-context restoration;
- complete thread, TLS, descriptor, signal, or kernel-state restoration;
- stable dynamic-ELF reconstruction;
- ARM or MIPS Phase 1 support;
- production-grade DTA/DSE;
- automatic application and validation of the passive repair plan.

The static demo demonstrates trace-relative sufficiency for a controlled
fixture. It does not constitute malware-family evaluation, protocol-semantic
rehosting, or a proof of environment minimality.

The next execution milestone is to replace the temporary
`original static ELF + Phase 1 metadata` bridge with a validated reconstructed
ELF path or an address-preserving snapshot-replay backend.
