# TaintForge-IoT Reviewer Guide

This guide provides the shortest reproducible path for evaluating the current
research prototype. It covers the implemented Phase 1 to Phase 2 path only;
fuzzing (Phase 3) is outside the submitted demo.

## 1. What this demo evaluates

The canonical experiment runs a statically linked Linux i386 fixture through
the complete current pipeline:

1. Phase 1 executes the sample under QEMU and records file and network
   dependencies while retaining `unpacked.bin` and `unpacked.json`.
2. The compatibility bridge normalizes the Phase 1 observations into the
   Phase 2 input contract.
3. Phase 2 reconstructs a minimal filesystem and controlled network
   environment, then re-executes the sample inside that environment.
4. A versioned target-state specification evaluates whether the expected
   behavioral milestone was reached.
5. The Phase 2 run is repeated three times as a small stability check.

The experiment includes an empty-contract baseline. The fixture must fail to
reach its milestone in the baseline and reach it after the Phase 1 dependency
contract is applied.

## 2. Supported environment and input

The reference development environment is Arch Linux. A real Linux host or a
disposable Linux VM is recommended because the runtime needs QEMU user-mode
execution, mount/network namespaces, chroot, and firewall tooling.

The current unified path accepts only binaries with all of these properties:

- Linux ELF executable;
- ELF32;
- little-endian;
- Intel 80386;
- statically linked, with no `PT_INTERP` program header.

Dynamic binaries, x86-64, ARM, AArch64, and MIPS are not supported by this
temporary unified launcher.

## 3. Safety

Do not run unknown malware on a workstation containing valuable data or
credentials. Use a disposable VM or dedicated analysis machine.

Phase 1 creates a network namespace by default. Phase 2 uses chroot, private
mounts, resource limits, and network namespaces. These controls reduce
exposure, but they are not a virtual-machine security boundary.

Never use `--phase1-isolation none` with an untrusted sample.

## 4. Install the dependencies on Arch Linux

From an up-to-date Arch Linux installation:

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

Clone the repository and enter it:

```bash
git clone https://github.com/Lisoon22/TaintForge-IoT.git
cd TaintForge-IoT
```

The Phase 1 QEMU plugin is built automatically when a usable prebuilt plugin
is not present. The build requires `glib-2.0`, Capstone development metadata,
and `qemu-plugin.h`.

## 5. Run the preflight check

```bash
make doctor
```

Every required entry should be reported as `[ok]`. In particular, confirm:

- `qemu-i386` or `qemu-i386-static` is available;
- `pkg-config` finds both `glib-2.0` and `capstone`;
- a QEMU plugin header is available;
- namespace, tracing, firewall, and connection-inspection tools are installed.

If the QEMU plugin header is not installed system-wide, a configured QEMU
source/build tree can be supplied later with:

```bash
make demo-static DEMO_ARGS='--qemu-source /absolute/path/to/qemu'
```

## 6. Run the unit tests

```bash
make test
```

The submitted Phase 2 demo currently contains 188 tests. The expected final
result is:

```text
Ran 188 tests
OK
```

These tests do not replace the end-to-end experiment; they validate parsers,
orchestration, reporting, sandbox generation, the target specification, bridge
validation, and the reviewer-facing Make targets.

## 7. Run the complete reproducible demo

```bash
make demo-static
```

The command builds the static i386 fixture and runs the baseline, Phase 1,
bridge, Phase 2, target-state evaluation, and three stability repetitions.
The runtime may ask for the current user's `sudo` password when it creates the
controlled namespaces and mounts.

The experiment is successful only when all of the following are true:

- the empty-contract baseline does not reach the milestone;
- Phase 1 reports the required file and network observations;
- the bridge transfers the required file and TCP endpoint into
  `phase2_input.json`;
- the dependency-guided Phase 2 run reaches the milestone;
- all three stability repetitions reach the milestone and exit successfully.

The primary result files are:

```text
workdir/phase2_static_demo/demo_summary.json
workdir/phase2_static_demo/demo_summary.md
workdir/phase2_static_demo/full_pipeline/pipeline_report.json
workdir/phase2_static_demo/full_pipeline/pipeline_report.md
workdir/phase2_static_demo/full_pipeline/phase2_input.json
workdir/phase2_static_demo/full_pipeline/bridge_audit.json
workdir/phase2_static_demo/full_pipeline/phase1/unpacked.bin
workdir/phase2_static_demo/full_pipeline/phase1/unpacked.json
```

Inspect the acceptance evidence with:

```bash
jq '.passed' workdir/phase2_static_demo/demo_summary.json
jq '.baseline' workdir/phase2_static_demo/demo_summary.json
jq '.full_pipeline.bridge_contract' \
  workdir/phase2_static_demo/demo_summary.json
jq '.full_pipeline.milestone_reached' \
  workdir/phase2_static_demo/demo_summary.json
jq '.stability' workdir/phase2_static_demo/demo_summary.json
```

The expected high-level values are:

```text
passed                                      true
baseline.milestone_reached                  false
baseline.guest_exit_code                    10
bridge_contract.required_file_observed      true
bridge_contract.required_network_observed   true
full_pipeline.milestone_reached             true
stability.successful_repetitions             3
stability.requested_repetitions              3
```

To use a custom QEMU tree or increase a timeout:

```bash
make demo-static \
  DEMO_ARGS='--qemu-source /absolute/path/to/qemu --phase2-timeout 90'
```

## 8. Analyze a reviewer-provided binary

First inspect the input:

```bash
file /absolute/path/to/sample
readelf -hW /absolute/path/to/sample
readelf -lW /absolute/path/to/sample | grep INTERP || true
```

The last command should print no `INTERP` entry. Ensure the sample is
executable:

```bash
chmod +x /absolute/path/to/sample
```

Run the complete current Phase 1 to Phase 2 path with one command:

```bash
make analyze-static SAMPLE=/absolute/path/to/sample
```

By default, the output is written to `workdir/static_analysis` and the network
mode is selected automatically. Reviewers may choose another location or
disable controlled responders:

```bash
make analyze-static \
  SAMPLE=/absolute/path/to/sample \
  ANALYZE_OUT=workdir/reviewer_sample \
  ANALYZE_NETWORK=none
```

Additional launcher arguments can be passed without editing the Makefile:

```bash
make analyze-static \
  SAMPLE=/absolute/path/to/sample \
  ANALYZE_ARGS='--qemu-source /absolute/path/to/qemu --phase2-timeout 90'
```

Important output files include:

```text
workdir/static_analysis/pipeline_report.json
workdir/static_analysis/pipeline_report.md
workdir/static_analysis/phase2_input.json
workdir/static_analysis/bridge_audit.json
workdir/static_analysis/phase1/unpacked.bin
workdir/static_analysis/phase1/unpacked.json
workdir/static_analysis/phase2/report.json
workdir/static_analysis/phase2/report.md
```

The generic command validates pipeline execution and produces evidence, but it
does not claim a binary-specific behavioral milestone. Such a milestone must
be defined by an analyst who understands the intended behavior of that sample.

## 9. How to interpret the main artifacts

| Artifact | Purpose |
| --- | --- |
| `unpacked.bin` | Raw Phase 1 memory dump retained for analysis. |
| `unpacked.json` | Phase 1 metadata and observed dependency events. |
| `phase2_input.json` | Dependencies normalized for Phase 2. |
| `bridge_audit.json` | Counts, filtering, and lossy bridge transformations. |
| `phase2/report.json` | Structured Phase 2 environment and runtime report. |
| `phase2/report.md` | Human-readable Phase 2 report. |
| `pipeline_report.json` | Machine-readable end-to-end pipeline status. |
| `pipeline_report.md` | Human-readable end-to-end summary. |
| `demo_summary.json` | Canonical demo acceptance and stability result. |

## 10. Troubleshooting

### `make doctor` reports a missing QEMU plugin header

Install the relevant QEMU development files or provide a configured QEMU
source/build tree:

```bash
make demo-static DEMO_ARGS='--qemu-source /absolute/path/to/qemu'
```

For a reviewer-provided binary:

```bash
make analyze-static \
  SAMPLE=/absolute/path/to/sample \
  ANALYZE_ARGS='--qemu-source /absolute/path/to/qemu'
```

### Phase 1 plugin compilation fails

Inspect:

```text
build/qemu_unpacker.build.log
```

Then verify:

```bash
pkg-config --cflags --libs glib-2.0 capstone
```

### `unshare: Operation not permitted`

The current host or container is blocking Linux namespaces. Run the project on
a Linux host or disposable VM that permits mount and network namespaces. A
restricted application container is usually insufficient for the full demo.

### The custom sample is rejected before Phase 1

The error message reports the incompatible ELF property. Recheck the sample
against the input requirements in section 2. Dynamic or non-i386 binaries are
outside the current demo scope.

### A previous run left generated output

Both reviewer-facing commands use `--force` for their own output directory.
To remove all generated demo files manually:

```bash
make clean
```

This also removes the automatically built QEMU plugin, so the next run may
compile it again.

## 11. Scientific scope and limitations

The submitted demo supports the claim that the observed Phase 1 dependency
contract is sufficient for the controlled fixture to reach its defined Phase
2 milestone, while the empty contract is not sufficient.

The demo does not claim:

- execution of `unpacked.bin` as a restored process snapshot;
- fixed-address memory replay or register restoration;
- subset-minimality of the synthesized environment;
- support for dynamically linked or non-i386 binaries;
- implementation of a real malware C2 application protocol;
- VM-grade isolation;
- fuzzing or Phase 3 completion.

Phase 2 currently re-executes the original static ELF using the dependency
metadata produced by Phase 1. This limitation is recorded in the generated
reports and should be considered when interpreting the results.

## 12. Minimal reviewer checklist

```bash
make doctor
make test
make demo-static
jq '.passed' workdir/phase2_static_demo/demo_summary.json
```

Expected final value:

```text
true
```
