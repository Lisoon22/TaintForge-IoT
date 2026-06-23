import argparse
from pathlib import Path
import json
import os
import stat


from taintforge_env.c2_record_policy import (
    C2RecordPolicyError,
    load_c2_record_policy,
)
from taintforge_env.egress_policy import (
    EgressPolicyError,
    load_egress_policy,
)
from taintforge_env.network_modes import (
    NetworkMode,
    normalize_network_mode,
    requires_egress_policy,
    requires_record_policy,
)
from taintforge_env.orchestrator import (
    OrchestratorConfig,
    OrchestratorError,
    Phase2Orchestrator,
)

def create_auto_sysroot(out_dir: Path, taint_path: Path) -> Path:
    """
    Create a minimal base sysroot automatically.

    This is enough for statically linked binaries and simple smoke tests.
    For dynamic firmware binaries, --sysroot can still be used to provide
    real vendor libraries.
    """
    with taint_path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)

    arch = cfg.get("arch", "generic")
    lib_deps = cfg.get("library_dependencies", [])

    sysroot = out_dir.parent / "_auto_sysroots" / f"{arch}-minimal"

    dirs = [
        "bin",
        "sbin",
        "lib",
        "lib32",
        "usr/bin",
        "usr/sbin",
        "usr/lib",
        "usr/lib32",
        "etc",
        "proc",
        "sys",
        "dev",
        "tmp",
        "var",
        "var/run",
        "run",
    ]

    for d in dirs:
        path = sysroot / d
        path.mkdir(parents=True, exist_ok=True)

    os.chmod(sysroot / "tmp", 0o1777)

    (sysroot / "etc" / "hosts").write_text(
        "127.0.0.1 localhost\n",
        encoding="utf-8",
    )

    (sysroot / "etc" / "hostname").write_text(
        "iot-device\n",
        encoding="utf-8",
    )

    (sysroot / "etc" / "resolv.conf").write_text(
        "nameserver 127.0.0.1\n",
        encoding="utf-8",
    )

    # Create basic device nodes when running as root.
    # If not root, skip: many static smoke tests do not need them.
    devices = [
        ("null", 0o666, 1, 3),
        ("zero", 0o666, 1, 5),
        ("random", 0o666, 1, 8),
        ("urandom", 0o666, 1, 9),
    ]

    for name, mode, major, minor in devices:
        dev_path = sysroot / "dev" / name
        if dev_path.exists():
            continue

        try:
            os.mknod(
                dev_path,
                stat.S_IFCHR | mode,
                os.makedev(major, minor),
            )
        except PermissionError:
            pass
        except FileExistsError:
            pass

    marker = sysroot / ".taintforge-auto-sysroot"
    marker.write_text(
        f"auto-generated minimal sysroot for arch={arch}\n"
        f"library_dependencies={len(lib_deps)}\n",
        encoding="utf-8",
    )

    return sysroot


def main():
    parser = argparse.ArgumentParser(
        description="Run TaintForge-IoT Phase 2 pipeline"
    )

    parser.add_argument("--taint", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sysroot", default=None, help="Optional base sysroot. If omitted, TaintForge creates a minimal one automatically.")
    parser.add_argument("--out", required=True)

    parser.add_argument("--timeout", type=int, default=60)

    parser.add_argument(
        "--network",
        choices=[
            "auto",
            "controlled",
            "none",
            "emulated",
            "replay",
            "brokered_fetch",
            "brokered_relay",
            "brokered_record",
        ],
        default="auto",
        help=(
            "Network mode. 'controlled' is an alias for 'emulated'. "
            "fetch/relay modes require --egress-policy; "
            "brokered_record requires --record-policy."
        ),
    )
    parser.add_argument(
        "--egress-policy",
        default=None,
        help="Path to a validated brokered-egress policy JSON.",
    )
    parser.add_argument(
        "--record-policy",
        default=None,
        help="Path to a strict brokered-record policy JSON.",
    )

    parser.add_argument("--bind-ip", default="10.10.0.1")
    parser.add_argument("--namespace", default="tf-iot-ns")

    parser.add_argument("--catch-all-port", type=int, default=40000)
    parser.add_argument("--udp-catch-all-port", type=int, default=40001)

    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--keep-namespace", action="store_true")
    parser.add_argument("--keep-workdir", action="store_true")
    parser.add_argument("--allow-missing-libraries", action="store_true")
    parser.add_argument("--self-test-network", action="store_true")

    args = parser.parse_args()

    with open(args.taint, "r", encoding="utf-8") as f:
        taint_raw = json.load(f)

    network_deps = taint_raw.get("network_dependencies", [])

    try:
        effective_network_mode = normalize_network_mode(
            args.network,
            has_network_dependencies=bool(network_deps),
        )
    except ValueError as exc:
        parser.error(str(exc))

    egress_policy_path: Path | None = None
    record_policy_path: Path | None = None

    if requires_record_policy(effective_network_mode):
        if not args.record_policy:
            parser.error(
                "--network brokered_record requires --record-policy"
            )
        if args.egress_policy:
            parser.error(
                "--egress-policy cannot be combined with brokered_record"
            )

        record_policy_path = Path(args.record_policy).resolve()
        try:
            load_c2_record_policy(record_policy_path)
        except C2RecordPolicyError as exc:
            parser.error(f"Invalid record policy: {exc}")

    elif args.record_policy:
        parser.error(
            "--record-policy is only valid with brokered_record"
        )

    if requires_egress_policy(effective_network_mode):
        if not args.egress_policy:
            parser.error(
                f"--network {effective_network_mode.value} requires "
                "--egress-policy"
            )

        egress_policy_path = Path(args.egress_policy).resolve()

        try:
            policy = load_egress_policy(egress_policy_path)
        except EgressPolicyError as exc:
            parser.error(f"Invalid egress policy: {exc}")

        if policy.mode != effective_network_mode:
            parser.error(
                "Egress policy mode does not match --network: "
                f"policy={policy.mode.value}, "
                f"network={effective_network_mode.value}"
            )
    elif args.egress_policy:
        parser.error(
            "--egress-policy is only valid with "
            "brokered_fetch or brokered_relay"
        )

    out_dir = Path(args.out).resolve()
    taint_path = Path(args.taint).resolve()

    if args.sysroot is None:
        args.sysroot = str(create_auto_sysroot(out_dir, taint_path))
        print(f"[info] auto sysroot: {args.sysroot}")
    else:
        args.sysroot = str(Path(args.sysroot).resolve())

    config = OrchestratorConfig(
        taint_path=Path(args.taint),
        binary_path=Path(args.binary),
        sysroot_path=Path(args.sysroot),
        out_dir=Path(args.out),
        timeout_seconds=args.timeout,
        network_mode=effective_network_mode,
        egress_policy_path=egress_policy_path,
        record_policy_path=record_policy_path,
        bind_ip=args.bind_ip,
        namespace=args.namespace,
        catch_all_port=args.catch_all_port,
        udp_catch_all_port=args.udp_catch_all_port,
        build_only=args.build_only,
        keep_namespace=args.keep_namespace,
        keep_workdir=args.keep_workdir,
        allow_missing_libraries=args.allow_missing_libraries,
        self_test_network=args.self_test_network)

    try:
        Phase2Orchestrator(config).run()
    except OrchestratorError as e:
        print(f"[-] Orchestrator failed: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
