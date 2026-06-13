import argparse
from pathlib import Path

from taintforge_env.orchestrator import (
    OrchestratorConfig,
    OrchestratorError,
    Phase2Orchestrator,
)


def main():
    parser = argparse.ArgumentParser(
        description="Run TaintForge-IoT Phase 2 pipeline"
    )

    parser.add_argument("--taint", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sysroot", required=True)
    parser.add_argument("--out", required=True)

    parser.add_argument("--timeout", type=int, default=60)

    parser.add_argument(
        "--network",
        choices=["controlled"],
        default="controlled",
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

    config = OrchestratorConfig(
        taint_path=Path(args.taint),
        binary_path=Path(args.binary),
        sysroot_path=Path(args.sysroot),
        out_dir=Path(args.out),
        timeout_seconds=args.timeout,
        network_mode=args.network,
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
