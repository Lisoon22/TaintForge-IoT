import argparse
from pathlib import Path

from taintforge_env.network_sandbox_runner import (
    NetworkSandboxRunnerError,
    build_network_sandbox_config,
    generate_network_sandbox_script,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--namespace", default="tf-iot-ns")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    try:
        config = build_network_sandbox_config(runtime_config_path=args.runtime, namespace_name=args.namespace, timeout_seconds=args.timeout)

        generate_network_sandbox_script(config=config, network_policy_path=args.policy, out_path=Path(args.out))


    except NetworkSandboxRunnerError as e:
        print(f" Failed to generate network sandbox runner: {e}")
        raise SystemExit(1)

    print(f" Network sandbox runner generated: {args.out}")
    print(f" Namespace: {args.namespace}")


if __name__ == "__main__":
    main()
