import argparse
from pathlib import Path

from taintforge_env.sandbox_runner import (SandboxRunnerError, build_sandbox_run_config, generate_run_sandbox_script)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument(
        "--network-mode",
        choices=["none"],
        default="none",
    )
    args = parser.parse_args()

    try:
        config = build_sandbox_run_config(runtime_config_path=args.runtime, timeout_seconds=args.timeout, network_mode=args.network_mode)

        generate_run_sandbox_script(config=config, out_path=Path(args.out))

    except SandboxRunnerError as e:
        print(f" Failed to generate sandbox runner: {e}")
        raise SystemExit(1)

    print(f" Sandbox runner generated: {args.out}")
    print(f" Network mode: {args.network_mode}")


if __name__ == "__main__":
    main()
