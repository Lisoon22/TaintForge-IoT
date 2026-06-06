import argparse
import asyncio
from pathlib import Path
from taintforge_env.network_policy import load_network_policy
from taintforge_env.network_stub import run_network_emulator

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()

    policy = load_network_policy(args.policy)

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(run_network_emulator(policy=policy, log_dir = log_dir))
    except KeyboardInterrupt:
        print("Network emulator stopped")

if __name__ == "__main__":
    main()
