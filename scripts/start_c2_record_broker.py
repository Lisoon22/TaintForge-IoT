import argparse
import asyncio
from pathlib import Path

from taintforge_env.c2_record_broker import C2RecordBroker
from taintforge_env.c2_record_policy import (
    C2RecordPolicyError,
    load_c2_record_policy,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run bounded TaintForge C2 recording broker"
    )
    parser.add_argument("--policy", required=True)
    parser.add_argument("--bind-ip", required=True)
    parser.add_argument("--capture-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--event-log", required=True)
    args = parser.parse_args()

    try:
        policy = load_c2_record_policy(args.policy)
    except C2RecordPolicyError as exc:
        parser.error(str(exc))

    broker = C2RecordBroker(
        policy=policy,
        bind_ip=args.bind_ip,
        capture_root=Path(args.capture_dir),
        run_id=args.run_id,
        event_path=Path(args.event_log),
    )

    async def run() -> None:
        await broker.start()
        print(
            "[+] C2 record broker listening on "
            f"{args.bind_ip}:{broker.bound_port}",
            flush=True,
        )
        print(
            "[+] Upstream target: "
            f"{policy.target.upstream_ip}:"
            f"{policy.target.upstream_port}",
            flush=True,
        )
        try:
            await broker.serve_forever()
        finally:
            await broker.close()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
