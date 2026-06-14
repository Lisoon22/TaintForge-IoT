import argparse

from taintforge_env.strace_parser import (
    StraceParserError,
    parse_strace_logs,
)


def main():
    parser = argparse.ArgumentParser(
        description="Parse strace logs into syscall_events.jsonl"
    )
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    try:
        summary = parse_strace_logs(
            log_dir=args.log_dir,
            out_path=args.out,
        )
    except StraceParserError as e:
        print(f" strace parsing failed: {e}")
        raise SystemExit(1)

    print(" strace parsed")
    print(f"    events: {summary.get('events_total')}")
    print(f"    categories: {summary.get('by_category')}")
    print(f"    high risk: {summary.get('high_risk_count')}")


if __name__ == "__main__":
    main()
