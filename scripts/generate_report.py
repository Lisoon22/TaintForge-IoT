import argparse

from taintforge_env.report_generator import (
    ReportGenerationError,
    generate_report,
)


def main():
    parser = argparse.ArgumentParser(
        description="Generate TaintForge-IoT Phase 2 run report"
    )
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    try:
        report = generate_report(args.out)
    except ReportGenerationError as e:
        print(f" Report generation failed: {e}")
        raise SystemExit(1)

    print(" Report generated")
    print(f"    report.json: {args.out}/report.json")
    print(f"    report.md:   {args.out}/report.md")

    network = report.get("network", {})
    print()
    print(" Network summary")
    print(f"    total events:       {network.get('events_total')}")
    print(f"    known TCP events:   {network.get('known_tcp_events')}")
    print(f"    unknown TCP events: {network.get('unknown_tcp_events')}")
    print(f"    UDP datagrams:      {network.get('udp_datagrams')}")
    print(f"    DNS datagrams:      {network.get('dns_datagrams')}")


if __name__ == "__main__":
    main()
