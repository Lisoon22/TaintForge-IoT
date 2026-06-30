#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from taintforge_env.repair_planner import RepairPlanner, RepairPlanningError


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build a passive, auditable Phase 2 repair plan from "
            "runtime_requirements.json. The command never mutates the rootfs."
        )
    )
    parser.add_argument(
        "--requirements",
        required=True,
        type=Path,
        help="Path to config/runtime_requirements.json",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output path for repair_plan.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        plan = RepairPlanner().plan_file(args.requirements, args.out)
    except RepairPlanningError as exc:
        print(f"[!] Repair planning failed: {exc}")
        return 2

    summary = plan.summary()
    print(f"[+] Repair plan: {args.out}")
    print(f"[+] Decisions: {summary['decisions_total']}")
    print(f"[+] Automatic candidates: {summary['automatic_candidates']}")
    for disposition, count in summary["by_disposition"].items():
        print(f"    {disposition}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
