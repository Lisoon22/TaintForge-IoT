#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from taintforge_env.target_state_oracle import (
    TargetStateError,
    TargetStateOracle,
    TargetStateSpec,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate an explicit TaintForge-IoT target-state specification "
            "against an existing iteration run directory."
        )
    )
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=(
            "Output JSON path. Defaults to "
            "<run-dir>/config/target_state_evaluation.json."
        ),
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the target specification without reading runtime evidence.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        spec = TargetStateSpec.load(args.spec)
        if args.validate_only:
            print("[+] Target-state specification is valid")
            print(f"[+] Goal: {spec.goal_id}")
            print(f"[+] Rules: {len(spec.rules)}")
            print(f"[+] SHA-256: {spec.source_sha256}")
            return 0

        evaluation = TargetStateOracle().evaluate(args.run_dir, spec)
        out = args.out or (
            args.run_dir / "config" / "target_state_evaluation.json"
        )
        evaluation.save(out)
        print(json.dumps(evaluation.to_dict(), indent=2, ensure_ascii=False))
        print(f"[+] Evaluation saved: {out}")
        return 0 if evaluation.reached else 1
    except TargetStateError as exc:
        print(f"[!] Target-state evaluation failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
