#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SEED_PATH = Path("/tmp/taintforge-phase2-demo.ready")


class DemoError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise DemoError(f"JSON artifact is not an object: {path}")
    return raw


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_command(
    command: list[str],
    *,
    cwd: Path,
    expected: set[int] | None = None,
) -> subprocess.CompletedProcess[str]:
    expected_codes = expected or {0}
    print("[cmd]", " ".join(command), flush=True)
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        check=False,
    )
    if result.returncode not in expected_codes:
        raise DemoError(
            f"command exited with {result.returncode}, expected "
            f"{sorted(expected_codes)}: {' '.join(command)}"
        )
    return result


def evaluate_target(
    *,
    project_root: Path,
    run_dir: Path,
    spec: Path,
    expected_reached: bool,
) -> dict[str, Any]:
    result = run_command(
        [
            sys.executable,
            "scripts/evaluate_target_state.py",
            "--run-dir",
            str(run_dir),
            "--spec",
            str(spec),
        ],
        cwd=project_root,
        expected={0} if expected_reached else {1},
    )
    evaluation_path = run_dir / "config" / "target_state_evaluation.json"
    evaluation = load_json(evaluation_path)
    if evaluation.get("reached") is not expected_reached:
        raise DemoError(
            "target-state result disagrees with the expected experimental "
            f"outcome: {evaluation_path}"
        )
    run_command(
        [
            sys.executable,
            "scripts/generate_report.py",
            "--out",
            str(run_dir),
        ],
        cwd=project_root,
    )
    return evaluation


def build_markdown(summary: dict[str, Any]) -> str:
    baseline = summary["baseline"]
    full = summary["full_pipeline"]
    stability = summary["stability"]
    lines = [
        "# TaintForge-IoT Static Phase 2 Demo",
        "",
        f"Generated: `{summary['generated_at_utc']}`",
        f"Overall result: `{'PASS' if summary['passed'] else 'FAIL'}`",
        "",
        "## Scientific claim",
        "",
        summary["scientific_claim"],
        "",
        "## Baseline",
        "",
        f"- Milestone reached: `{baseline['milestone_reached']}`",
        f"- Guest exit code: `{baseline['guest_exit_code']}`",
        f"- Evidence: `{baseline['evaluation']}`",
        "",
        "## Phase 1 and Phase 2",
        "",
        f"- Pipeline status: `{full['status']}`",
        f"- Phase 1 file dependencies: `{full['phase1_file_dependencies']}`",
        f"- Phase 1 network events: `{full['phase1_network_events']}`",
        f"- Milestone reached: `{full['milestone_reached']}`",
        f"- Evidence: `{full['evaluation']}`",
        "",
        "## Stability",
        "",
        f"- Successful repetitions: `{stability['successful_repetitions']}/"
        f"{stability['requested_repetitions']}`",
        "",
        "## Scope limitations",
        "",
    ]
    lines.extend(f"- {item}" for item in summary["limitations"])
    lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the reproducible TaintForge-IoT static i386 Phase 2 "
            "baseline, full pipeline, milestone oracle, and stability trials."
        )
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("workdir/phase2_static_demo"),
    )
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--qemu-source", type=Path)
    parser.add_argument("--qemu", default=None)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--phase1-timeout", type=int, default=20)
    parser.add_argument("--phase2-timeout", type=int, default=30)
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.repetitions < 1:
        raise SystemExit("--repetitions must be positive")

    project_root = Path(__file__).resolve().parent.parent
    output_root = args.out.expanduser().resolve()
    target = project_root / "samples" / "phase2_demo_i386"
    target_spec = project_root / "examples" / "targets" / "phase2_demo_i386.json"
    baseline_taint = project_root / "examples" / "phase2_demo_baseline.json"

    if output_root.exists():
        if not args.force:
            print(
                f"[-] Output exists: {output_root}; use --force",
                file=sys.stderr,
            )
            return 2
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root)
    os.environ.update(env)

    try:
        run_command(
            ["bash", "scripts/build_phase2_demo_i386.sh"],
            cwd=project_root,
        )
        target_sha256 = sha256_file(target)

        SEED_PATH.unlink(missing_ok=True)
        baseline_dir = output_root / "baseline"
        run_command(
            [
                sys.executable,
                "scripts/run_sample.py",
                "--taint",
                str(baseline_taint),
                "--binary",
                str(target),
                "--out",
                str(baseline_dir),
                "--network",
                "none",
                "--timeout",
                str(args.phase2_timeout),
            ],
            cwd=project_root,
        )
        baseline_evaluation = evaluate_target(
            project_root=project_root,
            run_dir=baseline_dir,
            spec=target_spec,
            expected_reached=False,
        )
        baseline_status = load_json(
            baseline_dir / "logs" / "runtime_status.json"
        )
        if baseline_status.get("exit_code") != 10:
            raise DemoError(
                "baseline must fail on the absent file with exit code 10"
            )

        SEED_PATH.write_text(
            "dependency observed during the Phase 1 trace\n",
            encoding="utf-8",
        )
        full_dir = output_root / "full_pipeline"
        command = [
            sys.executable,
            "scripts/run_static_pipeline.py",
            str(target),
            "--out",
            str(full_dir),
            "--network",
            "controlled",
            "--self-test-network",
            "--target-spec",
            str(target_spec),
            "--phase1-timeout",
            str(args.phase1_timeout),
            "--phase2-timeout",
            str(args.phase2_timeout),
            "--force",
        ]
        if args.plugin is not None:
            command.extend(["--plugin", str(args.plugin.resolve())])
        if args.qemu_source is not None:
            command.extend(["--qemu-source", str(args.qemu_source.resolve())])
        if args.qemu is not None:
            command.extend(["--qemu", args.qemu])
        run_command(command, cwd=project_root)

        pipeline_report = load_json(full_dir / "pipeline_report.json")
        full_evaluation_path = (
            full_dir
            / "phase2"
            / "config"
            / "target_state_evaluation.json"
        )
        full_evaluation = load_json(full_evaluation_path)
        if not full_evaluation.get("reached"):
            raise DemoError("full Phase 2 run did not reach the milestone")

        phase2_input = full_dir / "phase2_input.json"
        repetitions: list[dict[str, Any]] = []
        for index in range(1, args.repetitions + 1):
            run_dir = output_root / "stability" / f"run_{index:02d}"
            run_command(
                [
                    sys.executable,
                    "scripts/run_sample.py",
                    "--taint",
                    str(phase2_input),
                    "--binary",
                    str(target),
                    "--out",
                    str(run_dir),
                    "--network",
                    "controlled",
                    "--self-test-network",
                    "--namespace",
                    f"tf-phase2-demo-{index}",
                    "--timeout",
                    str(args.phase2_timeout),
                ],
                cwd=project_root,
            )
            evaluation = evaluate_target(
                project_root=project_root,
                run_dir=run_dir,
                spec=target_spec,
                expected_reached=True,
            )
            status = load_json(run_dir / "logs" / "runtime_status.json")
            repetitions.append(
                {
                    "index": index,
                    "milestone_reached": evaluation.get("reached"),
                    "guest_exit_code": status.get("exit_code"),
                    "evaluation": str(
                        run_dir.relative_to(output_root)
                        / "config"
                        / "target_state_evaluation.json"
                    ),
                }
            )

        successful = sum(
            1
            for item in repetitions
            if item["milestone_reached"] is True
            and item["guest_exit_code"] == 0
        )
        summary = {
            "schema_version": 1,
            "generated_at_utc": utc_now(),
            "passed": (
                pipeline_report.get("status") == "completed"
                and successful == args.repetitions
            ),
            "scientific_claim": (
                "For this controlled static i386 target, the Phase 1 "
                "dependency contract enables Phase 2 to synthesize a "
                "trace-relative sufficient environment that reaches the "
                "analyst-defined milestone, while the empty-contract "
                "baseline does not."
            ),
            "target": {
                "path": str(target.relative_to(project_root)),
                "sha256": target_sha256,
                "target_spec": str(target_spec.relative_to(project_root)),
                "target_spec_sha256": sha256_file(target_spec),
            },
            "baseline": {
                "milestone_reached": baseline_evaluation.get("reached"),
                "guest_exit_code": baseline_status.get("exit_code"),
                "evaluation": "baseline/config/target_state_evaluation.json",
            },
            "full_pipeline": {
                "status": pipeline_report.get("status"),
                "phase1_file_dependencies": pipeline_report.get("phase1", {}).get(
                    "file_dependencies"
                ),
                "phase1_network_events": pipeline_report.get("phase1", {}).get(
                    "network_events"
                ),
                "milestone_reached": full_evaluation.get("reached"),
                "evaluation": (
                    "full_pipeline/phase2/config/target_state_evaluation.json"
                ),
                "pipeline_report": "full_pipeline/pipeline_report.json",
            },
            "stability": {
                "requested_repetitions": args.repetitions,
                "successful_repetitions": successful,
                "runs": repetitions,
            },
            "limitations": [
                "The current unified path supports only static Linux ELF32 i386.",
                "Phase 2 re-executes the original ELF and does not execute unpacked.bin.",
                "This experiment demonstrates trace-relative sufficiency, not subset-minimality.",
                "The controlled responder proves transport-level rehosting, not real C2 protocol semantics.",
                "Namespaces and chroot reduce exposure but are not a virtual machine boundary."
            ],
        }
        write_json(output_root / "demo_summary.json", summary)
        (output_root / "demo_summary.md").write_text(
            build_markdown(summary),
            encoding="utf-8",
        )
        if not summary["passed"]:
            raise DemoError("one or more demo acceptance checks failed")

        print("[+] Static Phase 2 scientific demo passed")
        print(f"[+] Summary: {output_root / 'demo_summary.json'}")
        print(f"[+] Report:  {output_root / 'demo_summary.md'}")
        return 0
    except (DemoError, OSError) as exc:
        print(f"[-] Static Phase 2 demo failed: {exc}", file=sys.stderr)
        return 1
    finally:
        SEED_PATH.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
