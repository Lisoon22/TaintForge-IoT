from __future__ import annotations

import argparse

from taintforge_env.observations import ObservationLoadError, load_observation_bundle
from taintforge_env.requirement_extractor import RequirementExtractor


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract Phase 2 runtime requirements from syscall, network, "
            "stderr, runtime-status, and rootfs-diff artifacts"
        )
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Phase 2 output directory containing logs/",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output runtime_requirements.json path",
    )
    args = parser.parse_args()

    try:
        bundle = load_observation_bundle(args.run_dir)
        report = RequirementExtractor().extract(bundle)
        report.save(args.out)
    except ObservationLoadError as exc:
        print(f"Requirement extraction failed: {exc}")
        raise SystemExit(1) from exc

    summary = report.summary()
    print("Runtime requirements extracted")
    print(f"requirements: {summary['requirements_total']}")
    print(f"repairable: {summary['repairable_total']}")
    print(f"by kind: {summary['by_kind']}")
    print(f"by status: {summary['by_status']}")
    if report.warnings:
        print("warnings:")
        for warning in report.warnings:
            print(f"  - {warning}")


if __name__ == "__main__":
    main()
