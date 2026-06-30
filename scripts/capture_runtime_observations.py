#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from taintforge_env.rootfs_diff import SnapshotOptions
from taintforge_env.runtime_observer import (
    RuntimeObservationSession,
    RuntimeObserverError,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture Phase 2 rootfs observations and derive runtime requirements "
            "without depending on the Phase 1 JSON schema."
        )
    )
    parser.add_argument("phase", choices=("before", "after", "requirements", "finalize"))
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GUEST_PATH",
        help="Exclude an absolute guest path; may be repeated.",
    )
    parser.add_argument(
        "--cross-filesystems",
        action="store_true",
        help="Allow traversal into filesystems mounted below rootfs (unsafe by default).",
    )
    parser.add_argument(
        "--no-hash",
        action="store_true",
        help="Do not hash regular files; metadata changes will still be detected.",
    )
    parser.add_argument(
        "--non-strict",
        action="store_true",
        help="Record unreadable entries instead of failing the snapshot.",
    )
    parser.add_argument(
        "--allow-external-rootfs",
        action="store_true",
        help="Allow rootfs outside run-dir; disabled by default to prevent accidents.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    options = SnapshotOptions(
        stay_on_filesystem=not args.cross_filesystems,
        hash_regular_files=not args.no_hash,
        exclude_paths=tuple(args.exclude),
        strict=not args.non_strict,
    )

    try:
        session = RuntimeObservationSession(
            run_dir=args.run_dir,
            rootfs=args.rootfs,
            snapshot_options=options,
            require_rootfs_inside_run_dir=not args.allow_external_rootfs,
        )
        if args.phase == "before":
            snapshot = session.capture_before()
            output = {
                "phase": "before",
                "entries": snapshot.get("entries_count", 0),
                "path": str(session.paths.before_snapshot),
            }
        elif args.phase == "after":
            snapshot, diff = session.capture_after()
            output = {
                "phase": "after",
                "entries": snapshot.get("entries_count", 0),
                "created": diff.get("created_count", 0),
                "modified": diff.get("modified_count", 0),
                "deleted": diff.get("deleted_count", 0),
                "path": str(session.paths.rootfs_diff),
            }
        elif args.phase == "requirements":
            report = session.extract_requirements()
            output = {
                "phase": "requirements",
                "requirements": len(report.requirements),
                "warnings": list(report.warnings),
                "path": str(session.paths.requirements),
            }
        else:
            output = {
                "phase": "finalize",
                **session.finalize().to_dict(),
                "path": str(session.paths.requirements),
            }
    except RuntimeObserverError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
