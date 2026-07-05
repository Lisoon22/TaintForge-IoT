#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from taintforge_env.environment_snapshot import (
    EnvironmentSnapshotError,
    EnvironmentSnapshotStore,
    scan_environment,
    tree_digest,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Capture, verify, and clone immutable clean-rootfs snapshots for "
            "TaintForge-IoT repair iterations."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture = subparsers.add_parser("capture", help="capture a clean rootfs")
    capture.add_argument("--store", type=Path, required=True)
    capture.add_argument("--rootfs", type=Path, required=True)

    verify = subparsers.add_parser("verify", help="verify a stored snapshot")
    verify.add_argument("--store", type=Path, required=True)
    verify.add_argument("--snapshot", required=True)

    clone = subparsers.add_parser("clone", help="clone a verified snapshot")
    clone.add_argument("--store", type=Path, required=True)
    clone.add_argument("--snapshot", required=True)
    clone.add_argument("--out-rootfs", type=Path, required=True)

    inspect = subparsers.add_parser("inspect", help="inspect a rootfs digest")
    inspect.add_argument("--rootfs", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "inspect":
            entries = scan_environment(args.rootfs)
            print(
                json.dumps(
                    {
                        "rootfs": str(args.rootfs.resolve()),
                        "tree_sha256": tree_digest(entries),
                        "entries_total": len(entries),
                        "total_file_bytes": sum(entry.size or 0 for entry in entries),
                    },
                    indent=2,
                )
            )
            return 0

        store = EnvironmentSnapshotStore(args.store)
        if args.command == "capture":
            result = store.capture(args.rootfs)
            print(f"[+] Snapshot ID: {result.manifest.snapshot_id}")
            print(f"[+] Tree SHA-256: {result.manifest.tree_sha256}")
            print(f"[+] Snapshot directory: {result.snapshot_dir}")
            print(f"[+] Reused existing: {result.reused_existing}")
            print(f"[+] Entries: {result.manifest.summary()['entries_total']}")
            return 0
        if args.command == "verify":
            manifest = store.verify(args.snapshot)
            print(f"[+] Snapshot verified: {manifest.snapshot_id}")
            print(f"[+] Tree SHA-256: {manifest.tree_sha256}")
            print(f"[+] Entries: {manifest.summary()['entries_total']}")
            return 0
        if args.command == "clone":
            manifest = store.clone(args.snapshot, args.out_rootfs)
            print(f"[+] Snapshot cloned: {manifest.snapshot_id}")
            print(f"[+] Destination rootfs: {args.out_rootfs.resolve()}")
            print(f"[+] Tree SHA-256: {manifest.tree_sha256}")
            return 0
        raise AssertionError(f"unsupported command: {args.command}")
    except EnvironmentSnapshotError as exc:
        print(f"[!] Environment snapshot operation failed: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
