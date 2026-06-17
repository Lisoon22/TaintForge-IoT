import argparse

from taintforge_env.rootfs_diff import (
    RootfsDiffError,
    diff_snapshots,
    load_json,
    save_json,
    snapshot_rootfs,
)


def main():
    parser = argparse.ArgumentParser(
        description="Snapshot and diff TaintForge rootfs"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot_parser = subparsers.add_parser("snapshot")
    snapshot_parser.add_argument("--rootfs", required=True)
    snapshot_parser.add_argument("--out", required=True)

    diff_parser = subparsers.add_parser("diff")
    diff_parser.add_argument("--before", required=True)
    diff_parser.add_argument("--after", required=True)
    diff_parser.add_argument("--out", required=True)

    args = parser.parse_args()

    try:
        if args.command == "snapshot":
            snapshot = snapshot_rootfs(args.rootfs)
            save_json(snapshot, args.out)
            print(" rootfs snapshot saved")
            print(f"    entries: {snapshot.get('entries_count')}")
            print(f"    out:     {args.out}")
            return

        if args.command == "diff":
            before = load_json(args.before)
            after = load_json(args.after)

            diff = diff_snapshots(before=before, after=after)
            save_json(diff, args.out)

            print(" rootfs diff saved")
            print(f"    created:  {diff.get('created_count')}")
            print(f"    modified: {diff.get('modified_count')}")
            print(f"    deleted:  {diff.get('deleted_count')}")
            print(f"    out:      {args.out}")
            return

    except RootfsDiffError as e:
        print(f" rootfs diff failed: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
