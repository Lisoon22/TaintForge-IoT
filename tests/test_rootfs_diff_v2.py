from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintforge_env.rootfs_diff import (
    RootfsDiffError,
    SnapshotOptions,
    diff_snapshots,
    load_json,
    save_json,
    snapshot_rootfs,
)


class RootfsDiffV2Tests(unittest.TestCase):
    def test_created_modified_and_deleted_paths_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp) / "rootfs"
            rootfs.mkdir()
            existing = rootfs / "etc" / "device.conf"
            existing.parent.mkdir()
            existing.write_text("before\n", encoding="utf-8")
            deleted = rootfs / "tmp" / "old.pid"
            deleted.parent.mkdir()
            deleted.write_text("1\n", encoding="utf-8")

            before = snapshot_rootfs(rootfs)
            existing.write_text("after\n", encoding="utf-8")
            deleted.unlink()
            created = rootfs / "var" / "run" / "malware.pid"
            created.parent.mkdir(parents=True)
            created.write_text("2\n", encoding="utf-8")
            after = snapshot_rootfs(rootfs)

            diff = diff_snapshots(before, after)
            self.assertEqual(diff["created_count"], 3)  # /var, /var/run, file
            self.assertEqual(diff["deleted_count"], 1)
            modified_paths = {entry["path"] for entry in diff["modified"]}
            self.assertIn("/etc/device.conf", modified_paths)

    def test_excluded_path_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp) / "rootfs"
            (rootfs / "proc" / "self").mkdir(parents=True)
            (rootfs / "proc" / "self" / "maps").write_text("secret", encoding="utf-8")
            (rootfs / "etc").mkdir()
            (rootfs / "etc" / "ok").write_text("ok", encoding="utf-8")

            snapshot = snapshot_rootfs(
                rootfs,
                options=SnapshotOptions(exclude_paths=("/proc",)),
            )
            self.assertNotIn("/proc", snapshot["entries"])
            self.assertNotIn("/proc/self/maps", snapshot["entries"])
            self.assertIn("/etc/ok", snapshot["entries"])
            self.assertEqual(snapshot["skipped"][0]["reason"], "excluded")

    def test_atomic_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config" / "snapshot.json"
            save_json({"value": 1}, path)
            self.assertEqual(load_json(path), {"value": 1})
            self.assertEqual(list(path.parent.glob("*.tmp")), [])
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_invalid_excluded_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = Path(tmp) / "rootfs"
            rootfs.mkdir()
            with self.assertRaises(RootfsDiffError):
                snapshot_rootfs(
                    rootfs,
                    options=SnapshotOptions(exclude_paths=("relative/path",)),
                )


if __name__ == "__main__":
    unittest.main()
