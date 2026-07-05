from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from taintforge_env.environment_snapshot import (
    EnvironmentSnapshotError,
    EnvironmentSnapshotStore,
    scan_environment,
    tree_digest,
)


class EnvironmentSnapshotStoreTests(unittest.TestCase):
    def test_capture_verify_and_clone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir(mode=0o755)
            (source / "etc").mkdir(mode=0o750)
            config = source / "etc" / "device.conf"
            config.write_bytes(b"arch=x86\n")
            os.chmod(config, 0o640)
            os.symlink("device.conf", source / "etc" / "current.conf")

            store = EnvironmentSnapshotStore(base / "store")
            captured = store.capture(source)
            verified = store.verify(captured.manifest.snapshot_id)
            clone = base / "clone"
            store.clone(captured.manifest.snapshot_id, clone)

            self.assertFalse(captured.reused_existing)
            self.assertEqual(verified.tree_sha256, captured.manifest.tree_sha256)
            self.assertEqual(tree_digest(scan_environment(clone)), captured.manifest.tree_sha256)
            self.assertEqual((clone / "etc" / "device.conf").read_bytes(), b"arch=x86\n")
            self.assertTrue((clone / "etc" / "current.conf").is_symlink())
            self.assertEqual(os.readlink(clone / "etc" / "current.conf"), "device.conf")
            self.assertEqual((clone / "etc").stat().st_mode & 0o777, 0o750)
            self.assertEqual((clone / "etc" / "device.conf").stat().st_mode & 0o777, 0o640)

    def test_capture_is_content_addressed_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            (source / "a").write_text("same\n", encoding="utf-8")
            store = EnvironmentSnapshotStore(base / "store")
            first = store.capture(source)
            second = store.capture(source)
            self.assertEqual(first.manifest.snapshot_id, second.manifest.snapshot_id)
            self.assertFalse(first.reused_existing)
            self.assertTrue(second.reused_existing)

    def test_clone_does_not_share_file_inodes_with_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            (source / "payload").write_bytes(b"original")
            store = EnvironmentSnapshotStore(base / "store")
            result = store.capture(source)
            clone = base / "clone"
            store.clone(result.manifest.snapshot_id, clone)
            snapshot_file = result.snapshot_dir / "rootfs" / "payload"
            clone_file = clone / "payload"
            self.assertNotEqual(snapshot_file.stat().st_ino, clone_file.stat().st_ino)
            clone_file.write_bytes(b"mutated")
            self.assertEqual(snapshot_file.read_bytes(), b"original")

    def test_guest_hardlinks_are_preserved_inside_each_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            first = source / "busybox"
            first.write_bytes(b"binary")
            os.link(first, source / "sh")
            store = EnvironmentSnapshotStore(base / "store")
            result = store.capture(source)
            clone = base / "clone"
            store.clone(result.manifest.snapshot_id, clone)
            snapshot_first = result.snapshot_dir / "rootfs" / "busybox"
            snapshot_second = result.snapshot_dir / "rootfs" / "sh"
            clone_first = clone / "busybox"
            clone_second = clone / "sh"
            self.assertEqual(snapshot_first.stat().st_ino, snapshot_second.stat().st_ino)
            self.assertEqual(clone_first.stat().st_ino, clone_second.stat().st_ino)
            self.assertNotEqual(snapshot_first.stat().st_ino, clone_first.stat().st_ino)

    def test_symlink_to_outside_is_copied_but_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = base / "outside"
            outside.write_text("secret", encoding="utf-8")
            source = base / "source"
            source.mkdir()
            os.symlink(str(outside), source / "outside-link")
            store = EnvironmentSnapshotStore(base / "store")
            result = store.capture(source)
            clone = base / "clone"
            store.clone(result.manifest.snapshot_id, clone)
            self.assertTrue((clone / "outside-link").is_symlink())
            self.assertEqual(os.readlink(clone / "outside-link"), str(outside))
            self.assertFalse((result.snapshot_dir / "rootfs" / "secret").exists())

    def test_special_file_is_rejected_without_partial_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            os.mkfifo(source / "pipe")
            store_dir = base / "store"
            with self.assertRaisesRegex(EnvironmentSnapshotError, "unsupported special entry"):
                EnvironmentSnapshotStore(store_dir).capture(source)
            if store_dir.exists():
                self.assertEqual(list(store_dir.iterdir()), [])

    def test_tampered_snapshot_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            (source / "file").write_text("before", encoding="utf-8")
            store = EnvironmentSnapshotStore(base / "store")
            result = store.capture(source)
            (result.snapshot_dir / "rootfs" / "file").write_text("after", encoding="utf-8")
            with self.assertRaisesRegex(EnvironmentSnapshotError, "digest does not match"):
                store.verify(result.manifest.snapshot_id)

    def test_existing_clone_destination_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source"
            source.mkdir()
            store = EnvironmentSnapshotStore(base / "store")
            result = store.capture(source)
            destination = base / "clone"
            destination.mkdir()
            with self.assertRaisesRegex(EnvironmentSnapshotError, "already exists"):
                store.clone(result.manifest.snapshot_id, destination)

    def test_symlink_rootfs_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            real = base / "real"
            real.mkdir()
            link = base / "rootfs-link"
            os.symlink(real, link)
            with self.assertRaisesRegex(EnvironmentSnapshotError, "must not be a symlink"):
                EnvironmentSnapshotStore(base / "store").capture(link)


if __name__ == "__main__":
    unittest.main()
