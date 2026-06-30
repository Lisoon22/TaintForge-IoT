from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.runtime_observer import (
    RuntimeObservationSession,
    RuntimeObserverError,
)


class RuntimeObservationSessionTests(unittest.TestCase):
    def test_full_lifecycle_creates_diff_and_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            rootfs = run_dir / "rootfs"
            logs = run_dir / "logs"
            rootfs.mkdir(parents=True)
            logs.mkdir()
            (rootfs / "etc").mkdir()
            (rootfs / "etc" / "base.conf").write_text("base\n", encoding="utf-8")
            (rootfs / "var" / "run").mkdir(parents=True)

            session = RuntimeObservationSession(run_dir=run_dir, rootfs=rootfs)
            session.capture_before()

            created = rootfs / "var" / "run" / "malware.pid"
            created.parent.mkdir(parents=True, exist_ok=True)
            created.write_text("123\n", encoding="utf-8")
            (logs / "syscall_events.jsonl").write_text(
                json.dumps(
                    {
                        "event": "syscall",
                        "syscall": "openat",
                        "execution_context": "guest",
                        "path": "/etc/device.conf",
                        "paths": ["/etc/device.conf"],
                        "errno": "ENOENT",
                        "args": 'AT_FDCWD, "/etc/device.conf", O_RDONLY',
                        "raw": 'openat(AT_FDCWD, "/etc/device.conf", O_RDONLY) = -1 ENOENT',
                        "return_value": -1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (logs / "runtime_stdout.log").write_text("", encoding="utf-8")
            (logs / "runtime_stderr.log").write_text("", encoding="utf-8")

            result = session.finalize()
            self.assertEqual(result.created, 1)
            self.assertEqual(result.requirements, 2)
            self.assertTrue(session.paths.rootfs_diff.exists())
            self.assertTrue(session.paths.requirements.exists())

            requirements = json.loads(
                session.paths.requirements.read_text(encoding="utf-8")
            )["requirements"]
            keys = {
                (item["resource"], item["operation"], item["status"])
                for item in requirements
            }
            self.assertIn(
                ("/etc/device.conf", "path_exists", "unmet"),
                keys,
            )
            self.assertIn(
                ("/var/run/malware.pid", "path_writable", "provided"),
                keys,
            )

    def test_rootfs_outside_run_dir_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run_dir = base / "run"
            external = base / "external-rootfs"
            run_dir.mkdir()
            external.mkdir()
            with self.assertRaisesRegex(RuntimeObserverError, "outside"):
                RuntimeObservationSession(run_dir=run_dir, rootfs=external)

    def test_after_without_before_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            rootfs = run_dir / "rootfs"
            rootfs.mkdir(parents=True)
            session = RuntimeObservationSession(run_dir=run_dir, rootfs=rootfs)
            with self.assertRaisesRegex(RuntimeObserverError, "baseline"):
                session.capture_after()

    def test_lifecycle_state_reaches_completed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            rootfs = run_dir / "rootfs"
            logs = run_dir / "logs"
            rootfs.mkdir(parents=True)
            logs.mkdir()
            session = RuntimeObservationSession(run_dir=run_dir, rootfs=rootfs)
            session.capture_before()
            (logs / "syscall_events.jsonl").write_text("", encoding="utf-8")
            session.finalize()
            state = json.loads(
                session.paths.lifecycle_state.read_text(encoding="utf-8")
            )
            self.assertEqual(state["status"], "completed")


if __name__ == "__main__":
    unittest.main()
