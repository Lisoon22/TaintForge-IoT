from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from taintforge_env.runtime_preparer import RuntimePreparer
from tests.elf_fixture import write_elf


class RuntimePreparerQemuTests(unittest.TestCase):
    def test_qemu_is_bound_at_runtime_not_copied_into_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            (out / "rootfs").mkdir(parents=True)
            binary = write_elf(root / "arm-sample", arch="arm")
            qemu = write_elf(root / "qemu-arm-static", arch="x86_64")

            preparer = RuntimePreparer(out, "arm", binary)
            with patch.object(
                preparer,
                "_find_executable",
                return_value=qemu,
            ):
                config = preparer.prepare()

            runtime = json.loads(
                (out / "config" / "runtime.json").read_text(
                    encoding="utf-8"
                )
            )
            qemu_copied = (
                out / "rootfs" / "usr" / "bin" / qemu.name
            ).exists()
            guest_copied = (
                out / "rootfs" / "bin" / "unpacked.elf"
            ).is_file()

        self.assertTrue(config.qemu_required)
        self.assertEqual(config.execution_backend, "qemu_user")
        self.assertEqual(config.qemu_injection, "runtime_bind_mount")
        self.assertEqual(
            config.qemu_guest_path,
            "/__taintforge/qemu-user-static",
        )
        self.assertEqual(runtime["runtime_schema_version"], 2)
        self.assertFalse(qemu_copied)
        self.assertTrue(guest_copied)

    def test_native_runtime_does_not_require_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out"
            (out / "rootfs").mkdir(parents=True)
            binary = write_elf(root / "native", arch="x86_64")
            config = RuntimePreparer(out, "x86_64", binary).prepare()

        self.assertFalse(config.qemu_required)
        self.assertEqual(config.execution_backend, "native")
        self.assertIsNone(config.qemu_injection)


if __name__ == "__main__":
    unittest.main()
