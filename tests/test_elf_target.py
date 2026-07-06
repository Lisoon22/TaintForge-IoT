from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintforge_env.elf_target import (
    ElfTargetError,
    guest_path_exists,
    inspect_elf_target,
)
from tests.elf_fixture import write_elf


class ElfTargetTests(unittest.TestCase):
    def test_x86_64_static_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_elf(Path(tmp) / "sample", arch="x86_64")
            target = inspect_elf_target(path)
        self.assertEqual(target.arch, "x86_64")
        self.assertEqual(target.elf_class, 64)
        self.assertEqual(target.endianness, "little")
        self.assertTrue(target.static)
        self.assertIsNone(target.interpreter)

    def test_mips_endianness_selects_arch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            be = inspect_elf_target(write_elf(root / "be", arch="mips"))
            le = inspect_elf_target(write_elf(root / "le", arch="mipsel"))
        self.assertEqual(be.arch, "mips")
        self.assertEqual(be.endianness, "big")
        self.assertEqual(le.arch, "mipsel")
        self.assertEqual(le.endianness, "little")

    def test_dynamic_interpreter_is_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_elf(
                Path(tmp) / "arm",
                arch="arm",
                interpreter="/lib/ld-uClibc.so.0",
            )
            target = inspect_elf_target(path)
        self.assertFalse(target.static)
        self.assertEqual(target.interpreter, "/lib/ld-uClibc.so.0")

    def test_non_elf_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad"
            path.write_bytes(b"not-elf")
            with self.assertRaisesRegex(ElfTargetError, "too small|not an ELF"):
                inspect_elf_target(path)

    def test_guest_absolute_symlink_resolves_inside_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rootfs"
            (root / "lib").mkdir(parents=True)
            (root / "lib64").mkdir()
            (root / "lib64" / "loader.so").write_bytes(b"loader")
            (root / "lib" / "ld.so").symlink_to("/lib64/loader.so")
            self.assertTrue(guest_path_exists(root, "/lib/ld.so"))
            self.assertFalse(guest_path_exists(root, "/etc/host-only"))


if __name__ == "__main__":
    unittest.main()
