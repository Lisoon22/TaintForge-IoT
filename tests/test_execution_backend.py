from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from taintforge_env.execution_backend import (
    ExecutionBackendError,
    ExecutionBackendKind,
    ExecutionBackendResolver,
    TraceBackend,
)
from tests.elf_fixture import write_elf


class ExecutionBackendTests(unittest.TestCase):
    def make_rootfs(self, root: Path, binary: Path) -> Path:
        rootfs = root / "rootfs"
        (rootfs / "bin").mkdir(parents=True)
        (rootfs / "proc").mkdir()
        (rootfs / "bin" / "unpacked.elf").write_bytes(binary.read_bytes())
        (rootfs / "bin" / "unpacked.elf").chmod(0o755)
        return rootfs

    def test_native_x86_64_uses_host_strace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(root / "sample", arch="x86_64")
            rootfs = self.make_rootfs(root, binary)
            plan = ExecutionBackendResolver(host_arch="x86_64").resolve(
                runtime={"arch": "x86_64", "qemu_required": False},
                host_binary=binary,
                rootfs=rootfs,
                guest_binary="/bin/unpacked.elf",
            )
        self.assertEqual(plan.backend, ExecutionBackendKind.NATIVE)
        self.assertEqual(plan.trace_backend, TraceBackend.HOST_STRACE)
        self.assertIsNone(plan.qemu_host_path)

    def test_arm_uses_static_qemu_and_reserved_guest_mount(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(root / "sample-arm", arch="arm")
            qemu = write_elf(root / "qemu-arm-static", arch="x86_64")
            rootfs = self.make_rootfs(root, binary)
            plan = ExecutionBackendResolver(
                host_arch="x86_64",
                which=lambda name: str(qemu) if name == "qemu-arm-static" else None,
            ).resolve(
                runtime={"arch": "arm", "qemu_required": True},
                host_binary=binary,
                rootfs=rootfs,
                guest_binary="/bin/unpacked.elf",
            )
        self.assertEqual(plan.backend, ExecutionBackendKind.QEMU_USER)
        self.assertEqual(plan.trace_backend, TraceBackend.QEMU_STRACE)
        self.assertEqual(plan.qemu_guest_path, "/__taintforge/qemu-user-static")
        self.assertEqual(plan.qemu_host_path, str(qemu.resolve()))
        self.assertIsNotNone(plan.qemu_host_sha256)

    def test_foreign_target_cannot_claim_native_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(root / "sample-arm", arch="arm")
            rootfs = self.make_rootfs(root, binary)
            with self.assertRaisesRegex(
                ExecutionBackendError,
                "foreign ELF target",
            ):
                ExecutionBackendResolver(host_arch="x86_64").resolve(
                    runtime={"arch": "arm", "qemu_required": False},
                    host_binary=binary,
                    rootfs=rootfs,
                    guest_binary="/bin/unpacked.elf",
                )

    def test_runtime_arch_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(root / "sample", arch="mipsel")
            rootfs = self.make_rootfs(root, binary)
            with self.assertRaisesRegex(ExecutionBackendError, "does not match"):
                ExecutionBackendResolver(host_arch="x86_64").resolve(
                    runtime={"arch": "mips", "qemu_required": True},
                    host_binary=binary,
                    rootfs=rootfs,
                    guest_binary="/bin/unpacked.elf",
                )

    def test_missing_dynamic_interpreter_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(
                root / "sample-arm",
                arch="arm",
                interpreter="/lib/ld-uClibc.so.0",
            )
            qemu = write_elf(root / "qemu-arm-static", arch="x86_64")
            rootfs = self.make_rootfs(root, binary)
            with self.assertRaisesRegex(
                ExecutionBackendError,
                "dynamic interpreter is missing",
            ):
                ExecutionBackendResolver(
                    host_arch="x86_64",
                    which=lambda _name: str(qemu),
                ).resolve(
                    runtime={"arch": "arm", "qemu_required": True},
                    host_binary=binary,
                    rootfs=rootfs,
                    guest_binary="/bin/unpacked.elf",
                )

    def test_dynamic_qemu_binary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(root / "sample-arm", arch="arm")
            qemu = write_elf(
                root / "qemu-arm-static",
                arch="x86_64",
                interpreter="/lib64/ld-linux-x86-64.so.2",
            )
            rootfs = self.make_rootfs(root, binary)
            with self.assertRaisesRegex(ExecutionBackendError, "dynamically linked"):
                ExecutionBackendResolver(
                    host_arch="x86_64",
                    which=lambda _name: str(qemu),
                ).resolve(
                    runtime={"arch": "arm", "qemu_required": True},
                    host_binary=binary,
                    rootfs=rootfs,
                    guest_binary="/bin/unpacked.elf",
                )

    def test_reserved_internal_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = write_elf(root / "sample-arm", arch="arm")
            qemu = write_elf(root / "qemu-arm-static", arch="x86_64")
            rootfs = self.make_rootfs(root, binary)
            (rootfs / "__taintforge").mkdir()
            with self.assertRaisesRegex(ExecutionBackendError, "reserved"):
                ExecutionBackendResolver(
                    host_arch="x86_64",
                    which=lambda _name: str(qemu),
                ).resolve(
                    runtime={"arch": "arm", "qemu_required": True},
                    host_binary=binary,
                    rootfs=rootfs,
                    guest_binary="/bin/unpacked.elf",
                )


if __name__ == "__main__":
    unittest.main()
