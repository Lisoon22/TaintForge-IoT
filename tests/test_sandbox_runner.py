from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.sandbox_runner import (
    SandboxRunnerError,
    build_sandbox_run_config,
    generate_run_sandbox_script,
)


class SandboxRunnerTests(unittest.TestCase):
    def test_disconnected_runner_uses_private_network_and_writes_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime.json"
            runtime.write_text(
                json.dumps(
                    {
                        "rootfs": str(root / "rootfs"),
                        "guest_binary_path": "/bin/unpacked.elf",
                        "qemu_required": False,
                        "qemu_guest_path": None,
                    }
                ),
                encoding="utf-8",
            )
            config = build_sandbox_run_config(runtime, timeout_seconds=17)
            script = root / "run_disconnected_sandbox.sh"
            generate_run_sandbox_script(config, script)
            text = script.read_text(encoding="utf-8")

        self.assertIn("--net", text)
        self.assertIn("mount --make-rprivate /", text)
        self.assertIn("ip link set lo up", text)
        self.assertIn('"network_connected": false', text)
        self.assertIn('"network_namespace": true', text)
        self.assertIn("runtime_status.json", text)
        self.assertIn("security_status.json", text)
        self.assertIn("TIMEOUT_SECONDS=17", text)

    def test_foreign_qemu_target_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime.json"
            runtime.write_text(
                json.dumps(
                    {
                        "rootfs": str(Path(tmp) / "rootfs"),
                        "guest_binary_path": "/bin/unpacked.elf",
                        "qemu_required": True,
                        "qemu_guest_path": "/__taintforge/qemu-user-static",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SandboxRunnerError,
                "cannot inject QEMU safely",
            ):
                build_sandbox_run_config(runtime)


if __name__ == "__main__":
    unittest.main()
