import tempfile
import unittest
from pathlib import Path

from taintforge_env.run_manifest import (
    build_run_manifest,
    create_run_id,
)


class RunManifestTests(unittest.TestCase):
    def test_manifest_contains_hashes_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            taint = root / "taint.json"
            binary = root / "sample.elf"
            sysroot = root / "sysroot"
            out = root / "out"

            taint.write_text("{}", encoding="utf-8")
            binary.write_bytes(b"ELF-test")
            sysroot.mkdir()

            run_id = create_run_id(binary)
            manifest = build_run_manifest(
                run_id=run_id,
                taint_path=taint,
                binary_path=binary,
                sysroot_path=sysroot,
                out_dir=out,
                network_mode="emulated",
                timeout_seconds=60,
                bind_ip="10.10.0.1",
                namespace="tf-iot-ns",
                catch_all_port=40000,
                udp_catch_all_port=40001,
                build_only=False,
                allow_missing_libraries=False,
                self_test_network=True,
                egress_policy_path=None,
                egress_policy_summary=None,
            )

            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["run_id"], run_id)
            self.assertEqual(
                manifest["network"]["mode"],
                "emulated",
            )
            self.assertEqual(
                len(manifest["inputs"]["binary"]["sha256"]),
                64,
            )


if __name__ == "__main__":
    unittest.main()
