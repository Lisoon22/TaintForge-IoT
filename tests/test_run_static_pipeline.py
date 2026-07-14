from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.run_static_pipeline import (
    PHASE1_PLUGIN_SOURCE_NAMES,
    build_phase2_input,
)


class StaticPipelineTests(unittest.TestCase):
    def test_plugin_build_includes_dse_implementation(self) -> None:
        self.assertIn("dse.c", PHASE1_PLUGIN_SOURCE_NAMES)
        self.assertIn("dse_lift_x86.c", PHASE1_PLUGIN_SOURCE_NAMES)

    def test_bridge_preserves_non_loopback_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample"
            sample.write_bytes(b"unused")
            raw = {
                "oep": "0x8049000",
                "base": "0x8048000",
                "regions": [],
                "file_dependencies": [
                    {
                        "path": "/tmp/taintforge-phase2-demo.ready",
                        "write": False,
                    }
                ],
                "network_dependencies": [
                    {
                        "op": "connect",
                        "ip": "198.51.100.10",
                        "port": 48101,
                        "type": "tcp",
                    }
                ],
            }
            from scripts.run_static_pipeline import ElfInfo

            payload, audit = build_phase2_input(
                raw_phase1=raw,
                elf=ElfInfo(
                    elf_class="ELF32",
                    endianness="little",
                    machine="Intel 80386",
                    entry_point="0x8049000",
                    statically_linked=True,
                ),
            )

        self.assertEqual(len(payload["file_dependencies"]), 1)
        self.assertEqual(len(payload["network_dependencies"]), 1)
        self.assertEqual(
            payload["network_dependencies"][0]["ip"],
            "198.51.100.10",
        )
        self.assertEqual(audit["unsupported_loopback_endpoints"], [])


if __name__ == "__main__":
    unittest.main()
