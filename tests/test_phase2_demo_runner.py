from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.run_phase2_static_demo import (
    DemoError,
    REQUIRED_FILE_PATH,
    REQUIRED_REMOTE_IP,
    REQUIRED_REMOTE_PORT,
    validate_bridge_contract,
)


class Phase2DemoRunnerTests(unittest.TestCase):
    def write_json(self, path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_bridge_contract_requires_file_and_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase2_input = root / "phase2_input.json"
            bridge_audit = root / "bridge_audit.json"
            self.write_json(
                phase2_input,
                {
                    "file_dependencies": [
                        {"path": REQUIRED_FILE_PATH, "write": False}
                    ],
                    "network_dependencies": [
                        {
                            "ip": REQUIRED_REMOTE_IP,
                            "port": REQUIRED_REMOTE_PORT,
                            "type": "tcp",
                        }
                    ],
                    "library_dependencies": [],
                },
            )
            self.write_json(
                bridge_audit,
                {
                    "raw_counts": {
                        "file_dependencies": 1,
                        "network_events": 2,
                    },
                    "normalized_counts": {
                        "file_dependencies": 1,
                        "network_dependencies": 1,
                    },
                },
            )

            result = validate_bridge_contract(
                phase2_input_path=phase2_input,
                bridge_audit_path=bridge_audit,
            )

            self.assertTrue(result["required_file_observed"])
            self.assertTrue(result["required_network_observed"])

    def test_bridge_contract_rejects_empty_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase2_input = root / "phase2_input.json"
            bridge_audit = root / "bridge_audit.json"
            self.write_json(
                phase2_input,
                {
                    "file_dependencies": [],
                    "network_dependencies": [],
                    "library_dependencies": [],
                },
            )
            self.write_json(
                bridge_audit,
                {
                    "raw_counts": {
                        "file_dependencies": 0,
                        "network_events": 0,
                    },
                    "normalized_counts": {
                        "file_dependencies": 0,
                        "network_dependencies": 0,
                    },
                },
            )

            with self.assertRaisesRegex(
                DemoError,
                "lost the required file dependency",
            ):
                validate_bridge_contract(
                    phase2_input_path=phase2_input,
                    bridge_audit_path=bridge_audit,
                )


if __name__ == "__main__":
    unittest.main()
