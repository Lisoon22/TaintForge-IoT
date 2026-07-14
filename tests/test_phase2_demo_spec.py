from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.target_state_oracle import TargetStateOracle, TargetStateSpec


class Phase2DemoSpecTests(unittest.TestCase):
    def test_demo_spec_matches_complete_evidence(self) -> None:
        project_root = Path(__file__).resolve().parent.parent
        spec = TargetStateSpec.load(
            project_root / "examples" / "targets" / "phase2_demo_i386.json"
        )
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            logs = run_dir / "logs"
            logs.mkdir(parents=True)
            (logs / "runtime_stdout.log").write_text(
                "TAINTFORGE_PHASE2_MILESTONE\n",
                encoding="utf-8",
            )
            syscall_events = [
                {
                    "event": "syscall",
                    "execution_context": "guest",
                    "syscall": "open",
                    "path": "/tmp/taintforge-phase2-demo.ready",
                    "success": True,
                },
                {
                    "event": "syscall",
                    "execution_context": "guest",
                    "syscall": "connect",
                    "remote_ip": "198.51.100.10",
                    "remote_port": 48101,
                    "success": True,
                },
            ]
            (logs / "syscall_events.jsonl").write_text(
                "".join(json.dumps(event) + "\n" for event in syscall_events),
                encoding="utf-8",
            )
            (logs / "network_events.jsonl").write_text(
                json.dumps(
                    {
                        "event": "tcp_connection_open",
                        "original_remote_ip": "198.51.100.10",
                        "original_remote_port": 48101,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            evaluation = TargetStateOracle().evaluate(run_dir, spec)

        self.assertTrue(evaluation.reached)
        self.assertEqual(evaluation.matched_rules, 4)


if __name__ == "__main__":
    unittest.main()
