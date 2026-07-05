from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from taintforge_env.controlled_network_backend import (
    SubprocessProcessSupervisor,
)


class ControlledNetworkSudoHotfixTests(unittest.TestCase):
    @patch("taintforge_env.controlled_network_backend.subprocess.Popen")
    def test_background_supervisor_uses_process_group_not_new_session(
        self,
        popen: MagicMock,
    ) -> None:
        process = MagicMock()
        process.pid = 12345
        popen.return_value = process

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supervisor = SubprocessProcessSupervisor()
            background = supervisor.start(
                ["sudo", "-n", "true"],
                cwd=root,
                stdout_path=root / "stdout.log",
                stderr_path=root / "stderr.log",
            )

            kwargs = popen.call_args.kwargs
            self.assertEqual(kwargs["process_group"], 0)
            self.assertNotIn("start_new_session", kwargs)
            self.assertEqual(background.command, ["sudo", "-n", "true"])
            background.stdout_handle.close()
            background.stderr_handle.close()


if __name__ == "__main__":
    unittest.main()
