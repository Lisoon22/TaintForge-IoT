from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
import unittest

from taintforge_env.controlled_network_backend import _self_test_code


class ControlledNetworkSelfTestRetryTests(unittest.TestCase):
    def test_tcp_probe_retries_until_listener_is_ready(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        host, port = listener.getsockname()
        completed = threading.Event()

        def delayed_server() -> None:
            time.sleep(0.35)
            listener.listen(1)
            conn, _peer = listener.accept()
            data = conn.recv(4096)
            if data:
                conn.sendall(b"OK\n")
            conn.close()
            listener.close()
            completed.set()

        threading.Thread(target=delayed_server, daemon=True).start()
        code = _self_test_code(
            [{"kind": "tcp", "label": "delayed", "host": host, "port": port, "required": True}],
            retry_timeout_seconds=2.0,
            retry_interval_seconds=0.05,
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        probe = json.loads(result.stdout)["results"][0]
        self.assertTrue(probe["ok"])
        self.assertGreaterEqual(probe["attempts"], 1)
        self.assertTrue(completed.wait(1.0))


if __name__ == "__main__":
    unittest.main()
