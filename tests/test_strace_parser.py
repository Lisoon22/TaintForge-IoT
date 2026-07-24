from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.strace_parser import parse_result, parse_strace_logs


class StraceParserTests(unittest.TestCase):
    def test_parse_result_preserves_errno_and_success_value(self) -> None:
        self.assertEqual(parse_result("-1 ENOENT (No such file or directory)"), (-1, "ENOENT"))
        self.assertEqual(parse_result("3</tmp/testfile.txt>"), (3, None))
        self.assertEqual(parse_result("0x7f001000"), (0x7F001000, None))
        self.assertEqual(parse_result("?"), (None, None))

    def test_native_strace_events_include_errno_and_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log_dir = root / "logs"
            log_dir.mkdir()
            (log_dir / "strace.100").write_text(
                'chroot("/tmp/rootfs") = 0\n'
                'openat(AT_FDCWD, "/missing/config", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
                'connect(3, {sa_family=AF_INET, sin_port=htons(48101), sin_addr=inet_addr("198.51.100.10")}, 16) = -1 ECONNREFUSED (Connection refused)\n'
                'write(1</dev/stdout>, "ready\\n", 6) = 6\n'
                '+++ exited with 0 +++\n',
                encoding="utf-8",
            )
            out = log_dir / "syscall_events.jsonl"
            summary = parse_strace_logs(log_dir, out)
            events = [
                json.loads(line)
                for line in out.read_text(encoding="utf-8").splitlines()
            ]

        open_event = next(event for event in events if event["syscall"] == "openat")
        connect_event = next(event for event in events if event["syscall"] == "connect")
        write_event = next(event for event in events if event["syscall"] == "write")
        exit_event = next(event for event in events if event["event"] == "process_exit")

        self.assertEqual(open_event["execution_context"], "guest")
        self.assertEqual(open_event["return_value"], -1)
        self.assertEqual(open_event["errno"], "ENOENT")
        self.assertFalse(open_event["success"])
        self.assertEqual(connect_event["errno"], "ECONNREFUSED")
        self.assertFalse(connect_event["success"])
        self.assertEqual(write_event["return_value"], 6)
        self.assertTrue(write_event["success"])
        self.assertTrue(exit_event["success"])
        self.assertEqual(summary["by_context"]["guest"], 4)


if __name__ == "__main__":
    unittest.main()
