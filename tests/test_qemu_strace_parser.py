from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.qemu_strace_parser import parse_qemu_strace


class QemuStraceParserTests(unittest.TestCase):
    def test_guest_syscalls_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "qemu_strace.log"
            source.write_text(
                "100 openat(AT_FDCWD, \"/etc/config\", O_RDONLY) = -1 ENOENT (No such file or directory)\n"
                "guest diagnostic line\n"
                "100 write(1,0x40001000,3) = 3\n"
                "100 +++ exited with 0 +++\n",
                encoding="utf-8",
            )
            out = root / "syscall_events.jsonl"
            summary = parse_qemu_strace(
                source,
                out,
                target_arch="arm",
            )
            events = [
                json.loads(line)
                for line in out.read_text(encoding="utf-8").splitlines()
            ]
        self.assertEqual(summary["trace_backend"], "qemu_strace")
        self.assertEqual(summary["target_arch"], "arm")
        self.assertGreaterEqual(len(events), 2)
        self.assertTrue(all(event["execution_context"] == "guest" for event in events))
        self.assertTrue(all(event["trace_backend"] == "qemu_strace" for event in events))
        open_event = next(event for event in events if event["syscall"] == "openat")
        self.assertEqual(open_event["path"], "/etc/config")
        self.assertEqual(open_event["errno"], "ENOENT")


if __name__ == "__main__":
    unittest.main()
