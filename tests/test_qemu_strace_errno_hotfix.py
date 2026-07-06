from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.qemu_strace_parser import (
    _extract_qemu_errno,
    parse_qemu_strace,
)


class QemuStraceErrnoHotfixTests(unittest.TestCase):
    def test_symbolic_qemu_errno_is_extracted(self) -> None:
        self.assertEqual(
            _extract_qemu_errno(
                '100 openat(AT_FDCWD, "/etc/config", O_RDONLY) = -1 ENOENT (No such file or directory)'
            ),
            "ENOENT",
        )

    def test_numeric_qemu_errno_is_extracted(self) -> None:
        self.assertEqual(
            _extract_qemu_errno(
                '100 openat(AT_FDCWD, "/etc/config", O_RDONLY) = -1 errno=2 (No such file or directory)'
            ),
            "ENOENT",
        )

    def test_guest_syscalls_get_missing_errno_backfilled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "qemu_strace.log"
            source.write_text(
                '100 openat(AT_FDCWD, "/etc/config", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
                "100 write(1,0x40001000,3) = 3\n",
                encoding="utf-8",
            )
            out = root / "syscall_events.jsonl"
            parse_qemu_strace(source, out, target_arch="arm")
            events = [
                json.loads(line)
                for line in out.read_text(encoding="utf-8").splitlines()
            ]

        open_event = next(event for event in events if event["syscall"] == "openat")
        self.assertEqual(open_event["errno"], "ENOENT")
        self.assertEqual(open_event["trace_backend"], "qemu_strace")
        self.assertEqual(open_event["target_arch"], "arm")


if __name__ == "__main__":
    unittest.main()
