from __future__ import annotations

import errno as errno_module
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .strace_parser import (
    StraceParserError,
    build_summary,
    parse_strace_line,
)


class QemuStraceParserError(RuntimeError):
    """Raised when QEMU user-mode syscall output cannot be normalized."""


def parse_qemu_strace(
    input_path: str | Path,
    out_path: str | Path,
    *,
    target_arch: str,
) -> dict[str, Any]:
    source = Path(input_path)
    destination = Path(out_path)
    if source.is_symlink() or not source.is_file():
        raise QemuStraceParserError(
            f"QEMU strace input does not exist: {source}"
        )

    events = []
    for line_number, raw_line in enumerate(
        source.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line:
            continue
        if "<unfinished ...>" in line or "<... " in line and " resumed>" in line:
            continue
        try:
            event = parse_strace_line(
                line=line,
                source_file=source.name,
                line_number=line_number,
                execution_context="guest",
            )
        except StraceParserError as exc:
            raise QemuStraceParserError(str(exc)) from exc
        if event is not None:
            events.append((event, line))

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise QemuStraceParserError(
            f"QEMU syscall output must not be a symlink: {destination}"
        )
    with destination.open("w", encoding="utf-8") as stream:
        for event, raw_line in events:
            payload = asdict(event)
            if not payload.get("errno"):
                qemu_errno = _extract_qemu_errno(raw_line)
                if qemu_errno:
                    payload["errno"] = qemu_errno
            payload["trace_backend"] = "qemu_strace"
            payload["target_arch"] = target_arch
            stream.write(json.dumps(payload, ensure_ascii=False) + "\n")

    summary = build_summary([event for event, _raw_line in events])
    summary.update(
        {
            "trace_backend": "qemu_strace",
            "target_arch": target_arch,
            "source_file": source.name,
        }
    )
    summary_path = destination.with_suffix(".summary.json")
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


_QEMU_ERRNO_SYMBOL_RE = re.compile(
    r"=\s*-1\s+([A-Z][A-Z0-9_]+)(?:\s|$|\()"
)
_QEMU_ERRNO_NUMBER_RE = re.compile(
    r"=\s*-1\s+errno=(\d+)(?:\s|$|\()",
    re.IGNORECASE,
)


def _extract_qemu_errno(line: str) -> str | None:
    """Extract errno from QEMU user-mode -strace return syntax.

    QEMU user-mode commonly emits failures as either:

        openat(...) = -1 ENOENT (No such file or directory)

    or, on some builds:

        openat(...) = -1 errno=2 (No such file or directory)

    The repository's native strace parser handles normal host strace syntax, but
    older versions can parse the syscall while leaving errno empty for QEMU's
    symbolic form. This helper only fills that missing field; it does not turn
    arbitrary diagnostic lines into syscall events.
    """

    symbolic = _QEMU_ERRNO_SYMBOL_RE.search(line)
    if symbolic:
        return symbolic.group(1)

    numeric = _QEMU_ERRNO_NUMBER_RE.search(line)
    if numeric:
        code = int(numeric.group(1))
        return errno_module.errorcode.get(code, f"ERRNO_{code}")

    return None
