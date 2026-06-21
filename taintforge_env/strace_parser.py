from __future__ import annotations

import ast
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


SYSCALL_RE = re.compile(
    r"^\s*(?:(?P<pid>\d+)\s+)?"
    r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)"
    r"\((?P<args>.*)\)\s+=\s+(?P<result>.+?)\s*$"
)

CHROOT_SUCCESS_RE = re.compile(r'^chroot\(".*"\)\s+=\s+0')
GUEST_EXEC_RE = re.compile(
    r'^execve\("(?P<path>/bin/unpacked\.elf|/usr/bin/qemu-[^"]+)"'
)

EXIT_RE = re.compile(r"^\+\+\+ exited with (?P<exit_code>-?\d+) \+\+\+")

SIGNAL_RE = re.compile(r"^--- (?P<signal>[A-Z0-9_]+) ")

QUOTED_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')

INET_ADDR_RE = re.compile(r'inet_addr\("(?P<ip>[^"]+)"\)')
HTONS_PORT_RE = re.compile(r"htons\((?P<port>\d+)\)")

PATH_SYSCALLS = {
    "open",
    "openat",
    "creat",
    "stat",
    "lstat",
    "fstat",
    "newfstatat",
    "access",
    "faccessat",
    "readlink",
    "readlinkat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "chdir",
    "execve",
    "execveat",
}

NETWORK_SYSCALLS = {
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
}

PROCESS_SYSCALLS = {
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone",
    "clone3",
    "wait4",
}

MEMORY_SYSCALLS = {
    "mmap",
    "mmap2",
    "munmap",
    "mprotect",
    "brk",
}

ANTI_ANALYSIS_SYSCALLS = {
    "ptrace",
}

HIGH_RISK_SYSCALLS = {
    "ptrace",
    "mount",
    "umount",
    "umount2",
    "reboot",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "setuid",
    "setgid",
    "setreuid",
    "setregid",
    "setresuid",
    "setresgid",
}


@dataclass(slots=True)
class SyscallEvent:
    event: str
    syscall: str
    category: str
    execution_context: str
    source_file: str
    line_number: int

    raw: str
    args: str
    result: str

    pid: Optional[int] = None
    return_value: Optional[int] = None
    errno: Optional[str] = None

    path: Optional[str] = None
    paths: list[str] = field(default_factory=list)

    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None

    high_risk: bool = False


class StraceParserError(RuntimeError):
    pass


def parse_strace_logs(log_dir: str | Path, out_path: str | Path) -> dict:
    log_dir = Path(log_dir)
    out_path = Path(out_path)

    if not log_dir.exists():
        raise StraceParserError(f"log_dir does not exist: {log_dir}")

    strace_files = find_strace_files(log_dir)

    events: list[SyscallEvent] = []

    for path in strace_files:
        events.extend(parse_strace_file(path))

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")

    summary = build_summary(events)

    summary_path = out_path.with_suffix(".summary.json")
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return summary


def find_strace_files(log_dir: Path) -> list[Path]:
    candidates = []

    for path in log_dir.iterdir():
        if not path.is_file():
            continue

        name = path.name

        if name == "strace.log":
            candidates.append(path)
            continue

        if name.startswith("strace."):
            candidates.append(path)

    return sorted(candidates)

def is_successful_chroot_line(line: str) -> bool:
    return CHROOT_SUCCESS_RE.match(line) is not None


def is_guest_execve_line(line: str) -> bool:
    return GUEST_EXEC_RE.match(line) is not None

def parse_strace_file(path: Path) -> list[SyscallEvent]:
    events: list[SyscallEvent] = []

    execution_context = "host_wrapper"

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        line = line.strip()

        if not line:
            continue

        if "<unfinished ...>" in line or "resumed>" in line:
            continue

        if is_guest_execve_line(line):
            execution_context = "guest"

        parsed = parse_strace_line(
            line=line,
            source_file=path.name,
            line_number=line_number,
            execution_context=execution_context,
        )

        if parsed is not None:
            events.append(parsed)

        if is_successful_chroot_line(line):
            execution_context = "guest"

    return events

def parse_strace_line(
    line: str,
    source_file: str,
    line_number: int,
    execution_context: str
) -> Optional[SyscallEvent]:
    syscall_match = SYSCALL_RE.match(line)

    if syscall_match:
        return parse_syscall_match(
            match=syscall_match,
            line=line,
            source_file=source_file,
            line_number=line_number,
            execution_context=execution_context,
        )

    exit_match = EXIT_RE.match(line)
    if exit_match:
        return SyscallEvent(
            event="process_exit",
            syscall="exit",
            category="process",
            source_file=source_file,
            line_number=line_number,
            raw=line,
            args="",
            result=exit_match.group("exit_code"),
            return_value=int(exit_match.group("exit_code")),
            execution_context=execution_context,
        )

    signal_match = SIGNAL_RE.match(line)
    if signal_match:
        return SyscallEvent(
            event="signal",
            syscall="signal",
            category="process",
            source_file=source_file,
            line_number=line_number,
            raw=line,
            args="",
            result=signal_match.group("signal"),
            execution_context=execution_context
        )

    return None


def parse_syscall_match(
    match: re.Match,
    line: str,
    source_file: str,
    line_number: int,
    execution_context: str,
) -> SyscallEvent:
    pid_raw = match.group("pid")
    syscall = match.group("name")
    args = match.group("args")
    result = match.group("result")

    paths = extract_paths(syscall=syscall, args=args)
    remote_ip, remote_port = extract_network_target(args)

    return_value, errno = parse_result(result)

    category = classify_syscall(syscall)

    return SyscallEvent(
        event="syscall",
        syscall=syscall,
        category=category,
        source_file=source_file,
        line_number=line_number,
        raw=line,
        args=args,
        result=result,
        pid=int(pid_raw) if pid_raw else None,
        return_value=return_value,
        errno=errno,
        path=paths[0] if paths else None,
        paths=paths,
        remote_ip=remote_ip,
        remote_port=remote_port,
        high_risk=syscall in HIGH_RISK_SYSCALLS,
        execution_context=execution_context,
    )


def parse_result(result: str) -> tuple[Optional[int], Optional[str]]:
    result = result.strip()

    if result.startswith("?"):
        return None, None

    first = result.split(maxsplit=1)[0]

    try:
        return int(first), None
    except ValueError:
        pass

    errno = None

    parts = result.split()
    if len(parts) >= 2 and parts[0] == "-1":
        errno = parts[1]

    return None, errno


def extract_paths(syscall: str, args: str) -> list[str]:
    if syscall not in PATH_SYSCALLS:
        return []

    quoted = extract_quoted_strings(args)

    if not quoted:
        return []

    # execve("/path/to/bin", ["argv0", "arg1"], ...)
    # Only the first quoted string is the executable path.
    # Other quoted values are argv/env strings, not filesystem accesses.
    if syscall in {"execve", "execveat"}:
        return [quoted[0]]

    # openat/newfstatat/etc usually look like:
    # openat(AT_FDCWD, "/path", ...)
    # First quoted string is normally the path.
    if syscall in {
        "openat",
        "newfstatat",
        "faccessat",
        "unlinkat",
        "mkdirat",
        "readlinkat",
    }:
        return [quoted[0]]

    # renameat may contain old and new path.
    if syscall in {"rename", "renameat"}:
        return quoted[:2]

    return [quoted[0]]

def extract_quoted_strings(args: str) -> list[str]:
    values: list[str] = []

    for match in QUOTED_STRING_RE.finditer(args):
        raw = match.group(0)

        try:
            value = ast.literal_eval(raw)
        except Exception:
            value = raw.strip('"')

        if isinstance(value, str):
            values.append(value)

    return values


def extract_network_target(args: str) -> tuple[Optional[str], Optional[int]]:
    ip_match = INET_ADDR_RE.search(args)
    port_match = HTONS_PORT_RE.search(args)

    ip = ip_match.group("ip") if ip_match else None
    port = int(port_match.group("port")) if port_match else None

    return ip, port


def classify_syscall(syscall: str) -> str:
    if syscall in ANTI_ANALYSIS_SYSCALLS:
        return "anti_analysis"

    if syscall in PATH_SYSCALLS:
        return "filesystem"

    if syscall in NETWORK_SYSCALLS:
        return "network"

    if syscall in PROCESS_SYSCALLS:
        return "process"

    if syscall in MEMORY_SYSCALLS:
        return "memory"

    return "other"

def build_summary(events: list[SyscallEvent]) -> dict:
    by_syscall = Counter(event.syscall for event in events)
    by_category = Counter(event.category for event in events)
    by_context = Counter(event.execution_context for event in events)

    all_paths = sorted(
        {
            path
            for event in events
            for path in event.paths
            if path
        }
    )

    guest_paths = sorted(
        {
            path
            for event in events
            if event.execution_context == "guest"
            for path in event.paths
            if path
        }
    )

    host_wrapper_paths = sorted(
        {
            path
            for event in events
            if event.execution_context == "host_wrapper"
            for path in event.paths
            if path
        }
    )

    network_targets = sorted(
        {
            f"{event.remote_ip}:{event.remote_port}"
            for event in events
            if event.remote_ip is not None and event.remote_port is not None
        }
    )

    high_risk = [
        asdict(event)
        for event in events
        if event.high_risk
    ]

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "events_total": len(events),
        "by_syscall": dict(sorted(by_syscall.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_context": dict(sorted(by_context.items())),
        "paths": guest_paths,
        "guest_paths": guest_paths,
        "host_wrapper_paths": host_wrapper_paths,
        "all_paths": all_paths,
        "network_targets": network_targets,
        "high_risk_count": len(high_risk),
        "high_risk_events": high_risk[:50],
    }
