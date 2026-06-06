from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    AntiAnalysisEvent,
    FileDependency,
    LibraryDependency,
    NetworkDependency,
    SampleInfo,
    SyscallEvent,
    TaintLog,
)
from .validators import (
    TaintLogValidationError,
    require_dict,
    require_list,
    require_string,
    validate_arch,
    validate_file_path,
    validate_network_type,
    validate_port,
)


def load_taint_log(path: str | Path) -> TaintLog:
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Taint log not found: {path}")

    if not path.is_file():
        raise TaintLogValidationError(f"Taint log is not a file: {path}")

    with path.open("r", encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError as e:
            raise TaintLogValidationError(
                f"Invalid JSON in taint log {path}: {e}"
            ) from e

    return parse_taint_log(raw)


def parse_taint_log(raw: dict[str, Any]) -> TaintLog:
    raw = require_dict(raw, "taint_log")

    schema_version = str(raw.get("schema_version", "0.1"))

    sample = parse_sample(raw.get("sample"))

    file_dependencies = [
        parse_file_dependency(item, index=i)
        for i, item in enumerate(require_list(
            raw.get("file_dependencies"),
            "file_dependencies",
        ))
    ]

    network_dependencies = [
        parse_network_dependency(item, index=i)
        for i, item in enumerate(require_list(
            raw.get("network_dependencies"),
            "network_dependencies",
        ))
    ]

    library_dependencies = [
        parse_library_dependency(item, index=i)
        for i, item in enumerate(require_list(
            raw.get("library_dependencies"),
            "library_dependencies",
        ))
    ]

    syscalls = [
        parse_syscall_event(item, index=i)
        for i, item in enumerate(require_list(
            raw.get("syscalls"),
            "syscalls",
        ))
    ]

    anti_analysis = [
        parse_anti_analysis_event(item, index=i)
        for i, item in enumerate(require_list(
            raw.get("anti_analysis"),
            "anti_analysis",
        ))
    ]

    return TaintLog(
        schema_version=schema_version,
        sample=sample,
        file_dependencies=file_dependencies,
        network_dependencies=network_dependencies,
        library_dependencies=library_dependencies,
        syscalls=syscalls,
        anti_analysis=anti_analysis,
    )


def parse_sample(raw: Any) -> SampleInfo:
    raw = require_dict(raw, "sample")

    name = require_string(raw.get("name"), "sample.name")
    arch = validate_arch(raw.get("arch"))

    endianness = raw.get("endianness")
    if endianness is not None:
        endianness = require_string(endianness, "sample.endianness").lower()

    binary = raw.get("binary")
    if binary is not None:
        binary = require_string(binary, "sample.binary")

    oep = raw.get("oep")
    if oep is not None:
        oep = require_string(oep, "sample.oep")

    return SampleInfo(
        name=name,
        arch=arch,
        endianness=endianness,
        binary=binary,
        oep=oep,
    )


def parse_file_dependency(raw: Any, index: int) -> FileDependency:
    context = f"file_dependencies[{index}]"
    raw = require_dict(raw, context)

    path = validate_file_path(raw.get("path"))

    syscall = raw.get("syscall")
    if syscall is not None:
        syscall = require_string(syscall, f"{context}.syscall")

    flags = raw.get("flags")
    if flags is not None:
        flags = require_string(flags, f"{context}.flags")

    ret = raw.get("ret")
    if ret is not None and not isinstance(ret, int):
        raise TaintLogValidationError(f"{context}.ret must be int or null")

    content_hint = raw.get("content_hint")
    if content_hint is not None:
        content_hint = require_string(content_hint, f"{context}.content_hint")

    return FileDependency(
        path=path,
        syscall=syscall,
        flags=flags,
        ret=ret,
        content_hint=content_hint,
    )


def parse_network_dependency(raw: Any, index: int) -> NetworkDependency:
    context = f"network_dependencies[{index}]"
    raw = require_dict(raw, context)

    net_type = validate_network_type(raw.get("type"))

    role = raw.get("role")
    if role is not None:
        role = require_string(role, f"{context}.role")

    remote_ip = raw.get("remote_ip")
    if remote_ip is not None:
        remote_ip = require_string(remote_ip, f"{context}.remote_ip")

    remote_port = raw.get("remote_port")
    if remote_port is not None:
        remote_port = validate_port(remote_port, f"{context}.remote_port")

    ip = raw.get("ip")
    if ip is not None:
        ip = require_string(ip, f"{context}.ip")

    port = raw.get("port")
    if port is not None:
        port = validate_port(port, f"{context}.port")

    domain = raw.get("domain")
    if domain is not None:
        domain = require_string(domain, f"{context}.domain")

    response_ip = raw.get("response_ip")
    if response_ip is not None:
        response_ip = require_string(response_ip, f"{context}.response_ip")

    protocol_hint = raw.get("protocol_hint")
    if protocol_hint is not None:
        protocol_hint = require_string(protocol_hint, f"{context}.protocol_hint")

    effective_port = remote_port or port

    if net_type in {"tcp", "udp", "ntp"} and effective_port is None:
        raise TaintLogValidationError(
            f"{context}: remote_port or port is required for {net_type}"
        )

    if net_type == "dns" and domain is None:
        raise TaintLogValidationError(
            f"{context}.domain is required for dns"
        )

    return NetworkDependency(
        type=net_type,
        role=role,
        remote_ip=remote_ip,
        remote_port=remote_port,
        ip=ip,
        port=port,
        domain=domain,
        response_ip=response_ip,
        protocol_hint=protocol_hint,
    )

def parse_library_dependency(raw: Any, index: int) -> LibraryDependency:
    context = f"library_dependencies[{index}]"
    raw = require_dict(raw, context)

    name = require_string(raw.get("name"), f"{context}.name")

    path = raw.get("path")
    if path is not None:
        path = require_string(path, f"{context}.path")

    symbols_raw = raw.get("symbols", [])
    symbols_list = require_list(symbols_raw, f"{context}.symbols")

    symbols: list[str] = []
    for symbol_index, symbol in enumerate(symbols_list):
        symbols.append(
            require_string(
                symbol,
                f"{context}.symbols[{symbol_index}]",
            )
        )

    return LibraryDependency(
        name=name,
        path=path,
        symbols=symbols,
    )


def parse_syscall_event(raw: Any, index: int) -> SyscallEvent:
    context = f"syscalls[{index}]"
    raw = require_dict(raw, context)

    name = require_string(raw.get("name"), f"{context}.name")

    args = raw.get("args", [])
    args = require_list(args, f"{context}.args")

    ret = raw.get("ret")

    timestamp = raw.get("timestamp")
    if timestamp is not None and not isinstance(timestamp, int | float):
        raise TaintLogValidationError(f"{context}.timestamp must be number or null")

    pc = raw.get("pc")
    if pc is not None:
        pc = require_string(pc, f"{context}.pc")

    return SyscallEvent(
        name=name,
        args=args,
        ret=ret,
        timestamp=timestamp,
        pc=pc,
    )


def parse_anti_analysis_event(raw: Any, index: int) -> AntiAnalysisEvent:
    context = f"anti_analysis[{index}]"
    raw = require_dict(raw, context)

    event_type = require_string(raw.get("type"), f"{context}.type")

    detail = raw.get("detail")
    if detail is not None:
        detail = require_string(detail, f"{context}.detail")

    return AntiAnalysisEvent(
        type=event_type,
        detail=detail,
    )
