from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    AntiAnalysis,
    FileDependency,
    LibraryDependency,
    MemoryRegion,
    NetworkDependency,
    TaintLog,
)
from .validators import (
    TaintLogValidationError,
    require_bool,
    require_dict,
    require_int,
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

    oep = require_string(raw.get("oep"), "oep")
    arch = validate_arch(raw.get("arch"))
    base = require_string(raw.get("base"), "base")

    regions = [
        parse_memory_region(item, index=i)
        for i, item in enumerate(require_list(raw.get("regions"), "regions"))
    ]

    file_dependencies = [
        parse_file_dependency(item, index=i)
        for i, item in enumerate(
            require_list(raw.get("file_dependencies"), "file_dependencies")
        )
    ]

    network_dependencies = [
        parse_network_dependency(item, index=i)
        for i, item in enumerate(
            require_list(raw.get("network_dependencies"), "network_dependencies")
        )
    ]

    library_dependencies = [
        parse_library_dependency(item, index=i)
        for i, item in enumerate(
            require_list(raw.get("library_dependencies"), "library_dependencies")
        )
    ]

    anti_analysis = parse_anti_analysis(raw.get("anti_analysis", {}))

    return TaintLog(
        oep=oep,
        arch=arch,
        base=base,
        regions=regions,
        file_dependencies=file_dependencies,
        network_dependencies=network_dependencies,
        library_dependencies=library_dependencies,
        anti_analysis=anti_analysis,
    )


def parse_memory_region(raw: Any, index: int) -> MemoryRegion:
    context = f"regions[{index}]"
    raw = require_dict(raw, context)

    addr = require_string(raw.get("addr"), f"{context}.addr")
    size = require_int(raw.get("size"), f"{context}.size")
    prot = require_int(raw.get("prot"), f"{context}.prot")
    offset = require_int(raw.get("offset"), f"{context}.offset")

    if size <= 0:
        raise TaintLogValidationError(f"{context}.size must be > 0")

    if offset < 0:
        raise TaintLogValidationError(f"{context}.offset must be >= 0")

    return MemoryRegion(
        addr=addr,
        size=size,
        prot=prot,
        offset=offset,
    )


def parse_file_dependency(raw: Any, index: int) -> FileDependency:
    context = f"file_dependencies[{index}]"
    raw = require_dict(raw, context)

    path = validate_file_path(raw.get("path"))

    write = raw.get("write", False)
    write = require_bool(write, f"{context}.write")

    return FileDependency(
        path=path,
        write=write,
    )


def parse_network_dependency(raw: Any, index: int) -> NetworkDependency:
    context = f"network_dependencies[{index}]"
    raw = require_dict(raw, context)

    ip = require_string(raw.get("ip"), f"{context}.ip")
    port = validate_port(raw.get("port"), f"{context}.port")
    net_type = validate_network_type(raw.get("type"))

    sample_bytes = raw.get("sample_bytes")
    if sample_bytes is not None:
        sample_bytes = require_string(sample_bytes, f"{context}.sample_bytes")

    return NetworkDependency(
        ip=ip,
        port=port,
        type=net_type,
        sample_bytes=sample_bytes,
    )


def parse_library_dependency(raw: Any, index: int) -> LibraryDependency:
    context = f"library_dependencies[{index}]"

    # New schema: "library_dependencies": ["libc.so.6", "libpthread.so.0"]
    if isinstance(raw, str):
        return LibraryDependency(name=require_string(raw, context))

    # Optional compatibility: allow old object format too.
    raw = require_dict(raw, context)

    name = require_string(raw.get("name"), f"{context}.name")

    path = raw.get("path")
    if path is not None:
        path = require_string(path, f"{context}.path")

    return LibraryDependency(
        name=name,
        path=path,
    )


def parse_anti_analysis(raw: Any) -> AntiAnalysis:
    raw = require_dict(raw, "anti_analysis")

    cpuinfo_check = raw.get("cpuinfo_check", False)
    uname_check = raw.get("uname_check", False)
    ptrace_traceme = raw.get("ptrace_traceme", False)

    return AntiAnalysis(
        cpuinfo_check=require_bool(cpuinfo_check, "anti_analysis.cpuinfo_check"),
        uname_check=require_bool(uname_check, "anti_analysis.uname_check"),
        ptrace_traceme=require_bool(ptrace_traceme, "anti_analysis.ptrace_traceme"),
    )
