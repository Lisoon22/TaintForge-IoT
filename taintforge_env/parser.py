from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any

from .models import (
    AntiAnalysis,
    FileDependency,
    LibraryDependency,
    MemoryRegion,
    NetworkDependency,
    NetworkEvent,
    TaintLog,
    RuntimeMapping,
    RuntimeModule
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
    validate_hex_address,
    validate_runtime_module_kind
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
    base_value = raw.get("base")

    if base_value is None:
        regions_raw = raw.get("regions", [])
        if not regions_raw:
            raise TaintLogValidationError("base is missing and regions is empty")

        region_addrs = []
        for idx, region in enumerate(regions_raw):
            addr = require_string(region.get("addr"), f"regions[{idx}].addr")
            region_addrs.append(int(addr, 16))

        base = hex(min(region_addrs))
    else:
        base = require_string(base_value, "base")

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

    network_dependencies, network_events = parse_network_entries(
    require_list(
        raw.get("network_dependencies"),
        "network_dependencies",
    )
)

    library_dependencies = [
        parse_library_dependency(item, index=i)
        for i, item in enumerate(
            require_list(raw.get("library_dependencies"), "library_dependencies")
        )
    ]

    runtime_modules = [
        parse_runtime_module(item, index=i)
        for i, item in enumerate(
            require_list(
                raw.get("runtime_modules"),
                "runtime_modules",
                )
            )
        ]

    validate_runtime_module_set(runtime_modules)

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
        network_events=network_events,
        runtime_modules=runtime_modules,
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

def parse_runtime_mapping(
    raw: Any,
    module_index: int,
    mapping_index: int,
) -> RuntimeMapping:
    context = (
        f"runtime_modules[{module_index}]"
        f".mappings[{mapping_index}]"
    )

    raw = require_dict(raw, context)

    start = validate_hex_address(
        raw.get("start"),
        f"{context}.start",
    )
    end = validate_hex_address(
        raw.get("end"),
        f"{context}.end",
    )

    start_int = int(start, 16)
    end_int = int(end, 16)

    if end_int <= start_int:
        raise TaintLogValidationError(
            f"{context}.end must be greater than start"
        )

    prot = require_int(
        raw.get("prot"),
        f"{context}.prot",
    )

    if not (0 <= prot <= 7):
        raise TaintLogValidationError(
            f"{context}.prot must be between 0 and 7"
        )

    offset = raw.get("offset", 0)
    offset = require_int(offset, f"{context}.offset")

    if offset < 0:
        raise TaintLogValidationError(
            f"{context}.offset must be >= 0"
        )

    path = raw.get("path")
    if path is not None:
        path = require_string(path, f"{context}.path")

    return RuntimeMapping(
        start=start,
        end=end,
        prot=prot,
        offset=offset,
        path=path,
    )


def parse_runtime_module(
    raw: Any,
    index: int,
) -> RuntimeModule:
    context = f"runtime_modules[{index}]"
    raw = require_dict(raw, context)

    module_id = require_string(
        raw.get("module_id"),
        f"{context}.module_id",
    )

    kind = validate_runtime_module_kind(
        raw.get("kind"),
        f"{context}.kind",
    )

    load_bias = validate_hex_address(
        raw.get("load_bias"),
        f"{context}.load_bias",
    )

    mappings = [
        parse_runtime_mapping(
            mapping_raw,
            module_index=index,
            mapping_index=mapping_index,
        )
        for mapping_index, mapping_raw in enumerate(
            require_list(
                raw.get("mappings"),
                f"{context}.mappings",
            )
        )
    ]

    if not mappings:
        raise TaintLogValidationError(
            f"{context}.mappings must not be empty"
        )

    mappings.sort(key=lambda mapping: mapping.start_int())

    for previous, current in zip(mappings, mappings[1:]):
        if current.start_int() < previous.end_int():
            raise TaintLogValidationError(
                f"{context}.mappings overlap: "
                f"{previous.start}-{previous.end} and "
                f"{current.start}-{current.end}"
            )

    load_bias_int = int(load_bias, 16)

    for mapping_index, mapping in enumerate(mappings):
        if mapping.start_int() < load_bias_int:
            raise TaintLogValidationError(
                f"{context}.mappings[{mapping_index}].start "
                f"is below module load_bias"
            )

    path = raw.get("path")
    if path is not None:
        path = require_string(path, f"{context}.path")

    soname = raw.get("soname")
    if soname is not None:
        soname = require_string(
            soname,
            f"{context}.soname",
        )

    build_id = raw.get("build_id")
    if build_id is not None:
        build_id = require_string(
            build_id,
            f"{context}.build_id",
        )

    sha256 = raw.get("sha256")
    if sha256 is not None:
        sha256 = require_string(
            sha256,
            f"{context}.sha256",
        ).lower()

    return RuntimeModule(
        module_id=module_id,
        kind=kind,
        load_bias=load_bias,
        mappings=mappings,
        path=path,
        soname=soname,
        build_id=build_id,
        sha256=sha256,
    )


def validate_runtime_module_set(
    modules: list[RuntimeModule],
) -> None:
    if not modules:
        return

    module_ids: set[str] = set()

    for index, module in enumerate(modules):
        if module.module_id in module_ids:
            raise TaintLogValidationError(
                "Duplicate runtime module_id: "
                f"{module.module_id}"
            )

        module_ids.add(module.module_id)

    main_modules = [
        module
        for module in modules
        if module.kind == "main"
    ]

    if len(main_modules) != 1:
        raise TaintLogValidationError(
            "runtime_modules must contain exactly one "
            f"main module, found {len(main_modules)}"
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

def parse_network_entries(
    raw_entries: list[Any],
) -> tuple[list[NetworkDependency], list[NetworkEvent]]:
    dependencies: list[NetworkDependency] = []
    events: list[NetworkEvent] = []

    for index, item in enumerate(raw_entries):
        context = f"network_dependencies[{index}]"
        raw = require_dict(item, context)

        if "op" not in raw:
            dependencies.append(
                parse_network_dependency(raw, index=index)
            )
            continue

        event = parse_network_event(raw, index=index)
        events.append(event)

        if event.has_remote_endpoint():
            if event.socket_type is None:
                raise TaintLogValidationError(
                    f"{context}.type is required when an endpoint is present"
                )

            dependencies.append(
                NetworkDependency(
                    ip=event.ip,
                    port=event.port,
                    type=validate_network_type(event.socket_type),
                )
            )

    return dependencies, events


def parse_network_event(raw: Any, index: int) -> NetworkEvent:
    context = f"network_dependencies[{index}]"
    raw = require_dict(raw, context)

    op = require_string(raw.get("op"), f"{context}.op").lower()

    fd = raw.get("fd")
    if fd is not None:
        fd = require_int(fd, f"{context}.fd")

        if fd < 0:
            raise TaintLogValidationError(
                f"{context}.fd must be >= 0"
            )

    domain = raw.get("domain")
    if domain is not None:
        domain = require_string(domain, f"{context}.domain")

    socket_type = raw.get("socket_type", raw.get("type"))
    if socket_type is not None:
        socket_type = require_string(
            socket_type,
            f"{context}.type",
        ).lower()

    ip = raw.get("ip")
    if ip is not None:
        ip = require_string(ip, f"{context}.ip")

    port = raw.get("port")
    if port is not None:
        port = validate_port(port, f"{context}.port")

    if (ip is None) != (port is None):
        raise TaintLogValidationError(
            f"{context} must contain both ip and port, or neither"
        )

    return NetworkEvent(
        op=op,
        fd=fd,
        domain=domain,
        socket_type=socket_type,
        ip=ip,
        port=port,
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

    # Compact schema:
    #
    # "library_dependencies": [
    #   "libc.so.6",
    #   "libpthread.so.0"
    # ]
    if isinstance(raw, str):
        return LibraryDependency(
            name=require_string(raw, context)
        )

    raw = require_dict(raw, context)

    path = raw.get("path")
    if path is not None:
        path = require_string(path, f"{context}.path")

    name = raw.get("name")

    if name is None:
        if path is None:
            raise TaintLogValidationError(
                f"{context} must contain name or path"
            )

        name = PurePosixPath(path).name

        if not name:
            raise TaintLogValidationError(
                f"{context}.path does not contain a library filename"
            )
    else:
        name = require_string(name, f"{context}.name")

    symbols_raw = require_list(
        raw.get("symbols"),
        f"{context}.symbols",
    )

    symbols = [
        require_string(
            symbol,
            f"{context}.symbols[{symbol_index}]",
        )
        for symbol_index, symbol in enumerate(symbols_raw)
    ]

    observed_base = raw.get(
        "observed_base",
        raw.get("base"),
    )
    if observed_base is not None:
        observed_base = require_string(
            observed_base,
            f"{context}.base",
        )

    observed_size = raw.get(
        "observed_size",
        raw.get("size"),
    )
    if observed_size is not None:
        observed_size = require_int(
            observed_size,
            f"{context}.size",
        )

        if observed_size <= 0:
            raise TaintLogValidationError(
                f"{context}.size must be > 0"
            )

    return LibraryDependency(
        name=name,
        path=path,
        symbols=symbols,
        observed_base=observed_base,
        observed_size=observed_size,
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
