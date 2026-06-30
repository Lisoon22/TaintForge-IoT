from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


SUPPORTED_ARCHES = {
    "arm",
    "aarch64",
    "mips",
    "mipsel",
    "x86",
    "x86_64",
}


SUPPORTED_NETWORK_TYPES = {
    "c2_binary",
    "dns",
    "ntp",
    "tcp",
    "udp",
    "http",
    "https",
}

SUPPORTED_RUNTIME_MODULE_KINDS = {
    "main",
    "interpreter",
    "shared_library",
    "anonymous",
}

@dataclass(slots=True)
class MemoryRegion:
    addr: str
    size: int
    prot: int
    offset: int

@dataclass(slots=True)
class RuntimeMapping:
    start: str
    end: str
    prot: int
    offset: int = 0
    path: Optional[str] = None

    def start_int(self) -> int:
        return int(self.start, 16)

    def end_int(self) -> int:
        return int(self.end, 16)

    def size(self) -> int:
        return self.end_int() - self.start_int()

    def contains(self, address: int) -> bool:
        return self.start_int() <= address < self.end_int()


@dataclass(slots=True)
class RuntimeModule:
    module_id: str
    kind: str
    load_bias: str
    mappings: list[RuntimeMapping]

    path: Optional[str] = None
    soname: Optional[str] = None
    build_id: Optional[str] = None
    sha256: Optional[str] = None

    def load_bias_int(self) -> int:
        return int(self.load_bias, 16)

    def runtime_start(self) -> int:
        return min(mapping.start_int() for mapping in self.mappings)

    def runtime_end(self) -> int:
        return max(mapping.end_int() for mapping in self.mappings)

    def contains(self, address: int) -> bool:
        return any(
            mapping.contains(address)
            for mapping in self.mappings
        )

    def va_to_rva(self, address: int) -> int:
        if not self.contains(address):
            raise ValueError(
                f"Address {address:#x} is outside module "
                f"{self.module_id}"
            )

        return address - self.load_bias_int()

    def rva_to_va(self, rva: int) -> int:
        if rva < 0:
            raise ValueError("RVA must be >= 0")

        address = self.load_bias_int() + rva

        if not self.contains(address):
            raise ValueError(
                f"RVA {rva:#x} resolves outside module "
                f"{self.module_id}"
            )

        return address

@dataclass(slots=True)
class FileDependency:
    path: str
    write: bool = False

    def is_proc(self) -> bool:
        return self.path.startswith("/proc/")

    def is_dev(self) -> bool:
        return self.path.startswith("/dev/")

    def is_tmp(self) -> bool:
        return self.path.startswith("/tmp/")

    def is_config(self) -> bool:
        return self.path.startswith("/etc/") or self.path.startswith("/var/")


@dataclass(slots=True)
class NetworkDependency:
    ip: str
    port: int
    type: str
    sample_bytes: Optional[str] = None

    def is_dns(self) -> bool:
        return self.type == "dns" or self.port == 53

    def is_ntp(self) -> bool:
        return self.type == "ntp" or self.port == 123

    def is_c2(self) -> bool:
        return self.type.startswith("c2")

    def effective_remote_ip(self) -> str:
        return self.ip

    def effective_remote_port(self) -> int:
        return self.port

    def transport(self) -> str:
        if self.type == "dns":
            return "udp"

        if self.type == "ntp":
            return "udp"

        if self.type in {"udp"}:
            return "udp"

        # c2_binary, http, https, tcp are treated as TCP for the first MVP.
        return "tcp"


@dataclass(slots=True)
class NetworkEvent:
    op:str
    fd: Optional[int] = None
    domain: Optional[str] = None
    socket_type: Optional[str] = None
    ip: Optional[int] = None
    port: Optional[int] = None

    def has_remote_endpoint(self) -> bool:
        return self.ip is not None and self.port is not None


@dataclass(slots=True)
class LibraryDependency:
    name: str
    path: Optional[str] = None
    symbols: list[str] = field(default_factory=list)

    observed_base: Optional[str] = None
    observed_size: Optional[str] = None


@dataclass(slots=True)
class AntiAnalysis:
    cpuinfo_check: bool = False
    uname_check: bool = False
    ptrace_traceme: bool = False


@dataclass(slots=True)
class TaintLog:
    oep: str
    arch: str
    base: str
    regions: list[MemoryRegion] = field(default_factory=list)
    file_dependencies: list[FileDependency] = field(default_factory=list)
    network_dependencies: list[NetworkDependency] = field(default_factory=list)
    network_events: list[NetworkEvent] = field(default_factory=list)
    library_dependencies: list[LibraryDependency] = field(default_factory=list)
    anti_analysis: AntiAnalysis = field(default_factory=AntiAnalysis)
    runtime_modules: list[RuntimeModule] = field(default_factory=list)

    def required_paths(self) -> list[str]:
        return sorted({dep.path for dep in self.file_dependencies})

    def required_libraries(self) -> list[str]:
        return sorted({dep.name for dep in self.library_dependencies})

    def tcp_services(self) -> list[NetworkDependency]:
        return [
            dep for dep in self.network_dependencies
            if dep.transport() == "tcp"
        ]

    def udp_services(self) -> list[NetworkDependency]:
        return [
            dep for dep in self.network_dependencies
            if dep.transport() == "udp"
        ]

    def dns_dependencies(self) -> list[NetworkDependency]:
        return [
            dep for dep in self.network_dependencies
            if dep.is_dns()
        ]
