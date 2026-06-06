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


@dataclass(slots=True)
class MemoryRegion:
    addr: str
    size: int
    prot: int
    offset: int


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
class LibraryDependency:
    name: str
    path: Optional[str] = None
    symbols: list[str] = field(default_factory=list)


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
    library_dependencies: list[LibraryDependency] = field(default_factory=list)
    anti_analysis: AntiAnalysis = field(default_factory=AntiAnalysis)

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
