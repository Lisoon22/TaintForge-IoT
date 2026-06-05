from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


SUPPORTED_ARCHES = {
    "arm",
    "aarch64",
    "mips",
    "mipsel",
    "x86",
    "x86_64",
}

SUPPORTED_NETWORK_TYPES = {
    "tcp",
    "udp",
    "dns",
    "ntp",
}


@dataclass(slots=True)
class SampleInfo:
    name: str
    arch: str
    endianness: Optional[str] = None
    binary: Optional[str] = None
    oep: Optional[str] = None

    def is_cross_arch(self) -> bool:
        return self.arch in {"arm", "aarch64", "mips", "mipsel"}


@dataclass(slots=True)
class FileDependency:
    path: str
    syscall: Optional[str] = None
    flags: Optional[str] = None
    ret: Optional[int] = None
    content_hint: Optional[str] = None

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
    type: str
    role: Optional[str] = None

    # New explicit fields: what malware actually tried to contact.
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None

    # Legacy fields from early mock logs.
    ip: Optional[str] = None
    port: Optional[int] = None

    domain: Optional[str] = None
    response_ip: Optional[str] = None
    protocol_hint: Optional[str] = None

    def effective_remote_ip(self) -> Optional[str]:
        return self.remote_ip or self.ip

    def effective_remote_port(self) -> Optional[int]:
        return self.remote_port or self.port

    def is_tcp(self) -> bool:
        return self.type == "tcp"

    def is_udp(self) -> bool:
        return self.type == "udp"

    def is_dns(self) -> bool:
        return self.type == "dns"

    def is_ntp(self) -> bool:
        return self.type == "ntp"

@dataclass(slots=True)
class LibraryDependency:
    name: str
    path: Optional[str] = None
    symbols: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SyscallEvent:
    name: str
    args: list[Any] = field(default_factory=list)
    ret: Optional[Any] = None
    timestamp: Optional[float] = None
    pc: Optional[str] = None


@dataclass(slots=True)
class AntiAnalysisEvent:
    type: str
    detail: Optional[str] = None


@dataclass(slots=True)
class TaintLog:
    schema_version: str
    sample: SampleInfo
    file_dependencies: list[FileDependency] = field(default_factory=list)
    network_dependencies: list[NetworkDependency] = field(default_factory=list)
    library_dependencies: list[LibraryDependency] = field(default_factory=list)
    syscalls: list[SyscallEvent] = field(default_factory=list)
    anti_analysis: list[AntiAnalysisEvent] = field(default_factory=list)

    def required_paths(self) -> list[str]:
        return sorted({dep.path for dep in self.file_dependencies})

    def required_libraries(self) -> list[str]:
        return sorted({dep.name for dep in self.library_dependencies})

    def tcp_services(self) -> list[NetworkDependency]:
        return [
            dep for dep in self.network_dependencies
            if dep.type == "tcp"
        ]

    def udp_services(self) -> list[NetworkDependency]:
        return [
            dep for dep in self.network_dependencies
            if dep.type == "udp"
        ]

    def dns_dependencies(self) -> list[NetworkDependency]:
        return [
            dep for dep in self.network_dependencies
            if dep.type == "dns"
        ]

    def syscall_names(self) -> list[str]:
        return [event.name for event in self.syscalls]
