from __future__ import annotations

import json
import socket 
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .models import NetworkDependency, TaintLog

@dataclass(slots=True)
class NetworkServicePolicy:
    service_type: str
    role: str

    remote_ip: Optional[str]
    remote_port: Optional[int]
    domain: Optional[str]

    bind_ip: str
    bind_port: int
    protocol_hint: Optional[str] = None

@dataclass(slots=True)
class NetworkPolicy:
    mode: str = "local_test"
    allow_internet: bool = False
    services: list[NetworkServicePolicy] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
                "mode": self.mode,
                "allow_internet": self.allow_internet,
                "services": [asdict(service) for service in self.services]
        }

def is_tcp_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((host,port))
        except OSError:
            return False
        return True

def choose_tcp_bind_port(host: str, preferred_port: Optional[int]) -> int:
    if preferred_port is not None and is_tcp_port_available(host, preferred_port):
        return preferred_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host,0))
        return int(sock.getsockname()[1])

def build_network_policy(taint: TaintLog, mode: str = "local test", default_bind_ip: str = "127.0.0.1") -> NetworkPolicy:
    policy = NetworkPolicy(mode = mode, allow_internet = False)
    for dep in taint.network_dependencies:
        service = build_service_policy(dep = dep, default_bind_ip = default_bind_ip)

        if service is not None:
            policy.services.append(service)

    return policy

def build_service_policy(dep: NetworkDependency, default_bind_ip: str) -> Optional[NetworkServicePolicy]:
    if dep.type != "tcp":
        #all other types later
        return None
    
    remote_port = dep.effective_remote_port()

    if remote_port is None:
        return None

    bind_port = choose_tcp_bind_port(host = default_bind_ip, preferred_port=remote_port)

    return NetworkServicePolicy(service_type = dep.type, role = dep.role or "unknown", remote_ip = dep.effective_remote_ip(), remote_port = remote_port, domain = dep.domain, bind_ip = default_bind_ip, bind_port = bind_port, protocol_hint = dep.protocol_hint)

def save_network_policy(policy: NetworkPolicy, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy.to_dict(), indent=2), encoding = "utf-8")

def load_network_policy(path: str | Path) -> NetworkPolicy:
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    
    services = [
        NetworkServicePolicy(**item)
        for item in raw.get("services", [])
    ]

    return NetworkPolicy(mode=raw.get("mode", "local_test"), allow_internet = bool(raw.get("allow_internet", False)), services = services)
