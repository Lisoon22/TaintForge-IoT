from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .network_modes import NetworkMode


DEFAULT_BLOCKED_NETWORKS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
    "2001:db8::/32",
)

DEFAULT_BLOCKED_PORTS = (
    22, 23, 25, 445, 2375, 2376, 3389, 6379, 11211,
)

FETCH_METHODS = {"GET", "HEAD"}
FETCH_SCHEMES = {"http", "https"}


class EgressPolicyError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class GlobalLimits:
    max_connections: int = 4
    max_uploaded_bytes: int = 131072
    max_downloaded_bytes: int = 16777216
    max_duration_seconds: int = 30
    requests_per_second: float = 1.0


@dataclass(slots=True, frozen=True)
class DestinationRule:
    name: str
    hosts: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()
    schemes: tuple[str, ...] = ("http", "https")
    ports: tuple[int, ...] = (80, 443)
    methods: tuple[str, ...] = ("GET", "HEAD")
    max_connections: int = 2
    max_request_bytes: int = 65536
    max_response_bytes: int = 8388608
    timeout_seconds: int = 10
    cache_response: bool = True
    allow_redirects: bool = False
    max_redirects: int = 0
    verify_tls: bool = True

    def matches_identity(
        self,
        *,
        host: str | None,
        ip: str | None,
    ) -> bool:
        normalized_host = normalize_host(host) if host else None

        if normalized_host and normalized_host in self.hosts:
            return True

        if ip and ip in self.ips:
            return True

        return False

    def matches_request(
        self,
        *,
        host: str | None,
        ip: str | None,
        scheme: str,
        port: int,
        method: str,
    ) -> bool:
        return (
            self.matches_identity(host=host, ip=ip)
            and scheme.lower() in self.schemes
            and port in self.ports
            and method.upper() in self.methods
        )


@dataclass(slots=True, frozen=True)
class EgressDecision:
    allowed: bool
    reason: str
    rule_name: str | None = None


@dataclass(slots=True)
class EgressPolicy:
    schema_version: int
    mode: NetworkMode
    default_action: str
    rules: list[DestinationRule] = field(default_factory=list)
    blocked_networks: tuple[str, ...] = DEFAULT_BLOCKED_NETWORKS
    blocked_ports: tuple[int, ...] = DEFAULT_BLOCKED_PORTS
    block_non_global_ips: bool = True
    global_limits: GlobalLimits = field(default_factory=GlobalLimits)

    _parsed_blocked_networks: tuple[
        ipaddress.IPv4Network | ipaddress.IPv6Network,
        ...
    ] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise EgressPolicyError(
                f"Unsupported egress policy schema_version: "
                f"{self.schema_version}"
            )

        if self.default_action != "deny":
            raise EgressPolicyError(
                "Egress policy default_action must be 'deny'"
            )

        if self.mode not in {
            NetworkMode.BROKERED_FETCH,
            NetworkMode.BROKERED_RELAY,
        }:
            raise EgressPolicyError(
                "Egress policy mode must be brokered_fetch "
                "or brokered_relay"
            )

        self._parsed_blocked_networks = tuple(
            ipaddress.ip_network(value, strict=False)
            for value in self.blocked_networks
        )

    def validate_external_ip(self, value: str) -> None:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise EgressPolicyError(
                f"Invalid destination IP: {value}"
            ) from exc

        for network in self._parsed_blocked_networks:
            if address.version == network.version and address in network:
                raise EgressPolicyError(
                    f"Destination IP is blocked by {network}: {value}"
                )

        if self.block_non_global_ips and not address.is_global:
            raise EgressPolicyError(
                f"Destination IP is not globally routable: {value}"
            )

    def validate_resolved_ips(
        self,
        *,
        host: str,
        addresses: Iterable[str],
    ) -> tuple[str, ...]:
        validated: list[str] = []

        for value in addresses:
            self.validate_external_ip(value)
            validated.append(value)

        if not validated:
            raise EgressPolicyError(
                f"DNS returned no usable addresses for host: {host}"
            )

        return tuple(validated)

    def evaluate_request(
        self,
        *,
        host: str | None,
        ip: str | None,
        scheme: str,
        port: int,
        method: str,
    ) -> EgressDecision:
        scheme = scheme.lower()
        method = method.upper()

        if port in self.blocked_ports:
            return EgressDecision(
                allowed=False,
                reason=f"destination_port_blocked:{port}",
            )

        if ip is not None:
            try:
                self.validate_external_ip(ip)
            except EgressPolicyError as exc:
                return EgressDecision(
                    allowed=False,
                    reason=f"destination_ip_blocked:{exc}",
                )

        for rule in self.rules:
            if rule.matches_request(
                host=host,
                ip=ip,
                scheme=scheme,
                port=port,
                method=method,
            ):
                return EgressDecision(
                    allowed=True,
                    reason="matched_allow_rule",
                    rule_name=rule.name,
                )

        return EgressDecision(
            allowed=False,
            reason="no_matching_allow_rule",
        )


def normalize_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")

    if not host:
        raise EgressPolicyError("Host must not be empty")

    if "*" in host:
        raise EgressPolicyError(
            "Wildcard hosts are disabled in brokered_fetch MVP"
        )

    return host


def require_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EgressPolicyError(f"{context} must be an object")
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise EgressPolicyError(f"{context} must be a list")
    return value


def require_positive_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise EgressPolicyError(
            f"{context} must be a positive integer"
        )
    return value


def parse_ports(values: Any, context: str) -> tuple[int, ...]:
    ports: list[int] = []

    for index, value in enumerate(require_list(values, context)):
        port = require_positive_int(value, f"{context}[{index}]")
        if port > 65535:
            raise EgressPolicyError(
                f"{context}[{index}] is out of range: {port}"
            )
        ports.append(port)

    if not ports:
        raise EgressPolicyError(f"{context} must not be empty")

    return tuple(sorted(set(ports)))


def parse_hosts(values: Any, context: str) -> tuple[str, ...]:
    hosts = []

    for index, value in enumerate(require_list(values, context)):
        if not isinstance(value, str):
            raise EgressPolicyError(
                f"{context}[{index}] must be a string"
            )
        hosts.append(normalize_host(value))

    return tuple(sorted(set(hosts)))


def parse_ips(values: Any, context: str) -> tuple[str, ...]:
    ips = []

    for index, value in enumerate(require_list(values, context)):
        if not isinstance(value, str):
            raise EgressPolicyError(
                f"{context}[{index}] must be a string"
            )

        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise EgressPolicyError(
                f"{context}[{index}] is not an IP address: {value}"
            ) from exc

        ips.append(str(address))

    return tuple(sorted(set(ips)))


def parse_strings(
    values: Any,
    context: str,
    *,
    allowed: set[str],
    uppercase: bool = False,
) -> tuple[str, ...]:
    result = []

    for index, value in enumerate(require_list(values, context)):
        if not isinstance(value, str):
            raise EgressPolicyError(
                f"{context}[{index}] must be a string"
            )

        normalized = value.upper() if uppercase else value.lower()

        if normalized not in allowed:
            raise EgressPolicyError(
                f"Unsupported value in {context}[{index}]: {value}"
            )

        result.append(normalized)

    if not result:
        raise EgressPolicyError(f"{context} must not be empty")

    return tuple(sorted(set(result)))


def parse_destination_rule(
    raw: Any,
    *,
    index: int,
    mode: NetworkMode,
) -> DestinationRule:
    context = f"allowed_destinations[{index}]"
    raw = require_dict(raw, context)

    name = raw.get("name", f"rule-{index}")
    if not isinstance(name, str) or not name.strip():
        raise EgressPolicyError(
            f"{context}.name must be a non-empty string"
        )

    match = require_dict(raw.get("match", {}), f"{context}.match")
    hosts = parse_hosts(match.get("hosts", []), f"{context}.match.hosts")
    ips = parse_ips(match.get("ips", []), f"{context}.match.ips")

    if not hosts and not ips:
        raise EgressPolicyError(
            f"{context}.match must contain hosts or ips"
        )

    schemes = parse_strings(
        raw.get("schemes", ["http", "https"]),
        f"{context}.schemes",
        allowed=FETCH_SCHEMES,
    )

    methods = parse_strings(
        raw.get("methods", ["GET", "HEAD"]),
        f"{context}.methods",
        allowed=FETCH_METHODS,
        uppercase=True,
    )

    if mode == NetworkMode.BROKERED_FETCH:
        unsupported = set(methods) - FETCH_METHODS
        if unsupported:
            raise EgressPolicyError(
                "brokered_fetch only supports GET and HEAD"
            )

    return DestinationRule(
        name=name.strip(),
        hosts=hosts,
        ips=ips,
        schemes=schemes,
        ports=parse_ports(
            raw.get("ports", [80, 443]),
            f"{context}.ports",
        ),
        methods=methods,
        max_connections=require_positive_int(
            raw.get("max_connections", 2),
            f"{context}.max_connections",
        ),
        max_request_bytes=require_positive_int(
            raw.get("max_request_bytes", 65536),
            f"{context}.max_request_bytes",
        ),
        max_response_bytes=require_positive_int(
            raw.get("max_response_bytes", 8388608),
            f"{context}.max_response_bytes",
        ),
        timeout_seconds=require_positive_int(
            raw.get("timeout_seconds", 10),
            f"{context}.timeout_seconds",
        ),
        cache_response=bool(raw.get("cache_response", True)),
        allow_redirects=bool(raw.get("allow_redirects", False)),
        max_redirects=int(raw.get("max_redirects", 0)),
        verify_tls=bool(raw.get("verify_tls", True)),
    )


def parse_global_limits(raw: Any) -> GlobalLimits:
    raw = require_dict(raw or {}, "global_limits")

    requests_per_second = raw.get("requests_per_second", 1.0)
    if (
        not isinstance(requests_per_second, (int, float))
        or isinstance(requests_per_second, bool)
        or requests_per_second <= 0
    ):
        raise EgressPolicyError(
            "global_limits.requests_per_second must be positive"
        )

    return GlobalLimits(
        max_connections=require_positive_int(
            raw.get("max_connections", 4),
            "global_limits.max_connections",
        ),
        max_uploaded_bytes=require_positive_int(
            raw.get("max_uploaded_bytes", 131072),
            "global_limits.max_uploaded_bytes",
        ),
        max_downloaded_bytes=require_positive_int(
            raw.get("max_downloaded_bytes", 16777216),
            "global_limits.max_downloaded_bytes",
        ),
        max_duration_seconds=require_positive_int(
            raw.get("max_duration_seconds", 30),
            "global_limits.max_duration_seconds",
        ),
        requests_per_second=float(requests_per_second),
    )


def load_egress_policy(path: str | Path) -> EgressPolicy:
    path = Path(path)

    if not path.exists():
        raise EgressPolicyError(
            f"Egress policy does not exist: {path}"
        )

    if not path.is_file():
        raise EgressPolicyError(
            f"Egress policy is not a file: {path}"
        )

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EgressPolicyError(
            f"Invalid JSON in egress policy {path}: {exc}"
        ) from exc

    raw = require_dict(raw, "egress_policy")

    try:
        mode = NetworkMode(str(raw.get("mode", "")).lower())
    except ValueError as exc:
        raise EgressPolicyError(
            "egress_policy.mode must be brokered_fetch "
            "or brokered_relay"
        ) from exc

    rules = [
        parse_destination_rule(item, index=index, mode=mode)
        for index, item in enumerate(
            require_list(
                raw.get("allowed_destinations"),
                "allowed_destinations",
            )
        )
    ]

    blocked_networks = tuple(
        str(value)
        for value in require_list(
            raw.get("blocked_networks", list(DEFAULT_BLOCKED_NETWORKS)),
            "blocked_networks",
        )
    )

    for index, value in enumerate(blocked_networks):
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise EgressPolicyError(
                f"blocked_networks[{index}] is invalid: {value}"
            ) from exc

    blocked_ports = parse_ports(
        raw.get("blocked_ports", list(DEFAULT_BLOCKED_PORTS)),
        "blocked_ports",
    )

    return EgressPolicy(
        schema_version=int(raw.get("schema_version", 0)),
        mode=mode,
        default_action=str(raw.get("default_action", "")),
        rules=rules,
        blocked_networks=blocked_networks,
        blocked_ports=blocked_ports,
        block_non_global_ips=bool(
            raw.get("block_non_global_ips", True)
        ),
        global_limits=parse_global_limits(
            raw.get("global_limits", {})
        ),
    )
