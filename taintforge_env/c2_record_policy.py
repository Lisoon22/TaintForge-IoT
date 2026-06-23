from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
MODE = "brokered_record"
CAPTURE_KINDS = {"local_test", "live"}


class C2RecordPolicyError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class C2RecordTarget:
    original_ip: str
    original_port: int
    upstream_ip: str
    upstream_port: int


@dataclass(slots=True, frozen=True)
class C2RecordLimits:
    max_connections: int = 1
    connect_timeout_seconds: float = 5.0
    session_timeout_seconds: float = 30.0
    idle_timeout_seconds: float = 5.0
    max_client_bytes: int = 65536
    max_server_bytes: int = 1048576


@dataclass(slots=True, frozen=True)
class C2RecordPolicy:
    schema_version: int
    mode: str
    capture_kind: str
    default_action: str
    listen_port: int
    target: C2RecordTarget
    limits: C2RecordLimits
    live_capture_acknowledged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _require_mapping(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise C2RecordPolicyError(f"{key} must be an object")
    return value


def _require_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise C2RecordPolicyError(f"{key} must be a non-empty string")
    return value.strip()


def _require_bool(raw: dict[str, Any], key: str, default: bool = False) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise C2RecordPolicyError(f"{key} must be boolean")
    return value


def _require_int(
    raw: dict[str, Any],
    key: str,
    *,
    minimum: int,
    maximum: int,
    default: int | None = None,
) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise C2RecordPolicyError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise C2RecordPolicyError(
            f"{key} must be between {minimum} and {maximum}"
        )
    return value


def _require_number(
    raw: dict[str, Any],
    key: str,
    *,
    minimum: float,
    maximum: float,
    default: float,
) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise C2RecordPolicyError(f"{key} must be a number")
    result = float(value)
    if not minimum <= result <= maximum:
        raise C2RecordPolicyError(
            f"{key} must be between {minimum} and {maximum}"
        )
    return result


def _ip_literal(value: str, field: str) -> ipaddress._BaseAddress:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise C2RecordPolicyError(
            f"{field} must be an IP literal, not a hostname: {value}"
        ) from exc


def parse_c2_record_policy(raw: dict[str, Any]) -> C2RecordPolicy:
    if not isinstance(raw, dict):
        raise C2RecordPolicyError("policy root must be an object")

    schema_version = raw.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise C2RecordPolicyError(
            f"unsupported schema_version: {schema_version}"
        )

    mode = _require_string(raw, "mode")
    if mode != MODE:
        raise C2RecordPolicyError(f"mode must be {MODE!r}")

    capture_kind = _require_string(raw, "capture_kind").lower()
    if capture_kind not in CAPTURE_KINDS:
        raise C2RecordPolicyError(
            "capture_kind must be 'local_test' or 'live'"
        )

    default_action = _require_string(raw, "default_action").lower()
    if default_action != "deny":
        raise C2RecordPolicyError("default_action must be 'deny'")

    listen_port = _require_int(
        raw,
        "listen_port",
        minimum=1024,
        maximum=65535,
        default=41000,
    )

    target_raw = _require_mapping(raw, "target")
    original_ip_obj = _ip_literal(
        _require_string(target_raw, "original_ip"),
        "target.original_ip",
    )
    upstream_ip_obj = _ip_literal(
        _require_string(target_raw, "upstream_ip"),
        "target.upstream_ip",
    )

    original_port = _require_int(
        target_raw,
        "original_port",
        minimum=1,
        maximum=65535,
    )
    upstream_port = _require_int(
        target_raw,
        "upstream_port",
        minimum=1,
        maximum=65535,
    )

    limits_raw = _require_mapping(raw, "limits")
    max_connections = _require_int(
        limits_raw,
        "max_connections",
        minimum=1,
        maximum=4,
        default=1,
    )
    connect_timeout = _require_number(
        limits_raw,
        "connect_timeout_seconds",
        minimum=0.1,
        maximum=15.0,
        default=5.0,
    )
    session_timeout = _require_number(
        limits_raw,
        "session_timeout_seconds",
        minimum=1.0,
        maximum=120.0,
        default=30.0,
    )
    idle_timeout = _require_number(
        limits_raw,
        "idle_timeout_seconds",
        minimum=0.5,
        maximum=30.0,
        default=5.0,
    )
    max_client_bytes = _require_int(
        limits_raw,
        "max_client_bytes",
        minimum=1,
        maximum=1024 * 1024,
        default=65536,
    )
    max_server_bytes = _require_int(
        limits_raw,
        "max_server_bytes",
        minimum=1,
        maximum=16 * 1024 * 1024,
        default=1048576,
    )

    acknowledged = _require_bool(
        raw,
        "live_capture_acknowledged",
        default=False,
    )

    if capture_kind == "local_test":
        if not (
            upstream_ip_obj.is_loopback
            or upstream_ip_obj.is_private
        ):
            raise C2RecordPolicyError(
                "local_test upstream_ip must be loopback or private"
            )
    else:
        if not acknowledged:
            raise C2RecordPolicyError(
                "live capture requires live_capture_acknowledged=true"
            )
        if not original_ip_obj.is_global or not upstream_ip_obj.is_global:
            raise C2RecordPolicyError(
                "live capture requires globally routable original/upstream IPs"
            )
        if original_ip_obj != upstream_ip_obj:
            raise C2RecordPolicyError(
                "live capture requires upstream_ip == original_ip"
            )
        if original_port != upstream_port:
            raise C2RecordPolicyError(
                "live capture requires upstream_port == original_port"
            )
        if max_connections != 1:
            raise C2RecordPolicyError(
                "live capture requires max_connections=1"
            )
        if session_timeout > 60.0:
            raise C2RecordPolicyError(
                "live capture session_timeout_seconds must be <= 60"
            )
        if max_client_bytes > 131072:
            raise C2RecordPolicyError(
                "live capture max_client_bytes must be <= 131072"
            )
        if max_server_bytes > 4 * 1024 * 1024:
            raise C2RecordPolicyError(
                "live capture max_server_bytes must be <= 4194304"
            )

    return C2RecordPolicy(
        schema_version=SCHEMA_VERSION,
        mode=mode,
        capture_kind=capture_kind,
        default_action=default_action,
        listen_port=listen_port,
        target=C2RecordTarget(
            original_ip=str(original_ip_obj),
            original_port=original_port,
            upstream_ip=str(upstream_ip_obj),
            upstream_port=upstream_port,
        ),
        limits=C2RecordLimits(
            max_connections=max_connections,
            connect_timeout_seconds=connect_timeout,
            session_timeout_seconds=session_timeout,
            idle_timeout_seconds=idle_timeout,
            max_client_bytes=max_client_bytes,
            max_server_bytes=max_server_bytes,
        ),
        live_capture_acknowledged=acknowledged,
    )


def load_c2_record_policy(path: str | Path) -> C2RecordPolicy:
    path = Path(path)
    if not path.exists():
        raise C2RecordPolicyError(f"record policy not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise C2RecordPolicyError(
            f"invalid JSON in record policy: {exc}"
        ) from exc
    return parse_c2_record_policy(raw)
