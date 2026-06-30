from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from .models import SUPPORTED_ARCHES, SUPPORTED_NETWORK_TYPES, SUPPORTED_RUNTIME_MODULE_KINDS


class TaintLogValidationError(ValueError):
    pass


def require_dict(raw: Any, context: str) -> dict:
    if not isinstance(raw, dict):
        raise TaintLogValidationError(f"{context} must be an object/dict")
    return raw


def require_list(raw: Any, context: str) -> list:
    if raw is None:
        return []

    if not isinstance(raw, list):
        raise TaintLogValidationError(f"{context} must be a list")

    return raw


def require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TaintLogValidationError(f"{context} must be a non-empty string")
    return value


def require_bool(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise TaintLogValidationError(f"{context} must be boolean")
    return value


def require_int(value: Any, context: str) -> int:
    if not isinstance(value, int):
        raise TaintLogValidationError(f"{context} must be integer")
    return value


def validate_arch(arch: Any) -> str:
    arch = require_string(arch, "arch").lower()

    if arch not in SUPPORTED_ARCHES:
        supported = ", ".join(sorted(SUPPORTED_ARCHES))
        raise TaintLogValidationError(
            f"Unsupported architecture: {arch}. Supported: {supported}"
        )

    return arch


def validate_file_path(path: Any) -> str:
    path = require_string(path, "file_dependency.path")

    if not path.startswith("/"):
        raise TaintLogValidationError(
            f"File dependency path must be absolute: {path}"
        )

    posix_path = PurePosixPath(path)

    if ".." in posix_path.parts:
        raise TaintLogValidationError(
            f"File dependency path must not contain '..': {path}"
        )

    return str(posix_path)


def validate_network_type(net_type: Any) -> str:
    net_type = require_string(net_type, "network_dependency.type").lower()

    if net_type not in SUPPORTED_NETWORK_TYPES:
        supported = ", ".join(sorted(SUPPORTED_NETWORK_TYPES))
        raise TaintLogValidationError(
            f"Unsupported network type: {net_type}. Supported: {supported}"
        )

    return net_type


def validate_port(port: Any, context: str = "network_dependency.port") -> int:
    if isinstance(port, str) and port.isdigit():
        port = int(port)

    if not isinstance(port, int):
        raise TaintLogValidationError(f"{context} must be an integer")

    if not (1 <= port <= 65535):
        raise TaintLogValidationError(f"{context} out of range: {port}")

    return port

def validate_hex_address(value: Any, context: str) -> str:
    value = require_string(value, context).lower()

    if not value.startswith("0x"):
        raise TaintLogValidationError(
            f"{context} must start with 0x"
        )

    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise TaintLogValidationError(
            f"{context} is not a valid hexadecimal address: {value}"
        ) from exc

    if parsed < 0:
        raise TaintLogValidationError(
            f"{context} must be >= 0"
        )

    return hex(parsed)


def validate_runtime_module_kind(value: Any, context: str) -> str:
    kind = require_string(value, context).lower()

    if kind not in SUPPORTED_RUNTIME_MODULE_KINDS:
        supported = ", ".join(
            sorted(SUPPORTED_RUNTIME_MODULE_KINDS)
        )
        raise TaintLogValidationError(
            f"Unsupported runtime module kind: {kind}. "
            f"Supported: {supported}"
        )

    return kind
