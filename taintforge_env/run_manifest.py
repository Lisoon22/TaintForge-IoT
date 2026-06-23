from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_MANIFEST_SCHEMA_VERSION = 1


class RunManifestError(RuntimeError):
    pass


def sha256_file(path: str | Path) -> str:
    path = Path(path)
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def file_metadata(path: str | Path) -> dict[str, Any]:
    path = Path(path).resolve()

    if not path.exists() or not path.is_file():
        raise RunManifestError(f"Input file does not exist: {path}")

    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def create_run_id(binary_path: str | Path) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    binary_prefix = sha256_file(binary_path)[:8]
    nonce = secrets.token_hex(3)
    return f"{timestamp}-{binary_prefix}-{nonce}"


def build_run_manifest(
    *,
    run_id: str,
    taint_path: str | Path,
    binary_path: str | Path,
    sysroot_path: str | Path,
    out_dir: str | Path,
    network_mode: str,
    timeout_seconds: int,
    bind_ip: str,
    namespace: str,
    catch_all_port: int,
    udp_catch_all_port: int,
    build_only: bool,
    allow_missing_libraries: bool,
    self_test_network: bool,
    egress_policy_path: str | Path | None,
    egress_policy_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    policy_metadata = None

    if egress_policy_path is not None:
        policy_metadata = file_metadata(egress_policy_path)
        policy_metadata["summary"] = egress_policy_summary or {}

    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "run_id": run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "taint": file_metadata(taint_path),
            "binary": file_metadata(binary_path),
            "sysroot": {
                "path": str(Path(sysroot_path).resolve()),
                "exists": Path(sysroot_path).exists(),
            },
        },
        "output": {
            "path": str(Path(out_dir).resolve()),
        },
        "execution": {
            "timeout_seconds": timeout_seconds,
            "build_only": build_only,
            "allow_missing_libraries": allow_missing_libraries,
            "self_test_network": self_test_network,
        },
        "network": {
            "mode": network_mode,
            "bind_ip": bind_ip,
            "namespace": namespace,
            "catch_all_port": catch_all_port,
            "udp_catch_all_port": udp_catch_all_port,
            "egress_policy": policy_metadata,
        },
    }


def save_run_manifest(
    manifest: dict[str, Any],
    path: str | Path,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
