from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable

from .attempt import ExecutionStage


ENVIRONMENT_MANIFEST_SCHEMA_VERSION = 2
ENVIRONMENT_MANIFEST_MODEL_VERSION = 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}")
_PROVIDER_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CONSUMER_PC_RE = re.compile(r"0x[0-9a-fA-F]+")


class EnvironmentManifestError(RuntimeError):
    """Raised when an environment manifest or its version chain is invalid."""


class ManifestResourceKind(StrEnum):
    DIRECTORY = "directory"
    FILE = "file"
    DEVICE = "device"
    NETWORK_ENDPOINT = "network_endpoint"
    NETWORK_SERVICE = "network_service"
    LIBRARY = "library"
    LOADER = "loader"
    SYSCALL_MODEL = "syscall_model"
    PERSONA = "persona"


class LifecycleScope(StrEnum):
    REBUILD_ONLY = "REBUILD_ONLY"
    ITERATION_RUNTIME = "ITERATION_RUNTIME"
    SHARED = "SHARED"
    UNKNOWN = "UNKNOWN"


class ManifestConfidence(StrEnum):
    HYPOTHESIS = "hypothesis"
    OBSERVED = "observed"
    VALIDATED = "validated"
    REJECTED = "rejected"


class ManifestEntryStatus(StrEnum):
    ACTIVE = "active"
    UNRESOLVED = "unresolved"
    REMOVABLE = "removable"
    REJECTED = "rejected"


class EvidenceKind(StrEnum):
    STATIC_PREFLIGHT = "static_preflight"
    RUNTIME_EVENT = "runtime_event"
    PHASE1_EVENT = "phase1_event"
    REPAIR_APPLICATION = "repair_application"
    VALIDATION_RUN = "validation_run"
    OPERATOR_DECISION = "operator_decision"


@dataclass(slots=True, frozen=True)
class ManifestEvidence:
    evidence_id: str
    kind: EvidenceKind
    attempt_id: str
    artifact_sha256: str

    def __post_init__(self) -> None:
        _validate_identifier(self.evidence_id, "evidence_id")
        _validate_identifier(self.attempt_id, "evidence attempt_id")
        _validate_sha256(self.artifact_sha256, "evidence artifact_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "attempt_id": self.attempt_id,
            "artifact_sha256": self.artifact_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> ManifestEvidence:
        value = _require_dict(raw, "manifest evidence")
        try:
            return cls(
                evidence_id=_require_string(
                    value.get("evidence_id"), "evidence_id"
                ),
                kind=EvidenceKind(value.get("kind")),
                attempt_id=_require_string(
                    value.get("attempt_id"), "attempt_id"
                ),
                artifact_sha256=_require_string(
                    value.get("artifact_sha256"), "artifact_sha256"
                ),
            )
        except ValueError as exc:
            raise EnvironmentManifestError(
                "manifest evidence contains an unsupported kind"
            ) from exc


@dataclass(slots=True, frozen=True)
class ManifestEntry:
    resource_id: str
    kind: ManifestResourceKind
    lifecycle_scope: LifecycleScope
    first_seen_stage: ExecutionStage
    first_seen_attempt_id: str
    provider: str
    value_id: str
    value_sha256: str
    evidence: tuple[ManifestEvidence, ...]
    confidence: ManifestConfidence
    status: ManifestEntryStatus
    consumer_pc: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.resource_id, "resource_id")
        _validate_identifier(
            self.first_seen_attempt_id, "first_seen_attempt_id"
        )
        if not _PROVIDER_RE.fullmatch(self.provider):
            raise EnvironmentManifestError(
                "provider must be a lowercase provider identifier"
            )
        _validate_identifier(self.value_id, "value_id")
        _validate_sha256(self.value_sha256, "value_sha256")
        if not self.evidence:
            raise EnvironmentManifestError(
                f"manifest entry {self.resource_id!r} has no evidence"
            )
        evidence_ids = [item.evidence_id for item in self.evidence]
        if evidence_ids != sorted(evidence_ids):
            raise EnvironmentManifestError(
                f"manifest entry {self.resource_id!r} evidence must be sorted"
            )
        if len(evidence_ids) != len(set(evidence_ids)):
            raise EnvironmentManifestError(
                f"manifest entry {self.resource_id!r} repeats evidence"
            )
        if self.consumer_pc is not None and not _CONSUMER_PC_RE.fullmatch(
            self.consumer_pc
        ):
            raise EnvironmentManifestError("consumer_pc must be hexadecimal")
        if (
            self.status == ManifestEntryStatus.ACTIVE
            and self.confidence == ManifestConfidence.REJECTED
        ):
            raise EnvironmentManifestError(
                "an active manifest entry cannot have rejected confidence"
            )
        if self.status == ManifestEntryStatus.REJECTED and (
            self.confidence != ManifestConfidence.REJECTED
        ):
            raise EnvironmentManifestError(
                "a rejected entry must have rejected confidence"
            )

    @property
    def entry_sha256(self) -> str:
        return _canonical_sha256(self.identity_dict())

    def identity_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "kind": self.kind.value,
            "lifecycle_scope": self.lifecycle_scope.value,
            "first_seen_stage": self.first_seen_stage.value,
            "first_seen_attempt_id": self.first_seen_attempt_id,
            "consumer_pc": self.consumer_pc,
            "provider": self.provider,
            "value_id": self.value_id,
            "value_sha256": self.value_sha256,
            "evidence": [item.to_dict() for item in self.evidence],
            "confidence": self.confidence.value,
            "status": self.status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.identity_dict(), "entry_sha256": self.entry_sha256}

    @classmethod
    def from_dict(cls, raw: Any) -> ManifestEntry:
        value = _require_dict(raw, "manifest entry")
        evidence_raw = value.get("evidence")
        if not isinstance(evidence_raw, list):
            raise EnvironmentManifestError("manifest entry evidence must be an array")
        consumer_pc = value.get("consumer_pc")
        if consumer_pc is not None:
            consumer_pc = _require_string(consumer_pc, "consumer_pc")
        try:
            entry = cls(
                resource_id=_require_string(
                    value.get("resource_id"), "resource_id"
                ),
                kind=ManifestResourceKind(value.get("kind")),
                lifecycle_scope=LifecycleScope(value.get("lifecycle_scope")),
                first_seen_stage=ExecutionStage(value.get("first_seen_stage")),
                first_seen_attempt_id=_require_string(
                    value.get("first_seen_attempt_id"),
                    "first_seen_attempt_id",
                ),
                consumer_pc=consumer_pc,
                provider=_require_string(value.get("provider"), "provider"),
                value_id=_require_string(value.get("value_id"), "value_id"),
                value_sha256=_require_string(
                    value.get("value_sha256"), "value_sha256"
                ),
                evidence=tuple(
                    ManifestEvidence.from_dict(item) for item in evidence_raw
                ),
                confidence=ManifestConfidence(value.get("confidence")),
                status=ManifestEntryStatus(value.get("status")),
            )
        except ValueError as exc:
            raise EnvironmentManifestError(
                "manifest entry contains an unsupported enum value"
            ) from exc
        expected = _require_string(value.get("entry_sha256"), "entry_sha256")
        _validate_sha256(expected, "entry_sha256")
        if entry.entry_sha256 != expected:
            raise EnvironmentManifestError(
                f"manifest entry digest mismatch for {entry.resource_id}"
            )
        return entry


@dataclass(slots=True, frozen=True)
class EnvironmentManifest:
    sample_sha256: str
    manifest_version: int
    rootfs_snapshot_id: str
    entries: tuple[ManifestEntry, ...]
    created_by_attempt_id: str
    change_reason: str
    parent_version: int | None = None
    parent_manifest_id: str | None = None
    schema_version: int = ENVIRONMENT_MANIFEST_SCHEMA_VERSION
    model_version: int = ENVIRONMENT_MANIFEST_MODEL_VERSION
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.schema_version != ENVIRONMENT_MANIFEST_SCHEMA_VERSION:
            raise EnvironmentManifestError(
                "unsupported environment manifest schema_version"
            )
        if self.model_version != ENVIRONMENT_MANIFEST_MODEL_VERSION:
            raise EnvironmentManifestError(
                "unsupported environment manifest model_version"
            )
        _validate_sha256(self.sample_sha256, "sample_sha256")
        if self.manifest_version < 0:
            raise EnvironmentManifestError(
                "manifest_version must be non-negative"
            )
        _validate_identifier(self.rootfs_snapshot_id, "rootfs_snapshot_id")
        _validate_identifier(
            self.created_by_attempt_id, "created_by_attempt_id"
        )
        if not self.change_reason.strip():
            raise EnvironmentManifestError("change_reason is required")
        _validate_timestamp(self.generated_at_utc, "generated_at_utc")
        if self.manifest_version == 0:
            if self.parent_version is not None or self.parent_manifest_id is not None:
                raise EnvironmentManifestError(
                    "manifest version zero cannot have a parent"
                )
        else:
            if self.parent_version != self.manifest_version - 1:
                raise EnvironmentManifestError(
                    "parent_version must immediately precede manifest_version"
                )
            if self.parent_manifest_id is None:
                raise EnvironmentManifestError(
                    "non-seed manifest requires parent_manifest_id"
                )
            _validate_identifier(self.parent_manifest_id, "parent_manifest_id")
        resources = [entry.resource_id for entry in self.entries]
        if resources != sorted(resources):
            raise EnvironmentManifestError(
                "manifest entries must be sorted by resource_id"
            )
        if len(resources) != len(set(resources)):
            raise EnvironmentManifestError(
                "manifest contains duplicate resource_id values"
            )

    @property
    def sample_id(self) -> str:
        return f"packed-sample-{self.sample_sha256[:16]}"

    def identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "sample_id": self.sample_id,
            "sample_sha256": self.sample_sha256,
            "manifest_version": self.manifest_version,
            "parent_version": self.parent_version,
            "parent_manifest_id": self.parent_manifest_id,
            "rootfs_snapshot_id": self.rootfs_snapshot_id,
            "created_by_attempt_id": self.created_by_attempt_id,
            "change_reason": self.change_reason,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @property
    def manifest_sha256(self) -> str:
        return _canonical_sha256(self.identity_dict())

    @property
    def manifest_id(self) -> str:
        return f"manifest-v{self.manifest_version:04d}-{self.manifest_sha256[:16]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.identity_dict(),
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "generated_at_utc": self.generated_at_utc,
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        by_scope: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for entry in self.entries:
            by_scope[entry.lifecycle_scope.value] = (
                by_scope.get(entry.lifecycle_scope.value, 0) + 1
            )
            by_status[entry.status.value] = by_status.get(entry.status.value, 0) + 1
        return {
            "entries_total": len(self.entries),
            "by_lifecycle_scope": dict(sorted(by_scope.items())),
            "by_status": dict(sorted(by_status.items())),
        }

    def derive(
        self,
        *,
        rootfs_snapshot_id: str,
        entries: Iterable[ManifestEntry],
        created_by_attempt_id: str,
        change_reason: str,
    ) -> EnvironmentManifest:
        return EnvironmentManifest(
            sample_sha256=self.sample_sha256,
            manifest_version=self.manifest_version + 1,
            parent_version=self.manifest_version,
            parent_manifest_id=self.manifest_id,
            rootfs_snapshot_id=rootfs_snapshot_id,
            entries=tuple(sorted(entries, key=lambda item: item.resource_id)),
            created_by_attempt_id=created_by_attempt_id,
            change_reason=change_reason,
        )

    def diff(self, parent: EnvironmentManifest) -> ManifestDiff:
        if self.parent_version != parent.manifest_version:
            raise EnvironmentManifestError(
                "cannot diff manifests without a direct parent relationship"
            )
        if self.parent_manifest_id != parent.manifest_id:
            raise EnvironmentManifestError("parent_manifest_id mismatch")
        if self.sample_sha256 != parent.sample_sha256:
            raise EnvironmentManifestError("manifest samples do not match")

        previous = {entry.resource_id: entry for entry in parent.entries}
        current = {entry.resource_id: entry for entry in self.entries}
        added = tuple(sorted(set(current) - set(previous)))
        removed = tuple(sorted(set(previous) - set(current)))
        changed = tuple(
            sorted(
                resource
                for resource in set(previous) & set(current)
                if previous[resource].entry_sha256
                != current[resource].entry_sha256
            )
        )
        return ManifestDiff(
            from_manifest_id=parent.manifest_id,
            to_manifest_id=self.manifest_id,
            added=added,
            removed=removed,
            changed=changed,
            rootfs_changed=(
                self.rootfs_snapshot_id != parent.rootfs_snapshot_id
            ),
        )

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict(), overwrite=False)

    @classmethod
    def from_dict(cls, raw: Any) -> EnvironmentManifest:
        value = _require_dict(raw, "environment manifest")
        entries_raw = value.get("entries")
        if not isinstance(entries_raw, list):
            raise EnvironmentManifestError("manifest entries must be an array")
        parent_version = value.get("parent_version")
        if parent_version is not None:
            parent_version = _require_int(parent_version, "parent_version")
        parent_manifest_id = value.get("parent_manifest_id")
        if parent_manifest_id is not None:
            parent_manifest_id = _require_string(
                parent_manifest_id, "parent_manifest_id"
            )
        manifest = cls(
            schema_version=_require_int(
                value.get("schema_version"), "schema_version"
            ),
            model_version=_require_int(
                value.get("model_version"), "model_version"
            ),
            sample_sha256=_require_string(
                value.get("sample_sha256"), "sample_sha256"
            ),
            manifest_version=_require_int(
                value.get("manifest_version"), "manifest_version"
            ),
            parent_version=parent_version,
            parent_manifest_id=parent_manifest_id,
            rootfs_snapshot_id=_require_string(
                value.get("rootfs_snapshot_id"), "rootfs_snapshot_id"
            ),
            entries=tuple(ManifestEntry.from_dict(item) for item in entries_raw),
            created_by_attempt_id=_require_string(
                value.get("created_by_attempt_id"), "created_by_attempt_id"
            ),
            change_reason=_require_string(
                value.get("change_reason"), "change_reason"
            ),
            generated_at_utc=_require_string(
                value.get("generated_at_utc"), "generated_at_utc"
            ),
        )
        expected_sample_id = _require_string(
            value.get("sample_id"), "sample_id"
        )
        if expected_sample_id != manifest.sample_id:
            raise EnvironmentManifestError("sample_id mismatch")
        expected_id = _require_string(value.get("manifest_id"), "manifest_id")
        expected_sha256 = _require_string(
            value.get("manifest_sha256"), "manifest_sha256"
        )
        _validate_sha256(expected_sha256, "manifest_sha256")
        if expected_sha256 != manifest.manifest_sha256:
            raise EnvironmentManifestError("environment manifest digest mismatch")
        if expected_id != manifest.manifest_id:
            raise EnvironmentManifestError("environment manifest id mismatch")
        return manifest

    @classmethod
    def load(cls, path: str | Path) -> EnvironmentManifest:
        return cls.from_dict(_load_json(path, "environment manifest"))


@dataclass(slots=True, frozen=True)
class ManifestDiff:
    from_manifest_id: str
    to_manifest_id: str
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    rootfs_changed: bool

    @property
    def is_empty(self) -> bool:
        return not (
            self.added or self.removed or self.changed or self.rootfs_changed
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_manifest_id": self.from_manifest_id,
            "to_manifest_id": self.to_manifest_id,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
            "rootfs_changed": self.rootfs_changed,
            "is_empty": self.is_empty,
        }


class EnvironmentManifestStore:
    """Append-only storage and parent-chain verification for semantic manifests."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).resolve(strict=False)

    def path_for_version(self, version: int) -> Path:
        if version < 0:
            raise EnvironmentManifestError("manifest version must be non-negative")
        return self.directory / f"environment_manifest_v{version:04d}.json"

    def save(self, manifest: EnvironmentManifest) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise EnvironmentManifestError(
                "environment manifest store must not be a symlink"
            )
        path = self.path_for_version(manifest.manifest_version)
        if path.is_symlink():
            raise EnvironmentManifestError("manifest path must not be a symlink")
        if path.exists():
            existing = EnvironmentManifest.load(path)
            if existing.manifest_id != manifest.manifest_id:
                raise EnvironmentManifestError(
                    f"manifest version {manifest.manifest_version} is immutable"
                )
            return path
        if manifest.manifest_version > 0:
            parent = self.load(manifest.manifest_version - 1)
            self._validate_parent(manifest, parent)
        _atomic_write_json(path, manifest.to_dict(), overwrite=False)
        return path

    def load(self, version: int) -> EnvironmentManifest:
        return EnvironmentManifest.load(self.path_for_version(version))

    def verify_chain(self, through_version: int | None = None) -> tuple[EnvironmentManifest, ...]:
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise EnvironmentManifestError(
                f"environment manifest store is invalid: {self.directory}"
            )
        paths = sorted(self.directory.glob("environment_manifest_v[0-9][0-9][0-9][0-9].json"))
        if through_version is not None:
            paths = [
                path
                for path in paths
                if _version_from_path(path) <= through_version
            ]
        if not paths:
            raise EnvironmentManifestError("environment manifest store is empty")
        manifests = tuple(EnvironmentManifest.load(path) for path in paths)
        versions = [item.manifest_version for item in manifests]
        if versions != list(range(len(manifests))):
            raise EnvironmentManifestError(
                "environment manifest versions must be contiguous from zero"
            )
        for parent, child in zip(manifests, manifests[1:]):
            self._validate_parent(child, parent)
        return manifests

    @staticmethod
    def _validate_parent(
        child: EnvironmentManifest,
        parent: EnvironmentManifest,
    ) -> None:
        if child.sample_sha256 != parent.sample_sha256:
            raise EnvironmentManifestError("manifest parent sample mismatch")
        if child.parent_version != parent.manifest_version:
            raise EnvironmentManifestError("manifest parent version mismatch")
        if child.parent_manifest_id != parent.manifest_id:
            raise EnvironmentManifestError("manifest parent id mismatch")


def replace_manifest_entry(
    entries: Iterable[ManifestEntry],
    replacement: ManifestEntry,
) -> tuple[ManifestEntry, ...]:
    by_resource = {entry.resource_id: entry for entry in entries}
    by_resource[replacement.resource_id] = replacement
    return tuple(sorted(by_resource.values(), key=lambda item: item.resource_id))


def add_manifest_evidence(
    entry: ManifestEntry,
    evidence: ManifestEvidence,
) -> ManifestEntry:
    by_id = {item.evidence_id: item for item in entry.evidence}
    existing = by_id.get(evidence.evidence_id)
    if existing is not None and existing != evidence:
        raise EnvironmentManifestError(
            f"evidence id {evidence.evidence_id!r} is already bound"
        )
    by_id[evidence.evidence_id] = evidence
    return replace(
        entry,
        evidence=tuple(sorted(by_id.values(), key=lambda item: item.evidence_id)),
    )


def _version_from_path(path: Path) -> int:
    match = re.fullmatch(r"environment_manifest_v([0-9]{4})\.json", path.name)
    if match is None:
        raise EnvironmentManifestError(f"invalid environment manifest filename: {path}")
    return int(match.group(1))


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_sha256(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise EnvironmentManifestError(
            f"{label} must be a lowercase SHA-256 digest"
        )


def _validate_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise EnvironmentManifestError(f"{label} is invalid")


def _validate_timestamp(value: str, label: str) -> None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise EnvironmentManifestError(
            f"{label} is not an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise EnvironmentManifestError(f"{label} must include a timezone")


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnvironmentManifestError(f"{label} must be a JSON object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise EnvironmentManifestError(f"{label} must be a non-empty string")
    return value


def _require_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EnvironmentManifestError(f"{label} must be an integer")
    return value


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EnvironmentManifestError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise EnvironmentManifestError(f"invalid {label} JSON: {exc}") from exc
    return _require_dict(raw, label)


def _atomic_write_json(
    path: Path,
    payload: dict[str, Any],
    *,
    overwrite: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise EnvironmentManifestError(f"refusing to overwrite manifest: {path}")
    serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        if not overwrite and path.exists():
            raise EnvironmentManifestError(f"refusing to overwrite manifest: {path}")
        os.replace(temporary, path)
        os.chmod(path, 0o644)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)
