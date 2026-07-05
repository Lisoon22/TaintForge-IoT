from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterator

from .environment_snapshot import (
    EnvironmentSnapshotError,
    EnvironmentSnapshotStore,
)
from .progress_oracle import (
    IterationObservation,
    ProgressClassification,
    ProgressDecision,
    ProgressOracle,
    ProgressOracleError,
)
from .repair_applier import RepairApplicationError, RepairApplier


class IterationControllerError(RuntimeError):
    """Raised when an iteration session transition is invalid or unsafe."""


class SessionState(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class IterationState(StrEnum):
    PREPARED = "prepared"
    COMPLETED = "completed"


class StopReason(StrEnum):
    GOAL_REACHED = "goal_reached"
    FIXED_POINT = "fixed_point"
    CYCLE_DETECTED = "cycle_detected"
    NO_AUTOMATIC_REPAIRS = "no_automatic_repairs"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(slots=True, frozen=True)
class IterationRecord:
    index: int
    state: IterationState
    directory: str
    environment_snapshot_id: str
    parent_snapshot_id: str | None
    repair_application: str | None = None
    observation: str | None = None
    artifact_manifest: str | None = None
    progress: dict[str, Any] | None = None
    stop_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "state": self.state.value,
            "directory": self.directory,
            "environment_snapshot_id": self.environment_snapshot_id,
            "parent_snapshot_id": self.parent_snapshot_id,
            "repair_application": self.repair_application,
            "observation": self.observation,
            "artifact_manifest": self.artifact_manifest,
            "progress": self.progress,
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> IterationRecord:
        if not isinstance(raw, dict):
            raise IterationControllerError("iteration record must be an object")
        index = raw.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise IterationControllerError("iteration index is invalid")
        try:
            state = IterationState(raw.get("state"))
        except ValueError as exc:
            raise IterationControllerError("iteration state is invalid") from exc
        directory = raw.get("directory")
        environment_snapshot_id = raw.get("environment_snapshot_id")
        if not isinstance(directory, str) or not directory:
            raise IterationControllerError("iteration directory is invalid")
        if not isinstance(environment_snapshot_id, str) or not environment_snapshot_id.startswith("env_"):
            raise IterationControllerError("environment snapshot id is invalid")
        parent_snapshot_id = raw.get("parent_snapshot_id")
        if parent_snapshot_id is not None and (
            not isinstance(parent_snapshot_id, str)
            or not parent_snapshot_id.startswith("env_")
        ):
            raise IterationControllerError("parent snapshot id is invalid")
        _validate_relative_path(directory, "iteration directory")
        repair_application = _optional_string(raw.get("repair_application"))
        observation = _optional_string(raw.get("observation"))
        artifact_manifest = _optional_string(raw.get("artifact_manifest"))
        for label, value in (
            ("repair_application", repair_application),
            ("observation", observation),
            ("artifact_manifest", artifact_manifest),
        ):
            if value is not None:
                _validate_relative_path(value, label)
        progress = raw.get("progress")
        if progress is not None and not isinstance(progress, dict):
            raise IterationControllerError("iteration progress is invalid")
        return cls(
            index=index,
            state=state,
            directory=directory,
            environment_snapshot_id=environment_snapshot_id,
            parent_snapshot_id=parent_snapshot_id,
            repair_application=repair_application,
            observation=observation,
            artifact_manifest=artifact_manifest,
            progress=progress,
            stop_reason=_optional_string(raw.get("stop_reason")),
        )


@dataclass(slots=True, frozen=True)
class SessionManifest:
    session_id: str
    session_dir: str
    snapshot_store: str
    seed_snapshot_id: str
    max_iterations: int
    state: SessionState = SessionState.ACTIVE
    stop_reason: str | None = None
    iterations: tuple[IterationRecord, ...] = ()
    schema_version: int = 1
    controller_version: int = 1
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "controller_version": self.controller_version,
            "session_id": self.session_id,
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
            "session_dir": self.session_dir,
            "snapshot_store": self.snapshot_store,
            "seed_snapshot_id": self.seed_snapshot_id,
            "max_iterations": self.max_iterations,
            "state": self.state.value,
            "stop_reason": self.stop_reason,
            "iterations": [item.to_dict() for item in self.iterations],
        }

    @classmethod
    def load(cls, path: str | Path) -> SessionManifest:
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise IterationControllerError(f"session manifest does not exist: {path}") from exc
        except json.JSONDecodeError as exc:
            raise IterationControllerError(f"invalid session manifest JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise IterationControllerError("session manifest must be an object")
        if raw.get("schema_version") != 1 or raw.get("controller_version") != 1:
            raise IterationControllerError("unsupported session manifest version")
        session_id = raw.get("session_id")
        session_dir = raw.get("session_dir")
        snapshot_store = raw.get("snapshot_store")
        seed_snapshot_id = raw.get("seed_snapshot_id")
        max_iterations = raw.get("max_iterations")
        if not isinstance(session_id, str) or not session_id.startswith("session_"):
            raise IterationControllerError("session_id is invalid")
        for name, value in (
            ("session_dir", session_dir),
            ("snapshot_store", snapshot_store),
        ):
            if not isinstance(value, str) or not value:
                raise IterationControllerError(f"{name} is invalid")
        if not isinstance(seed_snapshot_id, str) or not seed_snapshot_id.startswith("env_"):
            raise IterationControllerError("seed_snapshot_id is invalid")
        if not isinstance(max_iterations, int) or isinstance(max_iterations, bool) or max_iterations < 1:
            raise IterationControllerError("max_iterations is invalid")
        try:
            state = SessionState(raw.get("state"))
        except ValueError as exc:
            raise IterationControllerError("session state is invalid") from exc
        iterations_raw = raw.get("iterations", [])
        if not isinstance(iterations_raw, list):
            raise IterationControllerError("iterations must be an array")
        iterations = tuple(IterationRecord.from_dict(item) for item in iterations_raw)
        if [item.index for item in iterations] != list(range(len(iterations))):
            raise IterationControllerError("iteration indexes must be contiguous")
        return cls(
            session_id=session_id,
            session_dir=session_dir,
            snapshot_store=snapshot_store,
            seed_snapshot_id=seed_snapshot_id,
            max_iterations=max_iterations,
            state=state,
            stop_reason=_optional_string(raw.get("stop_reason")),
            iterations=iterations,
            created_at_utc=str(raw.get("created_at_utc") or "unknown"),
            updated_at_utc=str(raw.get("updated_at_utc") or "unknown"),
        )

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())


@dataclass(slots=True, frozen=True)
class PreparedIteration:
    record: IterationRecord
    execution_rootfs: Path
    environment_snapshot_id: str


class IterationController:
    """State machine for immutable environment-repair iterations.

    The controller prepares clean execution clones and records externally
    produced Phase 2 artifacts. It does not run malware itself; runner
    integration remains a separate boundary.
    """

    def __init__(self, session_dir: str | Path) -> None:
        self.session_dir = _safe_directory_path(session_dir, "session directory")
        self.session_manifest_path = self.session_dir / "session.json"
        self.lock_path = self.session_dir / ".session.lock"

    @classmethod
    def initialize(
        cls,
        *,
        session_dir: str | Path,
        snapshot_store: str | Path,
        seed_rootfs: str | Path,
        max_iterations: int = 5,
    ) -> SessionManifest:
        if max_iterations < 1:
            raise IterationControllerError("max_iterations must be positive")
        session = _safe_directory_path(session_dir, "session directory")
        if session.exists() or session.is_symlink():
            raise IterationControllerError(f"session directory already exists: {session}")
        session.parent.mkdir(parents=True, exist_ok=True)
        if session.parent.is_symlink():
            raise IterationControllerError("session parent must not be a symlink")

        temporary = Path(
            tempfile.mkdtemp(
                prefix=f".{session.name}.",
                suffix=".tmp",
                dir=session.parent,
            )
        )
        try:
            store = EnvironmentSnapshotStore(snapshot_store)
            capture = store.capture(seed_rootfs)
            session_id = (
                "session_"
                + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                + "_"
                + uuid.uuid4().hex[:8]
            )
            manifest = SessionManifest(
                session_id=session_id,
                session_dir=str(session),
                snapshot_store=str(store.store_dir),
                seed_snapshot_id=capture.manifest.snapshot_id,
                max_iterations=max_iterations,
            )
            (temporary / "iterations").mkdir()
            manifest.save(temporary / "session.json")
            (temporary / ".session.lock").touch()
            os.replace(temporary, session)
            temporary = None
            return manifest
        except (EnvironmentSnapshotError, OSError) as exc:
            if isinstance(exc, IterationControllerError):
                raise
            raise IterationControllerError(str(exc)) from exc
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def load(self) -> SessionManifest:
        manifest = SessionManifest.load(self.session_manifest_path)
        if Path(manifest.session_dir).resolve(strict=False) != self.session_dir:
            raise IterationControllerError("session manifest path mismatch")
        return manifest

    def prepare_next(self) -> PreparedIteration:
        with self._locked():
            manifest = self.load()
            if manifest.state != SessionState.ACTIVE:
                raise IterationControllerError(
                    f"session is not active: {manifest.state.value}"
                )
            if manifest.iterations and manifest.iterations[-1].state == IterationState.PREPARED:
                raise IterationControllerError("the latest iteration is still prepared")
            index = len(manifest.iterations)
            if index >= manifest.max_iterations:
                raise IterationControllerError("iteration budget is exhausted")

            store = EnvironmentSnapshotStore(manifest.snapshot_store)
            repair_application_bytes: bytes | None = None
            if index == 0:
                parent_snapshot_id = None
                environment_snapshot_id = manifest.seed_snapshot_id
                repair_application_relative = None
            else:
                previous = manifest.iterations[-1]
                if previous.state != IterationState.COMPLETED:
                    raise IterationControllerError("previous iteration is incomplete")
                previous_dir = self.session_dir / previous.directory
                requirements_path = previous_dir / "artifacts" / "runtime_requirements.json"
                plan_path = previous_dir / "artifacts" / "repair_plan.json"
                if not requirements_path.is_file() or not plan_path.is_file():
                    raise IterationControllerError(
                        "previous iteration does not contain repair inputs"
                    )
                parent_snapshot_id = previous.environment_snapshot_id
                environment_snapshot_id, repair_application_bytes = self._build_repaired_snapshot(
                    store=store,
                    parent_snapshot_id=parent_snapshot_id,
                    plan_path=plan_path,
                    requirements_path=requirements_path,
                    iteration_index=index,
                )
                repair_application_relative = (
                    f"iterations/{index:04d}/repair_application.json"
                )

            iteration_relative = f"iterations/{index:04d}"
            iteration_dir = self.session_dir / iteration_relative
            temporary = Path(
                tempfile.mkdtemp(
                    prefix=f".{index:04d}.",
                    suffix=".tmp",
                    dir=self.session_dir / "iterations",
                )
            )
            try:
                execution_rootfs = temporary / "execution" / "rootfs"
                store.clone(environment_snapshot_id, execution_rootfs)
                if repair_application_bytes is not None:
                    (temporary / "repair_application.json").write_bytes(
                        repair_application_bytes
                    )
                record = IterationRecord(
                    index=index,
                    state=IterationState.PREPARED,
                    directory=iteration_relative,
                    environment_snapshot_id=environment_snapshot_id,
                    parent_snapshot_id=parent_snapshot_id,
                    repair_application=repair_application_relative,
                )
                _atomic_write_json(temporary / "iteration.json", record.to_dict())
                os.replace(temporary, iteration_dir)
                temporary = None
            finally:
                if temporary is not None and temporary.exists():
                    shutil.rmtree(temporary, ignore_errors=True)

            updated = _replace_session(
                manifest,
                iterations=manifest.iterations + (record,),
            )
            updated.save(self.session_manifest_path)
            return PreparedIteration(
                record=record,
                execution_rootfs=iteration_dir / "execution" / "rootfs",
                environment_snapshot_id=environment_snapshot_id,
            )

    def complete_iteration(
        self,
        *,
        iteration_index: int,
        artifacts_dir: str | Path,
        goal_reached: bool = False,
        goal_reason: str | None = None,
    ) -> IterationRecord:
        with self._locked():
            manifest = self.load()
            if manifest.state != SessionState.ACTIVE:
                raise IterationControllerError("cannot complete an inactive session")
            if iteration_index < 0 or iteration_index >= len(manifest.iterations):
                raise IterationControllerError("iteration index does not exist")
            record = manifest.iterations[iteration_index]
            if record.state != IterationState.PREPARED:
                raise IterationControllerError("iteration is not in prepared state")
            if iteration_index != len(manifest.iterations) - 1:
                raise IterationControllerError("only the latest iteration may be completed")

            iteration_dir = self.session_dir / record.directory
            _validate_execution_claim_for_completion(
                iteration_dir,
                iteration_index=iteration_index,
                session_id=manifest.session_id,
            )
            source_artifacts = Path(artifacts_dir).resolve(strict=False)
            if not source_artifacts.is_dir() or source_artifacts.is_symlink():
                raise IterationControllerError(
                    f"artifacts directory is invalid: {source_artifacts}"
                )
            target_artifacts = iteration_dir / "artifacts"
            if target_artifacts.exists() or target_artifacts.is_symlink():
                raise IterationControllerError("iteration artifacts already exist")
            if _is_relative_to(target_artifacts, source_artifacts):
                raise IterationControllerError(
                    "artifacts source must not contain the iteration target"
                )

            temporary_artifacts = iteration_dir / ".artifacts.tmp"
            if temporary_artifacts.exists():
                shutil.rmtree(temporary_artifacts)
            try:
                _copy_artifacts(source_artifacts, temporary_artifacts)
                oracle = ProgressOracle()
                observation = oracle.observe(
                    temporary_artifacts,
                    environment_snapshot_id=record.environment_snapshot_id,
                    goal_reached=goal_reached,
                    goal_reason=goal_reason,
                )
                previous_observation = self._previous_observation(manifest, iteration_index)
                progress = oracle.compare(previous_observation, observation)
                artifact_manifest = _build_artifact_manifest(temporary_artifacts)
                _atomic_write_json(
                    temporary_artifacts / "artifact_manifest.json",
                    artifact_manifest,
                )
                os.replace(temporary_artifacts, target_artifacts)
            except (ProgressOracleError, OSError) as exc:
                if temporary_artifacts.exists():
                    shutil.rmtree(temporary_artifacts, ignore_errors=True)
                raise IterationControllerError(str(exc)) from exc

            observation_path = iteration_dir / "observation.json"
            observation.save(observation_path)
            stop_reason = self._decide_stop_reason(
                manifest=manifest,
                iteration_index=iteration_index,
                observation=observation,
            )
            completed = IterationRecord(
                index=record.index,
                state=IterationState.COMPLETED,
                directory=record.directory,
                environment_snapshot_id=record.environment_snapshot_id,
                parent_snapshot_id=record.parent_snapshot_id,
                repair_application=record.repair_application,
                observation=str(observation_path.relative_to(self.session_dir)),
                artifact_manifest=str(
                    (target_artifacts / "artifact_manifest.json").relative_to(self.session_dir)
                ),
                progress=progress.to_dict(),
                stop_reason=stop_reason.value if stop_reason else None,
            )
            _atomic_write_json(iteration_dir / "iteration.json", completed.to_dict())

            iterations = list(manifest.iterations)
            iterations[iteration_index] = completed
            session_state = SessionState.COMPLETED if stop_reason else SessionState.ACTIVE
            updated = _replace_session(
                manifest,
                iterations=tuple(iterations),
                state=session_state,
                stop_reason=stop_reason.value if stop_reason else None,
            )
            updated.save(self.session_manifest_path)
            return completed

    def verify(self) -> SessionManifest:
        with self._locked():
            manifest = self.load()
            store = EnvironmentSnapshotStore(manifest.snapshot_store)
            store.verify(manifest.seed_snapshot_id)
            for record in manifest.iterations:
                store.verify(record.environment_snapshot_id)
                iteration_dir = self.session_dir / record.directory
                raw_record = IterationRecord.from_dict(
                    json.loads((iteration_dir / "iteration.json").read_text(encoding="utf-8"))
                )
                if raw_record != record:
                    raise IterationControllerError(
                        f"iteration manifest mismatch for {record.index}"
                    )
                if record.state == IterationState.COMPLETED:
                    if record.observation is None or record.artifact_manifest is None:
                        raise IterationControllerError("completed iteration lacks evidence")
                    IterationObservation.load(self.session_dir / record.observation)
                    _verify_artifact_manifest(
                        self.session_dir / record.artifact_manifest,
                        iteration_dir / "artifacts",
                    )
            return manifest

    def _build_repaired_snapshot(
        self,
        *,
        store: EnvironmentSnapshotStore,
        parent_snapshot_id: str,
        plan_path: Path,
        requirements_path: Path,
        iteration_index: int,
    ) -> tuple[str, bytes]:
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".repair-{iteration_index:04d}.",
                suffix=".tmp",
                dir=self.session_dir,
            )
        )
        try:
            candidate_rootfs = staging / "rootfs"
            store.clone(parent_snapshot_id, candidate_rootfs)
            application_path = staging / "repair_application.json"
            try:
                RepairApplier().apply_file(
                    plan_path=plan_path,
                    requirements_path=requirements_path,
                    rootfs=candidate_rootfs,
                    out_path=application_path,
                    dry_run=False,
                )
            except RepairApplicationError as exc:
                raise IterationControllerError(str(exc)) from exc
            capture = store.capture(candidate_rootfs)
            return (
                capture.manifest.snapshot_id,
                application_path.read_bytes(),
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    def _previous_observation(
        self,
        manifest: SessionManifest,
        iteration_index: int,
    ) -> IterationObservation | None:
        if iteration_index == 0:
            return None
        previous = manifest.iterations[iteration_index - 1]
        if previous.observation is None:
            raise IterationControllerError("previous iteration lacks observation")
        return IterationObservation.load(self.session_dir / previous.observation)

    def _decide_stop_reason(
        self,
        *,
        manifest: SessionManifest,
        iteration_index: int,
        observation: IterationObservation,
    ) -> StopReason | None:
        if observation.goal_reached:
            return StopReason.GOAL_REACHED

        prior: list[IterationObservation] = []
        for record in manifest.iterations[:iteration_index]:
            if record.observation is None:
                continue
            prior.append(IterationObservation.load(self.session_dir / record.observation))

        if prior and observation.state_fingerprint == prior[-1].state_fingerprint:
            return StopReason.FIXED_POINT
        if any(
            observation.state_fingerprint == item.state_fingerprint
            for item in prior[:-1]
        ):
            return StopReason.CYCLE_DETECTED
        if observation.metrics.automatic_candidates == 0:
            return StopReason.NO_AUTOMATIC_REPAIRS
        if iteration_index + 1 >= manifest.max_iterations:
            return StopReason.BUDGET_EXHAUSTED
        return None

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if not self.session_dir.is_dir() or self.session_dir.is_symlink():
            raise IterationControllerError(
                f"session directory does not exist: {self.session_dir}"
            )
        with self.lock_path.open("a+") as stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise IterationControllerError("iteration session is locked") from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _replace_session(
    manifest: SessionManifest,
    *,
    iterations: tuple[IterationRecord, ...] | None = None,
    state: SessionState | None = None,
    stop_reason: str | None = None,
) -> SessionManifest:
    return SessionManifest(
        session_id=manifest.session_id,
        session_dir=manifest.session_dir,
        snapshot_store=manifest.snapshot_store,
        seed_snapshot_id=manifest.seed_snapshot_id,
        max_iterations=manifest.max_iterations,
        state=state or manifest.state,
        stop_reason=stop_reason,
        iterations=iterations if iterations is not None else manifest.iterations,
        created_at_utc=manifest.created_at_utc,
        updated_at_utc=datetime.now(timezone.utc).isoformat(),
    )


def _validate_execution_claim_for_completion(
    iteration_dir: Path,
    *,
    iteration_index: int,
    session_id: str,
) -> None:
    """Reject completion while an integrated runner is still executing.

    Manual/external artifact ingestion remains supported when no claim exists.
    When a PrebuiltRootfsRunner claim exists, it is a synchronization contract:
    the adapter must advance it to ``completing`` before calling the controller.
    """

    claim_path = iteration_dir / "execution_attempt.json"
    if not claim_path.exists() and not claim_path.is_symlink():
        return
    if claim_path.is_symlink() or not claim_path.is_file():
        raise IterationControllerError(
            f"invalid execution claim: {claim_path}"
        )
    try:
        raw = json.loads(claim_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IterationControllerError(
            f"cannot load execution claim: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise IterationControllerError("execution claim must be an object")
    if raw.get("session_id") != session_id:
        raise IterationControllerError("execution claim session mismatch")
    if raw.get("iteration_index") != iteration_index:
        raise IterationControllerError("execution claim iteration mismatch")
    if raw.get("stage") != "completing":
        raise IterationControllerError(
            "iteration execution claim is not ready for completion: "
            f"stage={raw.get('stage')!r}"
        )


def _copy_artifacts(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        directories.sort()
        files.sort()
        relative = root_path.relative_to(source)
        target_root = destination / relative
        for directory in list(directories):
            source_dir = root_path / directory
            if source_dir.is_symlink():
                raise IterationControllerError(
                    f"artifact directory symlink is not allowed: {source_dir}"
                )
            (target_root / directory).mkdir(exist_ok=True)
        for filename in files:
            source_file = root_path / filename
            if source_file.is_symlink() or not source_file.is_file():
                raise IterationControllerError(
                    f"artifact must be a regular file: {source_file}"
                )
            target_file = target_root / filename
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target_file)

    # Promote the two required artifacts to stable top-level names so the next
    # iteration never depends on the external runner's directory layout.
    for filename in ("runtime_requirements.json", "repair_plan.json"):
        matches = [
            path for path in destination.rglob(filename)
            if path.is_file() and not path.is_symlink()
        ]
        if len(matches) != 1:
            raise IterationControllerError(
                f"expected exactly one {filename}, found {len(matches)}"
            )
        top_level = destination / filename
        if matches[0] != top_level:
            shutil.copy2(matches[0], top_level)


def _build_artifact_manifest(artifacts: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(item for item in artifacts.rglob("*") if item.is_file()):
        if path.name == "artifact_manifest.json":
            continue
        files.append(
            {
                "path": path.relative_to(artifacts).as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    digest = hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "bundle_sha256": digest,
        "files": files,
    }


def _verify_artifact_manifest(manifest_path: Path, artifacts: Path) -> None:
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IterationControllerError(f"invalid artifact manifest: {exc}") from exc
    expected = raw.get("bundle_sha256") if isinstance(raw, dict) else None
    actual = _build_artifact_manifest(artifacts).get("bundle_sha256")
    if expected != actual:
        raise IterationControllerError(
            f"artifact bundle digest mismatch: expected {expected}, got {actual}"
        )


def _validate_relative_path(value: str, label: str) -> None:
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise IterationControllerError(
            f"{label} must be a contained relative path"
        )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def _safe_directory_path(path: str | Path, label: str) -> Path:
    value = Path(path).expanduser().resolve(strict=False)
    if value == Path("/"):
        raise IterationControllerError(f"{label} must not be host root /")
    return value


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            temporary = Path(stream.name)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
