from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any


ATTEMPT_SCHEMA_VERSION = 1
ATTEMPT_CONTRACT_VERSION = 1
ATTEMPT_RESULT_VERSION = 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


class AttemptValidationError(RuntimeError):
    """Raised when an execution-attempt contract cannot be trusted."""


class RunPurpose(StrEnum):
    DISCOVERY = "discovery"
    FUZZING = "fuzzing"
    RECONSTRUCTION = "reconstruction"


class ExecutionStage(StrEnum):
    STATIC_PREFLIGHT = "static_preflight"
    PRE_OEP_DISCOVERY = "pre_oep_discovery"
    OEP_CANDIDATE = "oep_candidate"
    OEP_VALIDATION = "oep_validation"
    POST_OEP_STABILIZATION = "post_oep_stabilization"
    BOUNDARY_DISCOVERY = "boundary_discovery"
    BOUNDARY_READY = "boundary_ready"
    FUZZING = "fuzzing"
    RECONSTRUCTION = "reconstruction"


class AttemptOutcome(StrEnum):
    GOAL_REACHED = "goal_reached"
    REPAIR_REQUIRED = "repair_required"
    EXITED = "exited"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    UNSUPPORTED_DEPENDENCY = "unsupported_dependency"
    ISOLATION_VIOLATION = "isolation_violation"
    BACKEND_INCOMPATIBLE = "backend_incompatible"
    EXECUTION_ERROR = "execution_error"


_ALLOWED_STAGE_TRANSITIONS: dict[ExecutionStage, frozenset[ExecutionStage]] = {
    ExecutionStage.STATIC_PREFLIGHT: frozenset(
        {
            ExecutionStage.PRE_OEP_DISCOVERY,
            ExecutionStage.RECONSTRUCTION,
        }
    ),
    ExecutionStage.PRE_OEP_DISCOVERY: frozenset(
        {ExecutionStage.OEP_CANDIDATE}
    ),
    ExecutionStage.OEP_CANDIDATE: frozenset(
        {
            ExecutionStage.PRE_OEP_DISCOVERY,
            ExecutionStage.OEP_VALIDATION,
        }
    ),
    ExecutionStage.OEP_VALIDATION: frozenset(
        {
            ExecutionStage.PRE_OEP_DISCOVERY,
            ExecutionStage.OEP_CANDIDATE,
            ExecutionStage.POST_OEP_STABILIZATION,
        }
    ),
    ExecutionStage.POST_OEP_STABILIZATION: frozenset(
        {
            ExecutionStage.OEP_CANDIDATE,
            ExecutionStage.BOUNDARY_DISCOVERY,
        }
    ),
    ExecutionStage.BOUNDARY_DISCOVERY: frozenset(
        {
            ExecutionStage.POST_OEP_STABILIZATION,
            ExecutionStage.BOUNDARY_READY,
        }
    ),
    ExecutionStage.BOUNDARY_READY: frozenset(
        {ExecutionStage.FUZZING, ExecutionStage.RECONSTRUCTION}
    ),
    ExecutionStage.FUZZING: frozenset({ExecutionStage.BOUNDARY_READY}),
    ExecutionStage.RECONSTRUCTION: frozenset(),
}


@dataclass(slots=True, frozen=True)
class AttemptContract:
    attempt_id: str
    attempt_index: int
    purpose: RunPurpose
    sample_sha256: str
    packed_binary_sha256: str
    environment_manifest_id: str
    environment_manifest_version: int
    goal_id: str
    initial_stage: ExecutionStage
    schema_version: int = ATTEMPT_SCHEMA_VERSION
    contract_version: int = ATTEMPT_CONTRACT_VERSION
    created_at_utc: str = field(default_factory=lambda: _utc_now())

    def __post_init__(self) -> None:
        if self.schema_version != ATTEMPT_SCHEMA_VERSION:
            raise AttemptValidationError("unsupported attempt schema_version")
        if self.contract_version != ATTEMPT_CONTRACT_VERSION:
            raise AttemptValidationError("unsupported attempt contract_version")
        if not _IDENTIFIER_RE.fullmatch(self.attempt_id):
            raise AttemptValidationError("attempt_id is invalid")
        if self.attempt_index < 0:
            raise AttemptValidationError("attempt_index must be non-negative")
        _validate_sha256(self.sample_sha256, "sample_sha256")
        _validate_sha256(self.packed_binary_sha256, "packed_binary_sha256")
        if not _IDENTIFIER_RE.fullmatch(self.environment_manifest_id):
            raise AttemptValidationError("environment_manifest_id is invalid")
        if self.environment_manifest_version < 0:
            raise AttemptValidationError(
                "environment_manifest_version must be non-negative"
            )
        if not _IDENTIFIER_RE.fullmatch(self.goal_id):
            raise AttemptValidationError("goal_id is invalid")
        _validate_timestamp(self.created_at_utc, "created_at_utc")
        if self.purpose == RunPurpose.DISCOVERY and self.initial_stage not in {
            ExecutionStage.STATIC_PREFLIGHT,
            ExecutionStage.PRE_OEP_DISCOVERY,
        }:
            raise AttemptValidationError(
                "discovery attempts must start at static preflight or pre-OEP discovery"
            )
        if (
            self.purpose == RunPurpose.FUZZING
            and self.initial_stage != ExecutionStage.BOUNDARY_READY
        ):
            raise AttemptValidationError(
                "fuzzing attempts must start at a validated boundary"
            )
        if (
            self.purpose == RunPurpose.RECONSTRUCTION
            and self.initial_stage != ExecutionStage.RECONSTRUCTION
        ):
            raise AttemptValidationError(
                "reconstruction attempts must start in reconstruction stage"
            )

    @classmethod
    def create(
        cls,
        *,
        attempt_index: int,
        purpose: RunPurpose,
        sample_sha256: str,
        packed_binary_sha256: str,
        environment_manifest_id: str,
        environment_manifest_version: int,
        goal_id: str,
        initial_stage: ExecutionStage,
    ) -> AttemptContract:
        attempt_id = make_attempt_id(
            attempt_index=attempt_index,
            purpose=purpose,
            sample_sha256=sample_sha256,
            environment_manifest_id=environment_manifest_id,
        )
        return cls(
            attempt_id=attempt_id,
            attempt_index=attempt_index,
            purpose=purpose,
            sample_sha256=sample_sha256,
            packed_binary_sha256=packed_binary_sha256,
            environment_manifest_id=environment_manifest_id,
            environment_manifest_version=environment_manifest_version,
            goal_id=goal_id,
            initial_stage=initial_stage,
        )

    def identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "contract_version": self.contract_version,
            "attempt_id": self.attempt_id,
            "attempt_index": self.attempt_index,
            "purpose": self.purpose.value,
            "sample_sha256": self.sample_sha256,
            "packed_binary_sha256": self.packed_binary_sha256,
            "environment_manifest_id": self.environment_manifest_id,
            "environment_manifest_version": self.environment_manifest_version,
            "goal_id": self.goal_id,
            "initial_stage": self.initial_stage.value,
        }

    @property
    def contract_sha256(self) -> str:
        return _canonical_sha256(self.identity_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.identity_dict(),
            "created_at_utc": self.created_at_utc,
            "contract_sha256": self.contract_sha256,
        }

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> AttemptContract:
        value = _require_dict(raw, "attempt contract")
        try:
            contract = cls(
                schema_version=_require_int(
                    value.get("schema_version"), "schema_version"
                ),
                contract_version=_require_int(
                    value.get("contract_version"), "contract_version"
                ),
                attempt_id=_require_string(value.get("attempt_id"), "attempt_id"),
                attempt_index=_require_int(
                    value.get("attempt_index"), "attempt_index"
                ),
                purpose=RunPurpose(value.get("purpose")),
                sample_sha256=_require_string(
                    value.get("sample_sha256"), "sample_sha256"
                ),
                packed_binary_sha256=_require_string(
                    value.get("packed_binary_sha256"), "packed_binary_sha256"
                ),
                environment_manifest_id=_require_string(
                    value.get("environment_manifest_id"),
                    "environment_manifest_id",
                ),
                environment_manifest_version=_require_int(
                    value.get("environment_manifest_version"),
                    "environment_manifest_version",
                ),
                goal_id=_require_string(value.get("goal_id"), "goal_id"),
                initial_stage=ExecutionStage(value.get("initial_stage")),
                created_at_utc=_require_string(
                    value.get("created_at_utc"), "created_at_utc"
                ),
            )
        except ValueError as exc:
            raise AttemptValidationError(
                "attempt contract contains an unsupported enum value"
            ) from exc
        expected = _require_string(
            value.get("contract_sha256"), "contract_sha256"
        )
        _validate_sha256(expected, "contract_sha256")
        if expected != contract.contract_sha256:
            raise AttemptValidationError("attempt contract digest mismatch")
        return contract

    @classmethod
    def load(cls, path: str | Path) -> AttemptContract:
        return cls.from_dict(_load_json(path, "attempt contract"))


@dataclass(slots=True, frozen=True)
class StageTransition:
    sequence: int
    from_stage: ExecutionStage
    to_stage: ExecutionStage
    reason: str
    evidence_event_id: str
    timestamp_utc: str = field(default_factory=lambda: _utc_now())

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise AttemptValidationError("stage transition sequence is invalid")
        if self.to_stage not in _ALLOWED_STAGE_TRANSITIONS[self.from_stage]:
            raise AttemptValidationError(
                "invalid execution-stage transition: "
                f"{self.from_stage.value} -> {self.to_stage.value}"
            )
        if not self.reason.strip():
            raise AttemptValidationError("stage transition reason is required")
        if not _IDENTIFIER_RE.fullmatch(self.evidence_event_id):
            raise AttemptValidationError("stage transition evidence_event_id is invalid")
        _validate_timestamp(self.timestamp_utc, "stage transition timestamp")

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "from_stage": self.from_stage.value,
            "to_stage": self.to_stage.value,
            "reason": self.reason,
            "evidence_event_id": self.evidence_event_id,
            "timestamp_utc": self.timestamp_utc,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StageTransition:
        value = _require_dict(raw, "stage transition")
        try:
            return cls(
                sequence=_require_int(value.get("sequence"), "sequence"),
                from_stage=ExecutionStage(value.get("from_stage")),
                to_stage=ExecutionStage(value.get("to_stage")),
                reason=_require_string(value.get("reason"), "reason"),
                evidence_event_id=_require_string(
                    value.get("evidence_event_id"), "evidence_event_id"
                ),
                timestamp_utc=_require_string(
                    value.get("timestamp_utc"), "timestamp_utc"
                ),
            )
        except ValueError as exc:
            raise AttemptValidationError(
                "stage transition contains an unsupported stage"
            ) from exc


@dataclass(slots=True, frozen=True)
class AttemptProgress:
    goal_reached: bool
    oracle_reason: str | None
    guest_events_total: int
    coverage_edges: int | None = None
    observation_sha256: str | None = None

    def __post_init__(self) -> None:
        if self.guest_events_total < 0:
            raise AttemptValidationError("guest_events_total must be non-negative")
        if self.coverage_edges is not None and self.coverage_edges < 0:
            raise AttemptValidationError("coverage_edges must be non-negative")
        if self.goal_reached and not self.oracle_reason:
            raise AttemptValidationError(
                "goal_reached progress requires an oracle_reason"
            )
        if self.observation_sha256 is not None:
            _validate_sha256(self.observation_sha256, "observation_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal_reached": self.goal_reached,
            "oracle_reason": self.oracle_reason,
            "guest_events_total": self.guest_events_total,
            "coverage_edges": self.coverage_edges,
            "observation_sha256": self.observation_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> AttemptProgress:
        value = _require_dict(raw, "attempt progress")
        goal_reached = value.get("goal_reached")
        if not isinstance(goal_reached, bool):
            raise AttemptValidationError("goal_reached must be a boolean")
        coverage_edges = value.get("coverage_edges")
        if coverage_edges is not None:
            coverage_edges = _require_int(coverage_edges, "coverage_edges")
        observation_sha256 = value.get("observation_sha256")
        if observation_sha256 is not None:
            observation_sha256 = _require_string(
                observation_sha256, "observation_sha256"
            )
        oracle_reason = value.get("oracle_reason")
        if oracle_reason is not None:
            oracle_reason = _require_string(oracle_reason, "oracle_reason")
        return cls(
            goal_reached=goal_reached,
            oracle_reason=oracle_reason,
            guest_events_total=_require_int(
                value.get("guest_events_total"), "guest_events_total"
            ),
            coverage_edges=coverage_edges,
            observation_sha256=observation_sha256,
        )


@dataclass(slots=True, frozen=True)
class AttemptResult:
    attempt_id: str
    contract_sha256: str
    outcome: AttemptOutcome
    initial_stage: ExecutionStage
    final_stage: ExecutionStage
    progress: AttemptProgress
    transitions: tuple[StageTransition, ...] = ()
    failure_fingerprint: str | None = None
    started_at_utc: str = field(default_factory=lambda: _utc_now())
    finished_at_utc: str = field(default_factory=lambda: _utc_now())
    schema_version: int = ATTEMPT_SCHEMA_VERSION
    result_version: int = ATTEMPT_RESULT_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ATTEMPT_SCHEMA_VERSION:
            raise AttemptValidationError("unsupported attempt result schema_version")
        if self.result_version != ATTEMPT_RESULT_VERSION:
            raise AttemptValidationError("unsupported attempt result_version")
        if not _IDENTIFIER_RE.fullmatch(self.attempt_id):
            raise AttemptValidationError("attempt result attempt_id is invalid")
        _validate_sha256(self.contract_sha256, "contract_sha256")
        started = _parse_timestamp(self.started_at_utc, "started_at_utc")
        finished = _parse_timestamp(self.finished_at_utc, "finished_at_utc")
        if finished < started:
            raise AttemptValidationError("attempt result finishes before it starts")
        self._validate_transition_chain()
        failure_outcomes = {
            AttemptOutcome.REPAIR_REQUIRED,
            AttemptOutcome.TIMED_OUT,
            AttemptOutcome.CRASHED,
            AttemptOutcome.UNSUPPORTED_DEPENDENCY,
            AttemptOutcome.ISOLATION_VIOLATION,
            AttemptOutcome.BACKEND_INCOMPATIBLE,
            AttemptOutcome.EXECUTION_ERROR,
        }
        if self.outcome in failure_outcomes:
            if self.failure_fingerprint is None:
                raise AttemptValidationError(
                    f"{self.outcome.value} requires a failure fingerprint"
                )
            _validate_sha256(self.failure_fingerprint, "failure_fingerprint")
        elif self.failure_fingerprint is not None:
            _validate_sha256(self.failure_fingerprint, "failure_fingerprint")
        if self.outcome == AttemptOutcome.GOAL_REACHED:
            if not self.progress.goal_reached:
                raise AttemptValidationError(
                    "goal_reached outcome requires a successful progress oracle"
                )
        elif self.progress.goal_reached:
            raise AttemptValidationError(
                "only goal_reached outcome may carry goal_reached progress"
            )

    def _validate_transition_chain(self) -> None:
        expected_stage = self.initial_stage
        for sequence, transition in enumerate(self.transitions):
            if transition.sequence != sequence:
                raise AttemptValidationError(
                    "stage transition sequences must be contiguous"
                )
            if transition.from_stage != expected_stage:
                raise AttemptValidationError(
                    "stage transition chain does not continue from prior stage"
                )
            expected_stage = transition.to_stage
        if expected_stage != self.final_stage:
            raise AttemptValidationError(
                "attempt final_stage does not match its transition chain"
            )

    def identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "result_version": self.result_version,
            "attempt_id": self.attempt_id,
            "contract_sha256": self.contract_sha256,
            "started_at_utc": self.started_at_utc,
            "finished_at_utc": self.finished_at_utc,
            "outcome": self.outcome.value,
            "initial_stage": self.initial_stage.value,
            "final_stage": self.final_stage.value,
            "failure_fingerprint": self.failure_fingerprint,
            "progress": self.progress.to_dict(),
            "stage_transitions": [item.to_dict() for item in self.transitions],
        }

    @property
    def result_sha256(self) -> str:
        return _canonical_sha256(self.identity_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.identity_dict(), "result_sha256": self.result_sha256}

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> AttemptResult:
        value = _require_dict(raw, "attempt result")
        transitions_raw = value.get("stage_transitions")
        if not isinstance(transitions_raw, list):
            raise AttemptValidationError("stage_transitions must be a JSON array")
        failure_fingerprint = value.get("failure_fingerprint")
        if failure_fingerprint is not None:
            failure_fingerprint = _require_string(
                failure_fingerprint, "failure_fingerprint"
            )
        try:
            result = cls(
                schema_version=_require_int(
                    value.get("schema_version"), "schema_version"
                ),
                result_version=_require_int(
                    value.get("result_version"), "result_version"
                ),
                attempt_id=_require_string(value.get("attempt_id"), "attempt_id"),
                contract_sha256=_require_string(
                    value.get("contract_sha256"), "contract_sha256"
                ),
                started_at_utc=_require_string(
                    value.get("started_at_utc"), "started_at_utc"
                ),
                finished_at_utc=_require_string(
                    value.get("finished_at_utc"), "finished_at_utc"
                ),
                outcome=AttemptOutcome(value.get("outcome")),
                initial_stage=ExecutionStage(value.get("initial_stage")),
                final_stage=ExecutionStage(value.get("final_stage")),
                failure_fingerprint=failure_fingerprint,
                progress=AttemptProgress.from_dict(value.get("progress")),
                transitions=tuple(
                    StageTransition.from_dict(item) for item in transitions_raw
                ),
            )
        except ValueError as exc:
            raise AttemptValidationError(
                "attempt result contains an unsupported enum value"
            ) from exc
        expected = _require_string(
            value.get("result_sha256"), "result_sha256"
        )
        _validate_sha256(expected, "result_sha256")
        if expected != result.result_sha256:
            raise AttemptValidationError("attempt result digest mismatch")
        return result

    @classmethod
    def load(cls, path: str | Path) -> AttemptResult:
        return cls.from_dict(_load_json(path, "attempt result"))


def make_attempt_id(
    *,
    attempt_index: int,
    purpose: RunPurpose,
    sample_sha256: str,
    environment_manifest_id: str,
) -> str:
    if attempt_index < 0:
        raise AttemptValidationError("attempt_index must be non-negative")
    _validate_sha256(sample_sha256, "sample_sha256")
    if not _IDENTIFIER_RE.fullmatch(environment_manifest_id):
        raise AttemptValidationError("environment_manifest_id is invalid")
    digest = _canonical_sha256(
        {
            "attempt_index": attempt_index,
            "purpose": purpose.value,
            "sample_sha256": sample_sha256,
            "environment_manifest_id": environment_manifest_id,
        }
    )
    return f"attempt-{attempt_index:03d}-{digest[:12]}"


def make_failure_fingerprint(
    *,
    outcome: AttemptOutcome,
    stage: ExecutionStage,
    exit_code: int | None = None,
    signal: str | None = None,
    error_code: str | None = None,
    blocking_resource: str | None = None,
) -> str:
    if outcome == AttemptOutcome.GOAL_REACHED:
        raise AttemptValidationError(
            "goal_reached cannot be used to build a failure fingerprint"
        )
    payload = {
        "outcome": outcome.value,
        "stage": stage.value,
        "exit_code": exit_code,
        "signal": signal,
        "error_code": error_code,
        "blocking_resource": blocking_resource,
    }
    return _canonical_sha256(payload)


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
        raise AttemptValidationError(f"{label} must be a lowercase SHA-256 digest")


def _validate_timestamp(value: str, label: str) -> None:
    _parse_timestamp(value, label)


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise AttemptValidationError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AttemptValidationError(f"{label} must include a timezone")
    return parsed


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttemptValidationError(f"{label} must be a JSON object")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AttemptValidationError(f"{label} must be a non-empty string")
    return value


def _require_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AttemptValidationError(f"{label} must be an integer")
    return value


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise AttemptValidationError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AttemptValidationError(f"invalid {label} JSON: {exc}") from exc
    return _require_dict(raw, label)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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
        os.replace(temporary, path)
        os.chmod(path, 0o644)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
