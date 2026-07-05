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


class RepairPlanValidationError(ValueError):
    """Raised when a persisted repair plan is malformed or inconsistent."""


class RepairDisposition(StrEnum):
    AUTO_CANDIDATE = "auto_candidate"
    REVIEW_REQUIRED = "review_required"
    MANUAL_ANALYSIS = "manual_analysis"
    NOT_REQUIRED = "not_required"


class RepairPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class RepairRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RepairActionKind(StrEnum):
    NONE = "none"
    CREATE_DIRECTORY = "create_directory"
    PROVIDE_FILE = "provide_file"
    ADJUST_PATH_ACCESS = "adjust_path_access"
    MAKE_PATH_WRITABLE = "make_path_writable"
    REPAIR_PATH_LAYOUT = "repair_path_layout"
    PROVIDE_DEVICE_BACKEND = "provide_device_backend"
    CONFIGURE_TCP_SERVICE = "configure_tcp_service"
    CONFIGURE_UDP_SERVICE = "configure_udp_service"
    RESOLVE_LIBRARY = "resolve_library"
    PROVIDE_INTERPRETER = "provide_interpreter"
    PROVIDE_EXECUTABLE = "provide_executable"


@dataclass(slots=True, frozen=True)
class RepairDecision:
    decision_id: str
    requirement_id: str
    requirement_kind: str
    resource: str
    operation: str
    action: RepairActionKind
    disposition: RepairDisposition
    priority: RepairPriority
    risk: RepairRisk
    automatic_allowed: bool
    reason: str
    parameters: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "requirement_id": self.requirement_id,
            "requirement_kind": self.requirement_kind,
            "resource": self.resource,
            "operation": self.operation,
            "action": self.action.value,
            "disposition": self.disposition.value,
            "priority": self.priority.value,
            "risk": self.risk.value,
            "automatic_allowed": self.automatic_allowed,
            "reason": self.reason,
            "parameters": dict(self.parameters),
        }

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        location: str,
    ) -> RepairDecision:
        value = _require_dict(raw, location)

        decision_id = _require_nonempty_string(
            value.get("decision_id"),
            f"{location}.decision_id",
        )
        requirement_id = _require_nonempty_string(
            value.get("requirement_id"),
            f"{location}.requirement_id",
        )
        requirement_kind = _require_nonempty_string(
            value.get("requirement_kind"),
            f"{location}.requirement_kind",
        )
        resource = _require_nonempty_string(
            value.get("resource"),
            f"{location}.resource",
        )
        operation = _require_nonempty_string(
            value.get("operation"),
            f"{location}.operation",
        )
        action = _parse_enum(
            RepairActionKind,
            value.get("action"),
            f"{location}.action",
        )
        disposition = _parse_enum(
            RepairDisposition,
            value.get("disposition"),
            f"{location}.disposition",
        )
        priority = _parse_enum(
            RepairPriority,
            value.get("priority"),
            f"{location}.priority",
        )
        risk = _parse_enum(
            RepairRisk,
            value.get("risk"),
            f"{location}.risk",
        )
        automatic_allowed = _require_bool(
            value.get("automatic_allowed"),
            f"{location}.automatic_allowed",
        )
        reason = _require_nonempty_string(
            value.get("reason"),
            f"{location}.reason",
        )

        parameters_raw = _require_dict(
            value.get("parameters", {}),
            f"{location}.parameters",
        )
        parameters: list[tuple[str, Any]] = []
        for key, parameter_value in sorted(parameters_raw.items()):
            if not isinstance(key, str) or not key:
                raise RepairPlanValidationError(
                    f"{location}.parameters keys must be non-empty strings"
                )
            _validate_json_value(
                parameter_value,
                f"{location}.parameters[{key!r}]",
            )
            parameters.append((key, parameter_value))

        if automatic_allowed and disposition != RepairDisposition.AUTO_CANDIDATE:
            raise RepairPlanValidationError(
                f"{location}.automatic_allowed requires "
                "disposition=auto_candidate"
            )

        if automatic_allowed and action == RepairActionKind.NONE:
            raise RepairPlanValidationError(
                f"{location}.automatic_allowed cannot use action=none"
            )

        expected_id = make_decision_id(
            requirement_id,
            action,
            disposition,
            resource,
        )
        if decision_id != expected_id:
            raise RepairPlanValidationError(
                f"{location}.decision_id mismatch: expected {expected_id}, "
                f"got {decision_id}"
            )

        return cls(
            decision_id=decision_id,
            requirement_id=requirement_id,
            requirement_kind=requirement_kind,
            resource=resource,
            operation=operation,
            action=action,
            disposition=disposition,
            priority=priority,
            risk=risk,
            automatic_allowed=automatic_allowed,
            reason=reason,
            parameters=tuple(parameters),
        )


@dataclass(slots=True, frozen=True)
class RepairPlan:
    source_requirements: str
    source_sha256: str
    decisions: tuple[RepairDecision, ...]
    warnings: tuple[str, ...] = ()
    schema_version: int = 1
    planner_version: int = 1
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def summary(self) -> dict[str, Any]:
        by_disposition: dict[str, int] = {}
        by_action: dict[str, int] = {}
        by_priority: dict[str, int] = {}

        for decision in self.decisions:
            by_disposition[decision.disposition.value] = (
                by_disposition.get(decision.disposition.value, 0) + 1
            )
            by_action[decision.action.value] = (
                by_action.get(decision.action.value, 0) + 1
            )
            by_priority[decision.priority.value] = (
                by_priority.get(decision.priority.value, 0) + 1
            )

        return {
            "decisions_total": len(self.decisions),
            "automatic_candidates": sum(
                1
                for decision in self.decisions
                if decision.automatic_allowed
            ),
            "by_disposition": dict(sorted(by_disposition.items())),
            "by_action": dict(sorted(by_action.items())),
            "by_priority": dict(sorted(by_priority.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "planner_version": self.planner_version,
            "generated_at_utc": self.generated_at_utc,
            "source_requirements": self.source_requirements,
            "source_sha256": self.source_sha256,
            "summary": self.summary(),
            "warnings": list(self.warnings),
            "decisions": [decision.to_dict() for decision in self.decisions],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> RepairPlan:
        value = _require_dict(raw, "repair plan")

        schema_version = _require_int(
            value.get("schema_version"),
            "repair plan.schema_version",
        )
        if schema_version != 1:
            raise RepairPlanValidationError(
                "unsupported repair plan schema_version: "
                f"{schema_version}"
            )

        planner_version = _require_int(
            value.get("planner_version"),
            "repair plan.planner_version",
        )
        if planner_version != 1:
            raise RepairPlanValidationError(
                "unsupported repair plan planner_version: "
                f"{planner_version}"
            )

        generated_at_utc = _require_nonempty_string(
            value.get("generated_at_utc"),
            "repair plan.generated_at_utc",
        )
        source_requirements = _require_nonempty_string(
            value.get("source_requirements"),
            "repair plan.source_requirements",
        )
        source_sha256 = _require_nonempty_string(
            value.get("source_sha256"),
            "repair plan.source_sha256",
        )
        if not re.fullmatch(r"[0-9a-f]{64}", source_sha256):
            raise RepairPlanValidationError(
                "repair plan.source_sha256 must be a lowercase SHA-256 hex digest"
            )

        decisions_raw = value.get("decisions")
        if not isinstance(decisions_raw, list):
            raise RepairPlanValidationError(
                "repair plan.decisions must be a JSON array"
            )

        decisions = tuple(
            RepairDecision.from_dict(
                item,
                location=f"repair plan.decisions[{index}]",
            )
            for index, item in enumerate(decisions_raw)
        )

        decision_ids = [decision.decision_id for decision in decisions]
        if len(decision_ids) != len(set(decision_ids)):
            raise RepairPlanValidationError(
                "repair plan contains duplicate decision_id values"
            )

        requirement_ids = [decision.requirement_id for decision in decisions]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise RepairPlanValidationError(
                "repair plan contains multiple decisions for one requirement_id"
            )

        warnings_raw = value.get("warnings", [])
        if not isinstance(warnings_raw, list) or not all(
            isinstance(item, str) for item in warnings_raw
        ):
            raise RepairPlanValidationError(
                "repair plan.warnings must be an array of strings"
            )

        return cls(
            source_requirements=source_requirements,
            source_sha256=source_sha256,
            decisions=decisions,
            warnings=tuple(warnings_raw),
            schema_version=schema_version,
            planner_version=planner_version,
            generated_at_utc=generated_at_utc,
        )

    @classmethod
    def load(cls, path: str | Path) -> RepairPlan:
        path = Path(path)
        if not path.exists():
            raise RepairPlanValidationError(
                f"repair plan file does not exist: {path}"
            )
        if not path.is_file():
            raise RepairPlanValidationError(
                f"repair plan path is not a file: {path}"
            )

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise RepairPlanValidationError(
                f"cannot read repair plan {path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise RepairPlanValidationError(
                f"invalid JSON in repair plan {path}: {exc}"
            ) from exc

        return cls.from_dict(raw)

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(
            self.to_dict(),
            indent=2,
            ensure_ascii=False,
        ) + "\n"

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


def make_decision_id(
    requirement_id: str,
    action: RepairActionKind,
    disposition: RepairDisposition,
    resource: str,
) -> str:
    canonical = (
        f"{requirement_id}\0{action.value}\0{disposition.value}\0{resource}"
    ).encode("utf-8")
    return "repair_" + hashlib.sha256(canonical).hexdigest()[:16]


def _require_dict(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RepairPlanValidationError(f"{location} must be a JSON object")
    return value


def _require_nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise RepairPlanValidationError(
            f"{location} must be a non-empty string"
        )
    return value


def _require_bool(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise RepairPlanValidationError(f"{location} must be a boolean")
    return value


def _require_int(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RepairPlanValidationError(f"{location} must be an integer")
    return value


def _parse_enum(
    enum_type: type[Any],
    value: Any,
    location: str,
) -> Any:
    if not isinstance(value, str):
        raise RepairPlanValidationError(f"{location} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise RepairPlanValidationError(
            f"{location} must be one of: {allowed}"
        ) from exc


def _validate_json_value(value: Any, location: str) -> None:
    if value is None or isinstance(value, (str, int, float, bool)):
        return

    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{location}[{index}]")
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RepairPlanValidationError(
                    f"{location} object keys must be strings"
                )
            _validate_json_value(item, f"{location}[{key!r}]")
        return

    raise RepairPlanValidationError(
        f"{location} must contain only JSON-compatible values"
    )
