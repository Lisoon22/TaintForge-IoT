from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any


class RequirementValidationError(ValueError):
    """Raised when a persisted runtime-requirement report is malformed."""


class RequirementKind(StrEnum):
    FILESYSTEM = "filesystem"
    DEVICE = "device"
    NETWORK = "network"
    LIBRARY = "library"
    SYSCALL = "syscall"
    EXECUTION = "execution"


class RequirementStatus(StrEnum):
    """Whether the current environment already provided the resource."""

    UNMET = "unmet"
    PROVIDED = "provided"
    UNKNOWN = "unknown"


class BlockingAssessment(StrEnum):
    """How strongly observations suggest that the requirement blocks progress."""

    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    UNKNOWN = "unknown"


@dataclass(slots=True, frozen=True)
class RequirementEvidence:
    source: str
    summary: str
    raw: str | None = None
    event_index: int | None = None

    @classmethod
    def from_dict(cls, raw: Any, *, location: str) -> RequirementEvidence:
        value = _require_dict(raw, location)
        source = _require_nonempty_string(value.get("source"), f"{location}.source")
        summary = _require_nonempty_string(
            value.get("summary"),
            f"{location}.summary",
        )
        raw_text = _optional_string(value.get("raw"), f"{location}.raw")
        event_index = _optional_int(
            value.get("event_index"),
            f"{location}.event_index",
        )
        return cls(
            source=source,
            summary=summary,
            raw=raw_text,
            event_index=event_index,
        )


@dataclass(slots=True, frozen=True)
class RuntimeRequirement:
    requirement_id: str
    kind: RequirementKind
    resource: str
    operation: str
    status: RequirementStatus
    blocking: BlockingAssessment
    confidence: float
    repairable: bool
    errno: str | None = None
    evidence: tuple[RequirementEvidence, ...] = ()
    details: tuple[tuple[str, str], ...] = ()

    @property
    def key(self) -> tuple[str, str, str]:
        return self.kind.value, self.operation, self.resource

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "kind": self.kind.value,
            "resource": self.resource,
            "operation": self.operation,
            "status": self.status.value,
            "blocking": self.blocking.value,
            "confidence": self.confidence,
            "repairable": self.repairable,
            "errno": self.errno,
            "evidence": [asdict(item) for item in self.evidence],
            "details": dict(self.details),
        }

    @classmethod
    def from_dict(cls, raw: Any, *, location: str) -> RuntimeRequirement:
        value = _require_dict(raw, location)
        requirement_id = _require_nonempty_string(
            value.get("requirement_id"),
            f"{location}.requirement_id",
        )
        resource = _require_nonempty_string(
            value.get("resource"),
            f"{location}.resource",
        )
        operation = _require_nonempty_string(
            value.get("operation"),
            f"{location}.operation",
        )
        kind = _parse_enum(
            RequirementKind,
            value.get("kind"),
            f"{location}.kind",
        )
        status = _parse_enum(
            RequirementStatus,
            value.get("status"),
            f"{location}.status",
        )
        blocking = _parse_enum(
            BlockingAssessment,
            value.get("blocking"),
            f"{location}.blocking",
        )
        confidence = _require_float(
            value.get("confidence"),
            f"{location}.confidence",
        )
        if not 0.0 <= confidence <= 1.0:
            raise RequirementValidationError(
                f"{location}.confidence must be between 0.0 and 1.0"
            )
        repairable = _require_bool(
            value.get("repairable"),
            f"{location}.repairable",
        )
        errno = _optional_string(value.get("errno"), f"{location}.errno")

        evidence_raw = value.get("evidence", [])
        if not isinstance(evidence_raw, list):
            raise RequirementValidationError(
                f"{location}.evidence must be a JSON array"
            )
        evidence = tuple(
            RequirementEvidence.from_dict(
                item,
                location=f"{location}.evidence[{index}]",
            )
            for index, item in enumerate(evidence_raw)
        )

        details_raw = value.get("details", {})
        details_dict = _require_dict(details_raw, f"{location}.details")
        details: list[tuple[str, str]] = []
        for key, detail_value in sorted(details_dict.items()):
            if not isinstance(key, str) or not key:
                raise RequirementValidationError(
                    f"{location}.details keys must be non-empty strings"
                )
            if isinstance(detail_value, bool):
                rendered = "true" if detail_value else "false"
            elif detail_value is None:
                rendered = "null"
            elif isinstance(detail_value, (str, int, float)):
                rendered = str(detail_value)
            else:
                raise RequirementValidationError(
                    f"{location}.details[{key!r}] must be a scalar value"
                )
            details.append((key, rendered))

        expected_id = make_requirement_id(kind, operation, resource)
        if requirement_id != expected_id:
            raise RequirementValidationError(
                f"{location}.requirement_id mismatch: expected {expected_id}, "
                f"got {requirement_id}"
            )

        return cls(
            requirement_id=requirement_id,
            kind=kind,
            resource=resource,
            operation=operation,
            status=status,
            blocking=blocking,
            confidence=confidence,
            repairable=repairable,
            errno=errno,
            evidence=evidence,
            details=tuple(details),
        )


@dataclass(slots=True, frozen=True)
class RequirementReport:
    requirements: tuple[RuntimeRequirement, ...]
    warnings: tuple[str, ...] = ()
    schema_version: int = 1
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def summary(self) -> dict[str, Any]:
        by_kind: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_blocking: dict[str, int] = {}

        for requirement in self.requirements:
            by_kind[requirement.kind.value] = (
                by_kind.get(requirement.kind.value, 0) + 1
            )
            by_status[requirement.status.value] = (
                by_status.get(requirement.status.value, 0) + 1
            )
            by_blocking[requirement.blocking.value] = (
                by_blocking.get(requirement.blocking.value, 0) + 1
            )

        return {
            "requirements_total": len(self.requirements),
            "repairable_total": sum(
                1 for requirement in self.requirements if requirement.repairable
            ),
            "by_kind": dict(sorted(by_kind.items())),
            "by_status": dict(sorted(by_status.items())),
            "by_blocking": dict(sorted(by_blocking.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at_utc": self.generated_at_utc,
            "summary": self.summary(),
            "warnings": list(self.warnings),
            "requirements": [
                requirement.to_dict() for requirement in self.requirements
            ],
        }

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def from_dict(cls, raw: Any) -> RequirementReport:
        value = _require_dict(raw, "requirements report")
        schema_version = _require_int(
            value.get("schema_version"),
            "requirements report.schema_version",
        )
        if schema_version != 1:
            raise RequirementValidationError(
                "unsupported runtime requirements schema_version: "
                f"{schema_version}"
            )

        requirements_raw = value.get("requirements")
        if not isinstance(requirements_raw, list):
            raise RequirementValidationError(
                "requirements report.requirements must be a JSON array"
            )
        requirements = tuple(
            RuntimeRequirement.from_dict(
                item,
                location=f"requirements report.requirements[{index}]",
            )
            for index, item in enumerate(requirements_raw)
        )

        keys = [requirement.key for requirement in requirements]
        if len(keys) != len(set(keys)):
            raise RequirementValidationError(
                "requirements report contains duplicate requirement keys"
            )

        warnings_raw = value.get("warnings", [])
        if not isinstance(warnings_raw, list) or not all(
            isinstance(item, str) for item in warnings_raw
        ):
            raise RequirementValidationError(
                "requirements report.warnings must be an array of strings"
            )

        generated_at = _require_nonempty_string(
            value.get("generated_at_utc"),
            "requirements report.generated_at_utc",
        )
        return cls(
            requirements=requirements,
            warnings=tuple(warnings_raw),
            schema_version=schema_version,
            generated_at_utc=generated_at,
        )

    @classmethod
    def load(cls, path: str | Path) -> RequirementReport:
        path = Path(path)
        if not path.exists():
            raise RequirementValidationError(
                f"runtime requirements file does not exist: {path}"
            )
        if not path.is_file():
            raise RequirementValidationError(
                f"runtime requirements path is not a file: {path}"
            )
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RequirementValidationError(
                f"invalid JSON in runtime requirements file {path}: {exc}"
            ) from exc
        return cls.from_dict(raw)


def make_requirement_id(
    kind: RequirementKind,
    operation: str,
    resource: str,
) -> str:
    canonical = f"{kind.value}\0{operation}\0{resource}".encode("utf-8")
    return "req_" + hashlib.sha256(canonical).hexdigest()[:16]


def _require_dict(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RequirementValidationError(f"{location} must be a JSON object")
    return value


def _require_nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise RequirementValidationError(
            f"{location} must be a non-empty string"
        )
    return value


def _optional_string(value: Any, location: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RequirementValidationError(f"{location} must be a string or null")
    return value


def _require_bool(value: Any, location: str) -> bool:
    if not isinstance(value, bool):
        raise RequirementValidationError(f"{location} must be a boolean")
    return value


def _require_float(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RequirementValidationError(f"{location} must be a number")
    return float(value)


def _require_int(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RequirementValidationError(f"{location} must be an integer")
    return value


def _optional_int(value: Any, location: str) -> int | None:
    if value is None:
        return None
    return _require_int(value, location)


def _parse_enum(enum_type: type[Any], value: Any, location: str) -> Any:
    if not isinstance(value, str):
        raise RequirementValidationError(f"{location} must be a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_type)
        raise RequirementValidationError(
            f"{location} must be one of: {allowed}"
        ) from exc
