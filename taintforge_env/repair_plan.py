from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any


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
                1 for decision in self.decisions if decision.automatic_allowed
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
