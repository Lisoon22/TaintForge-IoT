from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .observations import ObservationLoadError, load_observation_bundle
from .requirement_extractor import RequirementExtractor
from .requirements import RequirementReport
from .rootfs_diff import (
    RootfsDiffError,
    SnapshotOptions,
    diff_snapshots,
    load_json,
    save_json,
    snapshot_rootfs,
)


class RuntimeObserverError(RuntimeError):
    """Raised when a runtime observation lifecycle becomes inconsistent."""


@dataclass(slots=True, frozen=True)
class RuntimeObservationPaths:
    run_dir: Path
    config_dir: Path
    before_snapshot: Path
    after_snapshot: Path
    rootfs_diff: Path
    requirements: Path
    lifecycle_state: Path
    lifecycle_error: Path

    @classmethod
    def from_run_dir(cls, run_dir: str | Path) -> RuntimeObservationPaths:
        run_dir = Path(run_dir).resolve()
        config_dir = run_dir / "config"
        return cls(
            run_dir=run_dir,
            config_dir=config_dir,
            before_snapshot=config_dir / "rootfs_before.json",
            after_snapshot=config_dir / "rootfs_after.json",
            rootfs_diff=config_dir / "rootfs_diff.json",
            requirements=config_dir / "runtime_requirements.json",
            lifecycle_state=config_dir / "observation_lifecycle.json",
            lifecycle_error=config_dir / "observation_error.json",
        )


@dataclass(slots=True, frozen=True)
class RuntimeObservationResult:
    before_entries: int
    after_entries: int
    created: int
    modified: int
    deleted: int
    requirements: int
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "before_entries": self.before_entries,
            "after_entries": self.after_entries,
            "created": self.created,
            "modified": self.modified,
            "deleted": self.deleted,
            "requirements": self.requirements,
            "warnings": list(self.warnings),
        }


class RuntimeObservationSession:
    """Own the pre-run/post-run observation lifecycle for one Phase 2 run.

    The session is intentionally independent of the Phase 1 JSON schema.  It
    observes the synthesized rootfs and the logs produced by Phase 2 itself.
    """

    def __init__(
        self,
        *,
        run_dir: str | Path,
        rootfs: str | Path,
        snapshot_options: SnapshotOptions | None = None,
        require_rootfs_inside_run_dir: bool = True,
    ) -> None:
        self.paths = RuntimeObservationPaths.from_run_dir(run_dir)
        self.rootfs = Path(rootfs).resolve()
        self.snapshot_options = snapshot_options or SnapshotOptions()
        self.require_rootfs_inside_run_dir = require_rootfs_inside_run_dir
        self._validate_layout()

    def capture_before(self) -> dict[str, Any]:
        """Capture the baseline after environment construction, before malware."""

        self.paths.config_dir.mkdir(parents=True, exist_ok=True)
        self.paths.lifecycle_error.unlink(missing_ok=True)
        self._write_state(
            status="capturing_before",
            details={"rootfs": str(self.rootfs)},
        )

        try:
            snapshot = snapshot_rootfs(
                self.rootfs,
                options=self.snapshot_options,
            )
            snapshot["observation_phase"] = "before_runtime"
            save_json(snapshot, self.paths.before_snapshot)
            self._write_state(
                status="before_captured",
                details={
                    "rootfs": str(self.rootfs),
                    "before_entries": int(snapshot.get("entries_count", 0)),
                    "before_snapshot": str(self.paths.before_snapshot),
                },
            )
            return snapshot
        except Exception as exc:
            self._record_error("capture_before", exc)
            raise self._wrap_error("cannot capture rootfs baseline", exc) from exc

    def capture_after(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Capture the post-run rootfs and derive a deterministic diff."""

        if not self.paths.before_snapshot.exists():
            raise RuntimeObserverError(
                "cannot capture post-run state before the baseline exists: "
                f"{self.paths.before_snapshot}"
            )

        self._write_state(
            status="capturing_after",
            details={"rootfs": str(self.rootfs)},
        )

        try:
            before = load_json(self.paths.before_snapshot)
            after = snapshot_rootfs(
                self.rootfs,
                options=self.snapshot_options,
            )
            after["observation_phase"] = "after_runtime"
            diff = diff_snapshots(before, after)
            save_json(after, self.paths.after_snapshot)
            save_json(diff, self.paths.rootfs_diff)
            self._write_state(
                status="after_captured",
                details={
                    "after_entries": int(after.get("entries_count", 0)),
                    "created": int(diff.get("created_count", 0)),
                    "modified": int(diff.get("modified_count", 0)),
                    "deleted": int(diff.get("deleted_count", 0)),
                    "after_snapshot": str(self.paths.after_snapshot),
                    "rootfs_diff": str(self.paths.rootfs_diff),
                },
            )
            return after, diff
        except Exception as exc:
            self._record_error("capture_after", exc)
            raise self._wrap_error("cannot capture post-run rootfs state", exc) from exc

    def extract_requirements(self) -> RequirementReport:
        """Extract requirements after syscall/network logs and rootfs diff exist."""

        self._write_state(status="extracting_requirements", details={})
        try:
            bundle = load_observation_bundle(self.paths.run_dir)
            report = RequirementExtractor().extract(bundle)
            report.save(self.paths.requirements)
            self._write_state(
                status="completed",
                details={
                    "requirements": len(report.requirements),
                    "requirements_path": str(self.paths.requirements),
                    "warnings": list(report.warnings),
                },
            )
            return report
        except Exception as exc:
            self._record_error("extract_requirements", exc)
            raise self._wrap_error("cannot extract runtime requirements", exc) from exc

    def finalize(self) -> RuntimeObservationResult:
        """Capture the final rootfs state and extract all runtime requirements."""

        before = load_json(self.paths.before_snapshot)
        after, diff = self.capture_after()
        report = self.extract_requirements()
        result = RuntimeObservationResult(
            before_entries=int(before.get("entries_count", 0)),
            after_entries=int(after.get("entries_count", 0)),
            created=int(diff.get("created_count", 0)),
            modified=int(diff.get("modified_count", 0)),
            deleted=int(diff.get("deleted_count", 0)),
            requirements=len(report.requirements),
            warnings=report.warnings,
        )
        self._write_state(status="completed", details=result.to_dict())
        return result

    def _validate_layout(self) -> None:
        if not self.paths.run_dir.exists():
            raise RuntimeObserverError(
                f"run directory does not exist: {self.paths.run_dir}"
            )
        if not self.paths.run_dir.is_dir():
            raise RuntimeObserverError(
                f"run path is not a directory: {self.paths.run_dir}"
            )
        if not self.rootfs.exists():
            raise RuntimeObserverError(f"rootfs does not exist: {self.rootfs}")
        if not self.rootfs.is_dir():
            raise RuntimeObserverError(f"rootfs is not a directory: {self.rootfs}")

        if self.require_rootfs_inside_run_dir and not _is_relative_to(
            self.rootfs,
            self.paths.run_dir,
        ):
            raise RuntimeObserverError(
                "refusing to snapshot a rootfs outside the run directory: "
                f"rootfs={self.rootfs}, run_dir={self.paths.run_dir}"
            )

    def _write_state(self, *, status: str, details: dict[str, Any]) -> None:
        payload = {
            "schema_version": 1,
            "updated_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "run_dir": str(self.paths.run_dir),
            "rootfs": str(self.rootfs),
            "details": details,
        }
        save_json(payload, self.paths.lifecycle_state)

    def _record_error(self, stage: str, exc: BaseException) -> None:
        payload = {
            "schema_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "run_dir": str(self.paths.run_dir),
            "rootfs": str(self.rootfs),
        }
        save_json(payload, self.paths.lifecycle_error)
        self._write_state(status="failed", details=payload)

    @staticmethod
    def _wrap_error(message: str, exc: BaseException) -> RuntimeObserverError:
        if isinstance(exc, RuntimeObserverError):
            return exc
        if isinstance(exc, (RootfsDiffError, ObservationLoadError)):
            return RuntimeObserverError(f"{message}: {exc}")
        return RuntimeObserverError(
            f"{message}: {type(exc).__name__}: {exc}"
        )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True
