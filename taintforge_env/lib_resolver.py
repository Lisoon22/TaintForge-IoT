from __future__ import annotations
import json 
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
from .library_planner import LibraryPlan, LibraryRequirement

@dataclass(slots=True)
class ResolvedLibrary:
    name: str
    kind: str
    source_path: str
    guest_path: str
    sources: list[str] = field(default_factory=list)

@dataclass(slots=True)
class MissingLibrary:
    name: str
    kind: str
    guest_path: Optional[str]
    sources: list[str] = field(default_factory=list)

@dataclass(slots=True)
class LibraryResolutionReport:
    resolved: list[ResolvedLibrary] = field(default_factory=list)
    missing: list[MissingLibrary] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
                "resolved": [asdict(item) for item in self.resolved],
                "missing": [asdict(item) for item in self.missing]

        }

class LibraryResolver:
    def __init__(self, rootfs: str | Path, sysroot_dirs: list[str | Path]):
        self.rootfs = Path(rootfs)
        self.sysroot_dirs = [Path(item) for item in sysroot_dirs]

    def resolve_plan(self, plan: LibraryPlan) -> LibraryResolutionReport:
        report = LibraryResolutionReport()

        for requirement in plan.requirements:
            resolved = self.resolve_requirement(requirement)

            if resolved is None:
                report.missing.append(MissingLibrary(name=requirement.name, kind=requirement.kind, guest_path=requirement.guest_path, sources=requirement.sources))
                continue

            self.copy_resolved_library(resolved)
            report.resolved.append(resolved)

        return report

    def resolve_requirement(self, requirement: LibraryRequirement) -> Optional[ResolvedLibrary]:
        if requirement.guest_path is not None:
            resolved = self.resolve_by_guest_path(requirement)

            if resolved is not None:
                return resolved

        return self.resolve_by_name(requirement)

    def resolve_by_guest_path(self, requirement: LibraryRequirement) -> Optional[ResolvedLibrary]:
        assert requirement.guest_path is not None

        relative_path = requirement.guest_path.lstrip("/")

        for sysroot in self.sysroot_dirs:
            candidate = sysroot / relative_path

            if candidate.exists() and candidate.is_file():
                return ResolvedLibrary(
                    name=requirement.name,
                    kind=requirement.kind,
                    source_path=str(candidate),
                    guest_path=requirement.guest_path,
                    sources=requirement.sources,
                )

        return None

    def resolve_by_name(
        self,
        requirement: LibraryRequirement,
    ) -> Optional[ResolvedLibrary]:
        search_dirs = [
            "lib",
            "lib32",
            "lib64",
            "usr/lib",
            "usr/lib32",
            "usr/lib64",
        ]

        for sysroot in self.sysroot_dirs:
            for search_dir in search_dirs:
                candidate = sysroot / search_dir / requirement.name

                if candidate.exists() and candidate.is_file():
                    guest_path = f"/{search_dir}/{requirement.name}"

                    return ResolvedLibrary(
                        name=requirement.name,
                        kind=requirement.kind,
                        source_path=str(candidate),
                        guest_path=guest_path,
                        sources=requirement.sources,
                    )

        return None

    def copy_resolved_library(self, resolved: ResolvedLibrary) -> None:
        destination = self.rootfs / resolved.guest_path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(resolved.source_path, destination)

    @staticmethod
    def save_report(
        report: LibraryResolutionReport,
        path: str | Path,
    ) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        path.write_text(
            json.dumps(report.to_dict(), indent=2),
            encoding="utf-8",
        )
