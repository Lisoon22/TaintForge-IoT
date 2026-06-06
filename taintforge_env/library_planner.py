from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .elf_analyzer import ELFInfo
from .models import TaintLog


@dataclass(slots=True)
class LibraryRequirement:
    name: str
    kind: str

    guest_path: Optional[str] = None

    sources: list[str] = field(default_factory=list)

    def add_source(self, source: str) -> None:
        if source not in self.sources:
            self.sources.append(source)


@dataclass(slots=True)
class LibraryPlan:
    requirements: list[LibraryRequirement] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "requirements": [
                asdict(requirement)
                for requirement in self.requirements
            ]
        }


def build_library_plan(taint: TaintLog, elf_info: Optional[ELFInfo] = None) -> LibraryPlan:
    requirements_by_key: dict[str, LibraryRequirement] = {}

    if elf_info is not None:
        add_elf_requirements(requirements_by_key, elf_info)

    add_taint_library_requirements(requirements_by_key, taint)
    add_library_like_file_requirements(requirements_by_key, taint)

    return LibraryPlan(
        requirements=sorted(
            requirements_by_key.values(),
            key=lambda item: (item.kind, item.name),
        )
    )


def add_elf_requirements(requirements: dict[str, LibraryRequirement],elf_info: ELFInfo) -> None:
    if elf_info.interpreter:
        add_requirement(
            requirements=requirements,
            name=Path(elf_info.interpreter).name,
            kind="interpreter",
            guest_path=elf_info.interpreter,
            source="elf_interpreter",
        )

    for lib_name in elf_info.needed_libraries:
        add_requirement(
            requirements=requirements,
            name=lib_name,
            kind="needed",
            guest_path=None,
            source="elf_needed",
        )


def add_taint_library_requirements(requirements: dict[str, LibraryRequirement],taint: TaintLog) -> None:
    for dep in taint.library_dependencies:
        guest_path = dep.path

        name = dep.name
        if not name and guest_path:
            name = Path(guest_path).name

        if not name:
            continue

        add_requirement(
            requirements=requirements,
            name=name,
            kind="runtime_library",
            guest_path=guest_path,
            source="taint_library_dependencies",
        )


def add_library_like_file_requirements(requirements: dict[str, LibraryRequirement],taint: TaintLog) -> None:
    for dep in taint.file_dependencies:
        path = dep.path

        if not looks_like_library_path(path):
            continue

        add_requirement(
            requirements=requirements,
            name=Path(path).name,
            kind="runtime_file_library",
            guest_path=path,
            source="taint_file_dependencies",
        )


def add_requirement(requirements: dict[str, LibraryRequirement],name: str,kind: str,guest_path: Optional[str],source: str) -> None:
    key = make_requirement_key(name=name, guest_path=guest_path)

    if key not in requirements:
        requirements[key] = LibraryRequirement(
            name=name,
            kind=kind,
            guest_path=guest_path,
            sources=[],
        )

    requirements[key].add_source(source)

    if requirements[key].guest_path is None and guest_path is not None:
        requirements[key].guest_path = guest_path


def make_requirement_key(name: str, guest_path: Optional[str]) -> str:
    if guest_path:
        return f"path:{guest_path}"

    return f"name:{name}"


def looks_like_library_path(path: str) -> bool:
    if not path:
        return False

    if path.startswith("/lib/") or path.startswith("/usr/lib/"):
        return True

    if ".so" in Path(path).name:
        return True

    return False


def save_library_plan(plan: LibraryPlan, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(plan.to_dict(), indent=2),
        encoding="utf-8",
    )

def load_library_plan(path: str | Path) -> LibraryPlan:
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))

    requirements = [
        LibraryRequirement(
            name=item["name"],
            kind=item["kind"],
            guest_path=item.get("guest_path"),
            sources=item.get("sources", []),
        )
        for item in raw.get("requirements", [])
    ]

    return LibraryPlan(requirements=requirements)
