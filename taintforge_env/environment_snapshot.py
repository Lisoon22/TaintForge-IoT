from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


HASH_CHUNK_SIZE = 1024 * 1024


class EnvironmentSnapshotError(RuntimeError):
    """Raised when an environment snapshot cannot be trusted or cloned."""


@dataclass(slots=True, frozen=True)
class EnvironmentEntry:
    path: str
    type: str
    mode: int
    size: int | None = None
    sha256: str | None = None
    symlink_target: str | None = None
    hardlink_group: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "type": self.type,
            "mode": self.mode,
            "size": self.size,
            "sha256": self.sha256,
            "symlink_target": self.symlink_target,
            "hardlink_group": self.hardlink_group,
        }

    @classmethod
    def from_dict(cls, raw: Any, *, location: str) -> EnvironmentEntry:
        if not isinstance(raw, dict):
            raise EnvironmentSnapshotError(f"{location} must be a JSON object")

        path = raw.get("path")
        entry_type = raw.get("type")
        mode = raw.get("mode")
        size = raw.get("size")
        digest = raw.get("sha256")
        target = raw.get("symlink_target")
        hardlink_group = raw.get("hardlink_group")

        if not isinstance(path, str) or not path.startswith("/"):
            raise EnvironmentSnapshotError(
                f"{location}.path must be an absolute guest path"
            )
        if entry_type not in {"dir", "file", "symlink"}:
            raise EnvironmentSnapshotError(
                f"{location}.type is unsupported: {entry_type!r}"
            )
        if path == "/" and entry_type != "dir":
            raise EnvironmentSnapshotError(
                f"{location}: the guest root entry must be a directory"
            )
        if not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777:
            raise EnvironmentSnapshotError(f"{location}.mode is invalid")

        if entry_type == "file":
            if path == "/":
                raise EnvironmentSnapshotError(f"{location}: root cannot be a file")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise EnvironmentSnapshotError(f"{location}.size is invalid")
            if not isinstance(digest, str) or not _is_sha256(digest):
                raise EnvironmentSnapshotError(f"{location}.sha256 is invalid")
            if target is not None:
                raise EnvironmentSnapshotError(
                    f"{location}.symlink_target is invalid for a file"
                )
        elif entry_type == "symlink":
            if path == "/":
                raise EnvironmentSnapshotError(f"{location}: root cannot be a symlink")
            if not isinstance(target, str):
                raise EnvironmentSnapshotError(
                    f"{location}.symlink_target is required"
                )
            if size is not None or digest is not None:
                raise EnvironmentSnapshotError(
                    f"{location} contains file fields for a symlink"
                )
        else:
            if size is not None or digest is not None or target is not None:
                raise EnvironmentSnapshotError(
                    f"{location} contains non-directory fields"
                )

        if hardlink_group is not None:
            if entry_type != "file":
                raise EnvironmentSnapshotError(
                    f"{location}.hardlink_group is only valid for files"
                )
            if not isinstance(hardlink_group, str) or not hardlink_group.startswith("hl_"):
                raise EnvironmentSnapshotError(
                    f"{location}.hardlink_group is invalid"
                )

        return cls(
            path=path,
            type=entry_type,
            mode=mode,
            size=size,
            sha256=digest,
            symlink_target=target,
            hardlink_group=hardlink_group,
        )


@dataclass(slots=True, frozen=True)
class EnvironmentSnapshotManifest:
    snapshot_id: str
    tree_sha256: str
    source_rootfs: str
    snapshot_rootfs: str
    entries: tuple[EnvironmentEntry, ...]
    schema_version: int = 1
    snapshot_version: int = 1
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        hardlink_groups: set[str] = set()
        total_bytes = 0
        for entry in self.entries:
            by_type[entry.type] = by_type.get(entry.type, 0) + 1
            total_bytes += entry.size or 0
            if entry.hardlink_group is not None:
                hardlink_groups.add(entry.hardlink_group)
        return {
            "entries_total": len(self.entries),
            "total_file_bytes": total_bytes,
            "hardlink_groups": len(hardlink_groups),
            "by_type": dict(sorted(by_type.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "snapshot_version": self.snapshot_version,
            "snapshot_id": self.snapshot_id,
            "generated_at_utc": self.generated_at_utc,
            "tree_sha256": self.tree_sha256,
            "source_rootfs": self.source_rootfs,
            "snapshot_rootfs": self.snapshot_rootfs,
            "summary": self.summary(),
            "entries": [entry.to_dict() for entry in self.entries],
        }

    def save(self, path: str | Path) -> None:
        _atomic_write_json(Path(path), self.to_dict())

    @classmethod
    def load(cls, path: str | Path) -> EnvironmentSnapshotManifest:
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise EnvironmentSnapshotError(
                f"snapshot manifest does not exist: {path}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise EnvironmentSnapshotError(
                f"invalid JSON in snapshot manifest {path}: {exc}"
            ) from exc

        if not isinstance(raw, dict):
            raise EnvironmentSnapshotError("snapshot manifest must be a JSON object")
        if raw.get("schema_version") != 1:
            raise EnvironmentSnapshotError(
                f"unsupported snapshot schema_version: {raw.get('schema_version')!r}"
            )
        if raw.get("snapshot_version") != 1:
            raise EnvironmentSnapshotError(
                f"unsupported snapshot_version: {raw.get('snapshot_version')!r}"
            )

        snapshot_id = raw.get("snapshot_id")
        tree_sha256 = raw.get("tree_sha256")
        source_rootfs = raw.get("source_rootfs")
        snapshot_rootfs = raw.get("snapshot_rootfs")
        entries_raw = raw.get("entries")

        if not isinstance(snapshot_id, str) or not snapshot_id.startswith("env_"):
            raise EnvironmentSnapshotError("snapshot_id is invalid")
        if not isinstance(tree_sha256, str) or not _is_sha256(tree_sha256):
            raise EnvironmentSnapshotError("tree_sha256 is invalid")
        if snapshot_id != make_snapshot_id(tree_sha256):
            raise EnvironmentSnapshotError("snapshot_id does not match tree_sha256")
        if not isinstance(source_rootfs, str) or not source_rootfs:
            raise EnvironmentSnapshotError("source_rootfs is invalid")
        if not isinstance(snapshot_rootfs, str) or not snapshot_rootfs:
            raise EnvironmentSnapshotError("snapshot_rootfs is invalid")
        if not isinstance(entries_raw, list):
            raise EnvironmentSnapshotError("entries must be a JSON array")

        entries = tuple(
            EnvironmentEntry.from_dict(value, location=f"entries[{index}]")
            for index, value in enumerate(entries_raw)
        )
        paths = [entry.path for entry in entries]
        if paths != sorted(paths):
            raise EnvironmentSnapshotError("entries must be sorted by guest path")
        if len(paths) != len(set(paths)):
            raise EnvironmentSnapshotError("entries contain duplicate guest paths")
        if not entries or entries[0].path != "/":
            raise EnvironmentSnapshotError("entries must contain the guest root /")

        calculated = tree_digest(entries)
        if calculated != tree_sha256:
            raise EnvironmentSnapshotError(
                "manifest entry digest does not match tree_sha256"
            )

        return cls(
            snapshot_id=snapshot_id,
            tree_sha256=tree_sha256,
            source_rootfs=source_rootfs,
            snapshot_rootfs=snapshot_rootfs,
            entries=entries,
            generated_at_utc=str(raw.get("generated_at_utc") or "unknown"),
        )


@dataclass(slots=True, frozen=True)
class SnapshotCaptureResult:
    manifest: EnvironmentSnapshotManifest
    snapshot_dir: Path
    reused_existing: bool


class EnvironmentSnapshotStore:
    """Content-addressed full-copy store for clean Phase 2 environments."""

    def __init__(self, store_dir: str | Path) -> None:
        self.store_dir = Path(store_dir).resolve(strict=False)

    def capture(self, source_rootfs: str | Path) -> SnapshotCaptureResult:
        source = _validate_rootfs(source_rootfs, label="source rootfs")
        entries = scan_environment(source)
        digest = tree_digest(entries)
        snapshot_id = make_snapshot_id(digest)
        snapshot_dir = self.store_dir / snapshot_id
        final_snapshot_rootfs = snapshot_dir / "rootfs"

        self.store_dir.mkdir(parents=True, exist_ok=True)
        _reject_symlink_components(self.store_dir.resolve())

        if snapshot_dir.exists() or snapshot_dir.is_symlink():
            manifest = self.verify(snapshot_id)
            if manifest.tree_sha256 != digest:
                raise EnvironmentSnapshotError(
                    f"snapshot id collision or corrupted snapshot: {snapshot_id}"
                )
            return SnapshotCaptureResult(manifest, snapshot_dir, True)

        temporary: Path | None = Path(
            tempfile.mkdtemp(
                prefix=f".{snapshot_id}.",
                suffix=".tmp",
                dir=self.store_dir,
            )
        )
        try:
            temporary_rootfs = temporary / "rootfs"
            clone_environment(source, temporary_rootfs)
            cloned_entries = scan_environment(temporary_rootfs)
            if tree_digest(cloned_entries) != digest:
                raise EnvironmentSnapshotError(
                    "captured rootfs digest differs from source rootfs digest"
                )
            manifest = EnvironmentSnapshotManifest(
                snapshot_id=snapshot_id,
                tree_sha256=digest,
                source_rootfs=str(source),
                snapshot_rootfs=str(final_snapshot_rootfs),
                entries=cloned_entries,
            )
            manifest.save(temporary / "manifest.json")
            os.replace(temporary, snapshot_dir)
            temporary = None
            return SnapshotCaptureResult(manifest, snapshot_dir, False)
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def verify(self, snapshot: str | Path) -> EnvironmentSnapshotManifest:
        snapshot_dir = self._resolve_snapshot_dir(snapshot)
        if snapshot_dir.is_symlink():
            raise EnvironmentSnapshotError(
                f"snapshot directory must not be a symlink: {snapshot_dir}"
            )
        if not snapshot_dir.is_dir():
            raise EnvironmentSnapshotError(
                f"snapshot directory does not exist: {snapshot_dir}"
            )
        manifest = EnvironmentSnapshotManifest.load(snapshot_dir / "manifest.json")
        rootfs = _validate_rootfs(snapshot_dir / "rootfs", label="snapshot rootfs")
        actual_entries = scan_environment(rootfs)
        actual_digest = tree_digest(actual_entries)
        if actual_digest != manifest.tree_sha256:
            raise EnvironmentSnapshotError(
                "snapshot rootfs digest does not match its manifest: "
                f"expected {manifest.tree_sha256}, got {actual_digest}"
            )
        if actual_entries != manifest.entries:
            raise EnvironmentSnapshotError(
                "snapshot rootfs entries do not match its manifest"
            )
        return manifest

    def clone(
        self,
        snapshot: str | Path,
        destination_rootfs: str | Path,
    ) -> EnvironmentSnapshotManifest:
        manifest = self.verify(snapshot)
        snapshot_dir = self._resolve_snapshot_dir(snapshot)
        source_rootfs = snapshot_dir / "rootfs"
        destination = Path(destination_rootfs).resolve(strict=False)

        if destination.exists() or destination.is_symlink():
            raise EnvironmentSnapshotError(
                f"clone destination already exists: {destination}"
            )
        if destination == Path("/"):
            raise EnvironmentSnapshotError("refusing to clone onto host root /")

        destination.parent.mkdir(parents=True, exist_ok=True)
        _reject_symlink_components(destination.parent.resolve())

        temporary: Path | None = Path(
            tempfile.mkdtemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
        )
        try:
            temporary_rootfs = temporary / "rootfs"
            clone_environment(source_rootfs, temporary_rootfs)
            cloned_entries = scan_environment(temporary_rootfs)
            if tree_digest(cloned_entries) != manifest.tree_sha256:
                raise EnvironmentSnapshotError(
                    "cloned rootfs digest does not match the snapshot"
                )
            os.replace(temporary_rootfs, destination)
            shutil.rmtree(temporary, ignore_errors=True)
            temporary = None
        finally:
            if temporary is not None and temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

        return manifest

    def _resolve_snapshot_dir(self, snapshot: str | Path) -> Path:
        value = Path(snapshot)
        if not value.is_absolute():
            candidate = self.store_dir / value
            if candidate.exists() or candidate.is_symlink():
                return candidate
        return value.resolve(strict=False)


def scan_environment(rootfs: str | Path) -> tuple[EnvironmentEntry, ...]:
    root = _validate_rootfs(rootfs, label="rootfs")
    try:
        root_stat = root.stat()
    except OSError as exc:
        raise EnvironmentSnapshotError(f"cannot stat rootfs {root}: {exc}") from exc

    raw: list[tuple[str, os.stat_result, str | None, str | None]] = [
        ("/", root_stat, None, None)
    ]
    hardlink_paths: dict[tuple[int, int], list[str]] = {}

    def on_walk_error(exc: OSError) -> None:
        raise EnvironmentSnapshotError(f"cannot walk rootfs {root}: {exc}") from exc

    for current_dir, dir_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=on_walk_error,
    ):
        current = Path(current_dir)
        dir_names.sort()
        file_names.sort()

        retained_dirs: list[str] = []
        for name in dir_names:
            path = current / name
            guest = _guest_path(root, path)
            try:
                entry_stat = path.lstat()
            except OSError as exc:
                raise EnvironmentSnapshotError(
                    f"cannot inspect {guest}: {exc}"
                ) from exc
            if stat.S_ISLNK(entry_stat.st_mode):
                raw.append((guest, entry_stat, os.readlink(path), None))
                continue
            if not stat.S_ISDIR(entry_stat.st_mode):
                raise EnvironmentSnapshotError(
                    f"directory walk encountered unsupported entry at {guest}"
                )
            if path.is_mount():
                raise EnvironmentSnapshotError(
                    f"rootfs contains another mounted filesystem at {guest}"
                )
            raw.append((guest, entry_stat, None, None))
            retained_dirs.append(name)
        dir_names[:] = retained_dirs

        for name in file_names:
            path = current / name
            guest = _guest_path(root, path)
            try:
                entry_stat = path.lstat()
            except OSError as exc:
                raise EnvironmentSnapshotError(
                    f"cannot inspect {guest}: {exc}"
                ) from exc
            if stat.S_ISREG(entry_stat.st_mode):
                digest = _sha256_file(path)
                raw.append((guest, entry_stat, None, digest))
                if entry_stat.st_nlink > 1:
                    hardlink_paths.setdefault(
                        (entry_stat.st_dev, entry_stat.st_ino), []
                    ).append(guest)
                continue
            if stat.S_ISLNK(entry_stat.st_mode):
                raw.append((guest, entry_stat, os.readlink(path), None))
                continue
            raise EnvironmentSnapshotError(
                "unsupported special entry in rootfs: "
                f"{guest} ({_special_type(entry_stat.st_mode)})"
            )

    hardlink_group_by_path: dict[str, str] = {}
    for paths in hardlink_paths.values():
        if len(paths) < 2:
            continue
        canonical_paths = sorted(paths)
        canonical = "\0".join(canonical_paths).encode("utf-8")
        group = "hl_" + hashlib.sha256(canonical).hexdigest()[:16]
        for guest in canonical_paths:
            hardlink_group_by_path[guest] = group

    entries: list[EnvironmentEntry] = []
    for guest, entry_stat, symlink_target, digest in raw:
        mode = stat.S_IMODE(entry_stat.st_mode)
        if stat.S_ISDIR(entry_stat.st_mode):
            entries.append(EnvironmentEntry(path=guest, type="dir", mode=mode))
        elif stat.S_ISREG(entry_stat.st_mode):
            entries.append(
                EnvironmentEntry(
                    path=guest,
                    type="file",
                    mode=mode,
                    size=entry_stat.st_size,
                    sha256=digest,
                    hardlink_group=hardlink_group_by_path.get(guest),
                )
            )
        elif stat.S_ISLNK(entry_stat.st_mode):
            entries.append(
                EnvironmentEntry(
                    path=guest,
                    type="symlink",
                    mode=mode,
                    symlink_target=symlink_target,
                )
            )
        else:  # pragma: no cover
            raise AssertionError("unsupported entry escaped validation")

    entries.sort(key=lambda entry: entry.path)
    return tuple(entries)


def tree_digest(entries: Iterable[EnvironmentEntry]) -> str:
    canonical = [entry.to_dict() for entry in entries]
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def make_snapshot_id(tree_sha256: str) -> str:
    if not _is_sha256(tree_sha256):
        raise EnvironmentSnapshotError("tree_sha256 is invalid")
    return "env_" + tree_sha256[:16]


def clone_environment(source_rootfs: str | Path, destination_rootfs: str | Path) -> None:
    source = _validate_rootfs(source_rootfs, label="clone source rootfs")
    destination = Path(destination_rootfs).resolve(strict=False)
    if destination.exists() or destination.is_symlink():
        raise EnvironmentSnapshotError(
            f"clone destination already exists: {destination}"
        )

    entries = scan_environment(source)
    root_entry = entries[0]
    destination.mkdir(mode=0o700, parents=False)
    directory_modes: list[tuple[Path, int]] = []
    hardlink_targets: dict[str, Path] = {}

    try:
        for entry in entries[1:]:
            relative = PurePosixPath(entry.path).parts[1:]
            source_path = source.joinpath(*relative)
            destination_path = destination.joinpath(*relative)

            if entry.type == "dir":
                destination_path.mkdir(mode=0o700)
                directory_modes.append((destination_path, entry.mode))
                continue
            if entry.type == "symlink":
                os.symlink(entry.symlink_target, destination_path)
                continue
            if entry.type != "file":  # pragma: no cover
                raise EnvironmentSnapshotError(
                    f"cannot clone unsupported entry type: {entry.type}"
                )

            if entry.hardlink_group is not None and entry.hardlink_group in hardlink_targets:
                os.link(
                    hardlink_targets[entry.hardlink_group],
                    destination_path,
                    follow_symlinks=False,
                )
            else:
                shutil.copyfile(
                    source_path,
                    destination_path,
                    follow_symlinks=False,
                )
                if entry.hardlink_group is not None:
                    hardlink_targets[entry.hardlink_group] = destination_path
            os.chmod(destination_path, entry.mode, follow_symlinks=False)

        for path, mode in sorted(
            directory_modes,
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            os.chmod(path, mode)
        os.chmod(destination, root_entry.mode)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _validate_rootfs(path: str | Path, *, label: str) -> Path:
    raw = Path(path)
    if raw.is_symlink():
        raise EnvironmentSnapshotError(f"{label} must not be a symlink: {raw}")
    try:
        resolved = raw.resolve(strict=True)
    except FileNotFoundError as exc:
        raise EnvironmentSnapshotError(f"{label} does not exist: {raw}") from exc
    if resolved == Path("/"):
        raise EnvironmentSnapshotError(f"refusing to use host root / as {label}")
    if not resolved.is_dir():
        raise EnvironmentSnapshotError(f"{label} is not a directory: {resolved}")
    return resolved


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise EnvironmentSnapshotError(
                f"path crosses a symbolic link: {current}"
            )


def _guest_path(rootfs: Path, path: Path) -> str:
    relative = path.relative_to(rootfs)
    return PurePosixPath("/", *relative.parts).as_posix()


def _special_type(mode: int) -> str:
    if stat.S_ISCHR(mode):
        return "char_device"
    if stat.S_ISBLK(mode):
        return "block_device"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    return "special"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EnvironmentSnapshotError(f"cannot hash file {path}: {exc}") from exc
    return digest.hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


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
        temporary = None
        os.chmod(path, 0o644)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)
