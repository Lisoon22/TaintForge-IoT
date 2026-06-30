from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

HASH_CHUNK_SIZE = 1024 * 1024


class RootfsDiffError(RuntimeError):
    """Raised when a rootfs snapshot or comparison cannot be trusted."""


@dataclass(slots=True, frozen=True)
class SnapshotOptions:
    """Controls deterministic and safe traversal of a synthesized rootfs.

    ``stay_on_filesystem`` prevents traversal into procfs, sysfs, devtmpfs or
    any other mount accidentally left below the rootfs.  This is important in
    a malware sandbox: walking a leaked ``rootfs/proc`` mount would otherwise
    snapshot the host-visible procfs namespace instead of the synthesized
    filesystem.

    ``exclude_paths`` contains guest paths.  Exclusions are explicit and are
    deliberately empty by default; the filesystem-boundary check is normally
    enough and does not hide synthetic files such as ``/proc/cpuinfo`` when
    ``/proc`` is an ordinary directory in the rootfs.
    """

    stay_on_filesystem: bool = True
    hash_regular_files: bool = True
    exclude_paths: tuple[str, ...] = ()
    strict: bool = True


@dataclass(slots=True, frozen=True)
class RootfsEntry:
    path: str
    type: str
    mode: int
    uid: int
    gid: int
    size: int | None
    mtime_ns: int
    device: int
    inode: int
    sha256: str | None = None
    symlink_target: str | None = None
    error: str | None = None


def snapshot_rootfs(
    rootfs: str | Path,
    *,
    options: SnapshotOptions | None = None,
) -> dict[str, Any]:
    """Create a deterministic metadata/content snapshot of ``rootfs``.

    The function does not follow symbolic links.  By default it also refuses
    to cross filesystem boundaries, which keeps leaked runtime mounts out of
    the snapshot.  Errors are fatal in strict mode because a partial snapshot
    must not be mistaken for complete evidence.
    """

    options = options or SnapshotOptions()
    rootfs = Path(rootfs).resolve()
    if not rootfs.exists():
        raise RootfsDiffError(f"rootfs does not exist: {rootfs}")
    if not rootfs.is_dir():
        raise RootfsDiffError(f"rootfs is not a directory: {rootfs}")

    try:
        root_stat = rootfs.stat()
    except OSError as exc:
        raise RootfsDiffError(f"cannot stat rootfs {rootfs}: {exc}") from exc

    excluded = _normalize_excluded_paths(options.exclude_paths)
    entries: dict[str, dict[str, Any]] = {}
    skipped: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    for current_dir, dir_names, file_names in os.walk(
        rootfs,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current_dir)
        dir_names.sort()
        file_names.sort()

        retained_dirs: list[str] = []
        for name in dir_names:
            path = current_path / name
            guest_path = _guest_path(rootfs, path)

            if _path_is_excluded(guest_path, excluded):
                skipped.append({"path": guest_path, "reason": "excluded"})
                continue

            try:
                st = path.lstat()
            except OSError as exc:
                _handle_snapshot_error(
                    options=options,
                    errors=errors,
                    path=guest_path,
                    exc=exc,
                )
                continue

            if options.stay_on_filesystem and st.st_dev != root_stat.st_dev:
                skipped.append(
                    {
                        "path": guest_path,
                        "reason": "filesystem_boundary",
                    }
                )
                continue

            try:
                entry = inspect_path(
                    rootfs=rootfs,
                    path=path,
                    options=options,
                )
            except RootfsDiffError as exc:
                _handle_snapshot_error(
                    options=options,
                    errors=errors,
                    path=guest_path,
                    exc=exc,
                )
                continue

            entries[entry.path] = asdict(entry)
            if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                retained_dirs.append(name)

        # Prune excluded directories, symlinked directories and other mounts.
        dir_names[:] = retained_dirs

        for name in file_names:
            path = current_path / name
            guest_path = _guest_path(rootfs, path)
            if _path_is_excluded(guest_path, excluded):
                skipped.append({"path": guest_path, "reason": "excluded"})
                continue

            try:
                entry = inspect_path(
                    rootfs=rootfs,
                    path=path,
                    options=options,
                )
            except RootfsDiffError as exc:
                _handle_snapshot_error(
                    options=options,
                    errors=errors,
                    path=guest_path,
                    exc=exc,
                )
                continue
            entries[entry.path] = asdict(entry)

    return {
        "schema_version": 2,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "rootfs": str(rootfs),
        "root_device": root_stat.st_dev,
        "options": {
            "stay_on_filesystem": options.stay_on_filesystem,
            "hash_regular_files": options.hash_regular_files,
            "exclude_paths": list(options.exclude_paths),
            "strict": options.strict,
        },
        "entries_count": len(entries),
        "skipped_count": len(skipped),
        "error_count": len(errors),
        "entries": entries,
        "skipped": skipped,
        "errors": errors,
    }


def inspect_path(
    rootfs: Path,
    path: Path,
    *,
    options: SnapshotOptions | None = None,
) -> RootfsEntry:
    options = options or SnapshotOptions()
    try:
        st = path.lstat()
    except FileNotFoundError as exc:
        raise RootfsDiffError(f"path disappeared during snapshot: {path}") from exc
    except OSError as exc:
        raise RootfsDiffError(f"cannot lstat {path}: {exc}") from exc

    guest_path = _guest_path(rootfs, path)
    mode = stat.S_IMODE(st.st_mode)
    common = {
        "path": guest_path,
        "mode": mode,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime_ns": st.st_mtime_ns,
        "device": st.st_dev,
        "inode": st.st_ino,
    }

    if stat.S_ISREG(st.st_mode):
        digest: str | None = None
        if options.hash_regular_files:
            try:
                digest = sha256_file(path)
            except OSError as exc:
                raise RootfsDiffError(f"cannot hash regular file {path}: {exc}") from exc
        return RootfsEntry(
            type="file",
            size=st.st_size,
            sha256=digest,
            **common,
        )

    if stat.S_ISDIR(st.st_mode):
        return RootfsEntry(type="dir", size=None, **common)

    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise RootfsDiffError(f"cannot read symlink {path}: {exc}") from exc
        return RootfsEntry(
            type="symlink",
            size=None,
            symlink_target=target,
            **common,
        )

    if stat.S_ISCHR(st.st_mode):
        entry_type = "char_device"
    elif stat.S_ISBLK(st.st_mode):
        entry_type = "block_device"
    elif stat.S_ISFIFO(st.st_mode):
        entry_type = "fifo"
    elif stat.S_ISSOCK(st.st_mode):
        entry_type = "socket"
    else:
        entry_type = "special"

    return RootfsEntry(type=entry_type, size=None, **common)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def diff_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two snapshots and return deterministic created/modified/deleted sets."""

    before_entries = _require_entries(before, "before")
    after_entries = _require_entries(after, "after")

    before_paths = set(before_entries)
    after_paths = set(after_entries)
    created_paths = sorted(after_paths - before_paths)
    deleted_paths = sorted(before_paths - after_paths)
    common_paths = sorted(before_paths & after_paths)

    created = [after_entries[path] for path in created_paths]
    deleted = [before_entries[path] for path in deleted_paths]
    modified: list[dict[str, Any]] = []

    for path in common_paths:
        old = before_entries[path]
        new = after_entries[path]
        changes = compare_entries(old, new)
        if not changes:
            continue
        modified.append(
            {
                "path": path,
                "type_before": old.get("type"),
                "type_after": new.get("type"),
                "changes": changes,
                "before": old,
                "after": new,
            }
        )

    return {
        "schema_version": 2,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "rootfs_before": before.get("rootfs"),
        "rootfs_after": after.get("rootfs"),
        "created_count": len(created),
        "modified_count": len(modified),
        "deleted_count": len(deleted),
        "created": created,
        "modified": modified,
        "deleted": deleted,
        "snapshot_warnings": {
            "before_skipped_count": int(before.get("skipped_count", 0)),
            "after_skipped_count": int(after.get("skipped_count", 0)),
            "before_error_count": int(before.get("error_count", 0)),
            "after_error_count": int(after.get("error_count", 0)),
        },
    }


def compare_entries(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    fields = (
        "type",
        "mode",
        "uid",
        "gid",
        "size",
        "sha256",
        "symlink_target",
        "device",
    )

    for field_name in fields:
        if old.get(field_name) == new.get(field_name):
            continue
        changes[field_name] = {
            "before": old.get(field_name),
            "after": new.get(field_name),
        }

    # Inodes are intentionally not compared: replacing a file atomically with
    # identical content is not an environmental requirement by itself.
    if not changes and old.get("mtime_ns") != new.get("mtime_ns"):
        changes["mtime_ns"] = {
            "before": old.get("mtime_ns"),
            "after": new.get("mtime_ns"),
        }
    return changes


def save_json(data: dict[str, Any], out_path: str | Path) -> None:
    """Atomically save JSON so interrupted analysis cannot leave partial artifacts."""

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=out_path.parent,
            prefix=f".{out_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
            temp_path = Path(stream.name)
        os.replace(temp_path, out_path)
        os.chmod(out_path, 0o644)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)


def load_json(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        raise RootfsDiffError(f"file does not exist: {path}")
    if not path.is_file():
        raise RootfsDiffError(f"path is not a file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RootfsDiffError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RootfsDiffError(
            f"expected JSON object in {path}, got {type(value).__name__}"
        )
    return value


def _guest_path(rootfs: Path, path: Path) -> str:
    relative = path.relative_to(rootfs)
    rendered = PurePosixPath("/", *relative.parts).as_posix()
    return rendered if rendered != "." else "/"


def _normalize_excluded_paths(paths: Iterable[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            raise RootfsDiffError(
                f"excluded guest path must be absolute: {raw_path!r}"
            )
        normalized_path = PurePosixPath(raw_path).as_posix()
        if normalized_path == "/":
            raise RootfsDiffError("excluding the entire rootfs is not allowed")
        normalized.append(normalized_path.rstrip("/"))
    return tuple(sorted(set(normalized)))


def _path_is_excluded(path: str, excluded: tuple[str, ...]) -> bool:
    return any(path == item or path.startswith(item + "/") for item in excluded)


def _handle_snapshot_error(
    *,
    options: SnapshotOptions,
    errors: list[dict[str, str]],
    path: str,
    exc: BaseException,
) -> None:
    if options.strict:
        if isinstance(exc, RootfsDiffError):
            raise exc
        raise RootfsDiffError(f"cannot snapshot {path}: {exc}") from exc
    errors.append({"path": path, "error": str(exc)})


def _require_entries(snapshot: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    entries = snapshot.get("entries")
    if not isinstance(entries, dict):
        raise RootfsDiffError(f"{name} snapshot has no valid entries object")
    for path, value in entries.items():
        if not isinstance(path, str) or not isinstance(value, dict):
            raise RootfsDiffError(f"{name} snapshot contains an invalid entry")
    return entries
