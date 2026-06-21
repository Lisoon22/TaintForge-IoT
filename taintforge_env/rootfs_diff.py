from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HASH_CHUNK_SIZE = 1024 * 1024


@dataclass(slots=True)
class RootfsEntry:
    path: str
    type: str
    mode: int
    uid: int
    gid: int
    size: int | None
    mtime_ns: int
    sha256: str | None = None
    symlink_target: str | None = None


class RootfsDiffError(RuntimeError):
    pass


def snapshot_rootfs(rootfs: str | Path) -> dict[str, Any]:
    rootfs = Path(rootfs)

    if not rootfs.exists():
        raise RootfsDiffError(f"rootfs does not exist: {rootfs}")

    if not rootfs.is_dir():
        raise RootfsDiffError(f"rootfs is not a directory: {rootfs}")

    entries: dict[str, dict[str, Any]] = {}

    for current_dir, dir_names, file_names in os.walk(rootfs, topdown=True, followlinks=False):
        current_path = Path(current_dir)

        # Deterministic order.
        dir_names.sort()
        file_names.sort()

        for name in dir_names:
            path = current_path / name
            entry = inspect_path(rootfs=rootfs, path=path)
            entries[entry.path] = asdict(entry)

        for name in file_names:
            path = current_path / name
            entry = inspect_path(rootfs=rootfs, path=path)
            entries[entry.path] = asdict(entry)

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "rootfs": str(rootfs),
        "entries_count": len(entries),
        "entries": entries,
    }


def inspect_path(rootfs: Path, path: Path) -> RootfsEntry:
    try:
        st = path.lstat()
    except FileNotFoundError:
        raise RootfsDiffError(f"path disappeared during snapshot: {path}")

    guest_path = "/" + str(path.relative_to(rootfs))

    mode = stat.S_IMODE(st.st_mode)

    if stat.S_ISREG(st.st_mode):
        return RootfsEntry(
            path=guest_path,
            type="file",
            mode=mode,
            uid=st.st_uid,
            gid=st.st_gid,
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
            sha256=sha256_file(path),
        )

    if stat.S_ISDIR(st.st_mode):
        return RootfsEntry(
            path=guest_path,
            type="dir",
            mode=mode,
            uid=st.st_uid,
            gid=st.st_gid,
            size=None,
            mtime_ns=st.st_mtime_ns,
        )

    if stat.S_ISLNK(st.st_mode):
        return RootfsEntry(
            path=guest_path,
            type="symlink",
            mode=mode,
            uid=st.st_uid,
            gid=st.st_gid,
            size=None,
            mtime_ns=st.st_mtime_ns,
            symlink_target=os.readlink(path),
        )

    return RootfsEntry(
        path=guest_path,
        type="special",
        mode=mode,
        uid=st.st_uid,
        gid=st.st_gid,
        size=None,
        mtime_ns=st.st_mtime_ns,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)

    return digest.hexdigest()


def diff_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_entries = before.get("entries", {})
    after_entries = after.get("entries", {})

    before_paths = set(before_entries)
    after_paths = set(after_entries)

    created_paths = sorted(after_paths - before_paths)
    deleted_paths = sorted(before_paths - after_paths)
    common_paths = sorted(before_paths & after_paths)

    created = [after_entries[path] for path in created_paths]
    deleted = [before_entries[path] for path in deleted_paths]

    modified = []

    for path in common_paths:
        old = before_entries[path]
        new = after_entries[path]

        changes = compare_entries(old, new)

        if changes:
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
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "rootfs_before": before.get("rootfs"),
        "rootfs_after": after.get("rootfs"),
        "created_count": len(created),
        "modified_count": len(modified),
        "deleted_count": len(deleted),
        "created": created,
        "modified": modified,
        "deleted": deleted,
    }


def compare_entries(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}

    fields = [
        "type",
        "mode",
        "uid",
        "gid",
        "size",
        "sha256",
        "symlink_target",
    ]

    for field in fields:
        if old.get(field) != new.get(field):
            changes[field] = {
                "before": old.get(field),
                "after": new.get(field),
            }

    # mtime-only changes are useful, but noisy. Keep them separate and only
    # report them if no content/metadata change was detected.
    if not changes and old.get("mtime_ns") != new.get("mtime_ns"):
        changes["mtime_ns"] = {
            "before": old.get("mtime_ns"),
            "after": new.get("mtime_ns"),
        }

    return changes


def save_json(data: dict[str, Any], out_path: str | Path) -> None:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_json(path: str | Path) -> dict[str, Any]:
    path = Path(path)

    if not path.exists():
        raise RootfsDiffError(f"file does not exist: {path}")

    return json.loads(path.read_text(encoding="utf-8"))
