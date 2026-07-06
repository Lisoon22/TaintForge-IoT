from __future__ import annotations

import os
import struct
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any


class ElfTargetError(RuntimeError):
    """Raised when an ELF target cannot be described safely."""


_ELF_MACHINE_NAMES = {
    3: "i386",
    8: "mips",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
}

_ELF_TYPE_NAMES = {
    0: "none",
    1: "relocatable",
    2: "executable",
    3: "shared_object",
    4: "core",
}

_ARCH_ALIASES = {
    "386": "i386",
    "i386": "i386",
    "i486": "i386",
    "i586": "i386",
    "i686": "i386",
    "x86": "i386",
    "x86_32": "i386",
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86_64": "x86_64",
    "arm": "arm",
    "arm32": "arm",
    "armel": "arm",
    "armhf": "arm",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "mips": "mips",
    "mipseb": "mips",
    "mips32": "mips",
    "mipsel": "mipsel",
    "mipsle": "mipsel",
}


@dataclass(slots=True, frozen=True)
class ElfTargetDescriptor:
    path: str
    sha256: str
    elf_class: int
    endianness: str
    machine_id: int
    machine: str
    arch: str
    file_type_id: int
    file_type: str
    interpreter: str | None
    static: bool
    pie: bool
    entry_point: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_arch(value: str) -> str:
    normalized = str(value).strip().lower().replace("-", "_")
    try:
        return _ARCH_ALIASES[normalized]
    except KeyError as exc:
        raise ElfTargetError(f"unsupported architecture label: {value!r}") from exc


def inspect_elf_target(path: str | Path) -> ElfTargetDescriptor:
    target = Path(path).resolve(strict=False)
    if target.is_symlink():
        raise ElfTargetError(f"ELF target must not be a symlink: {target}")
    if not target.is_file():
        raise ElfTargetError(f"ELF target does not exist: {target}")

    size = target.stat().st_size
    if size < 52:
        raise ElfTargetError(f"ELF target is too small: {target}")

    with target.open("rb") as stream:
        ident = stream.read(16)
        if len(ident) != 16 or ident[:4] != b"\x7fELF":
            raise ElfTargetError(f"not an ELF file: {target}")

        elf_class_raw = ident[4]
        if elf_class_raw == 1:
            elf_class = 32
            header_size = 52
        elif elf_class_raw == 2:
            elf_class = 64
            header_size = 64
        else:
            raise ElfTargetError(
                f"unsupported ELF class {elf_class_raw}: {target}"
            )

        data_raw = ident[5]
        if data_raw == 1:
            byte_order = "<"
            endianness = "little"
        elif data_raw == 2:
            byte_order = ">"
            endianness = "big"
        else:
            raise ElfTargetError(
                f"unsupported ELF data encoding {data_raw}: {target}"
            )

        stream.seek(0)
        header = stream.read(header_size)
        if len(header) != header_size:
            raise ElfTargetError(f"truncated ELF header: {target}")

        if elf_class == 32:
            values = struct.unpack(
                byte_order + "16sHHIIIIIHHHHHH",
                header,
            )
            (
                _ident,
                e_type,
                e_machine,
                _e_version,
                e_entry,
                e_phoff,
                _e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                _e_shentsize,
                _e_shnum,
                _e_shstrndx,
            ) = values
            expected_phentsize = 32
        else:
            values = struct.unpack(
                byte_order + "16sHHIQQQIHHHHHH",
                header,
            )
            (
                _ident,
                e_type,
                e_machine,
                _e_version,
                e_entry,
                e_phoff,
                _e_shoff,
                _e_flags,
                _e_ehsize,
                e_phentsize,
                e_phnum,
                _e_shentsize,
                _e_shnum,
                _e_shstrndx,
            ) = values
            expected_phentsize = 56

        if e_phnum > 4096:
            raise ElfTargetError(
                f"unreasonable ELF program-header count {e_phnum}: {target}"
            )
        if e_phnum and e_phentsize < expected_phentsize:
            raise ElfTargetError(
                f"invalid ELF program-header size {e_phentsize}: {target}"
            )
        if e_phnum:
            end = e_phoff + e_phentsize * e_phnum
            if e_phoff < header_size or end > size:
                raise ElfTargetError(
                    f"ELF program-header table is out of bounds: {target}"
                )

        interpreter: str | None = None
        for index in range(e_phnum):
            stream.seek(e_phoff + index * e_phentsize)
            raw = stream.read(e_phentsize)
            if len(raw) != e_phentsize:
                raise ElfTargetError(
                    f"truncated ELF program header {index}: {target}"
                )
            if elf_class == 32:
                fields = struct.unpack(
                    byte_order + "IIIIIIII",
                    raw[:expected_phentsize],
                )
                p_type = fields[0]
                p_offset = fields[1]
                p_filesz = fields[4]
            else:
                fields = struct.unpack(
                    byte_order + "IIQQQQQQ",
                    raw[:expected_phentsize],
                )
                p_type = fields[0]
                p_offset = fields[2]
                p_filesz = fields[5]

            if p_type != 3:  # PT_INTERP
                continue
            if interpreter is not None:
                raise ElfTargetError(
                    f"multiple PT_INTERP entries are not supported: {target}"
                )
            if p_filesz < 2 or p_filesz > 4096:
                raise ElfTargetError(
                    f"invalid PT_INTERP size {p_filesz}: {target}"
                )
            if p_offset + p_filesz > size:
                raise ElfTargetError(
                    f"PT_INTERP is out of bounds: {target}"
                )
            stream.seek(p_offset)
            raw_interp = stream.read(p_filesz)
            if len(raw_interp) != p_filesz:
                raise ElfTargetError(f"truncated PT_INTERP: {target}")
            if not raw_interp.endswith(b"\x00"):
                raise ElfTargetError(
                    f"PT_INTERP is not NUL terminated: {target}"
                )
            try:
                decoded = raw_interp[:-1].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ElfTargetError(
                    f"PT_INTERP is not valid UTF-8: {target}"
                ) from exc
            interpreter = _validate_interpreter(decoded)

    machine = _ELF_MACHINE_NAMES.get(e_machine, f"unknown_{e_machine}")
    if e_machine == 8:
        arch = "mipsel" if endianness == "little" else "mips"
    else:
        arch = machine

    return ElfTargetDescriptor(
        path=str(target),
        sha256=_sha256_file(target),
        elf_class=elf_class,
        endianness=endianness,
        machine_id=e_machine,
        machine=machine,
        arch=arch,
        file_type_id=e_type,
        file_type=_ELF_TYPE_NAMES.get(e_type, f"unknown_{e_type}"),
        interpreter=interpreter,
        static=interpreter is None,
        pie=e_type == 3,
        entry_point=e_entry,
    )


def guest_path_exists(rootfs: str | Path, guest_path: str) -> bool:
    """Resolve a guest path without allowing symlinks to escape the rootfs."""

    root = Path(rootfs).resolve(strict=False)
    if not root.is_dir() or root.is_symlink():
        return False
    try:
        pure = _validate_guest_path(guest_path)
    except ElfTargetError:
        return False

    pending = list(pure.parts[1:])
    resolved_parts: list[str] = []
    symlink_budget = 40

    while pending:
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved_parts:
                return False
            resolved_parts.pop()
            continue

        candidate = root.joinpath(*resolved_parts, part)
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            return False

        if not os.path.islink(candidate):
            resolved_parts.append(part)
            continue

        symlink_budget -= 1
        if symlink_budget < 0:
            return False
        try:
            link = os.readlink(candidate)
        except OSError:
            return False
        link_path = PurePosixPath(link)
        if link_path.is_absolute():
            resolved_parts = []
        replacement = list(link_path.parts)
        if link_path.is_absolute() and replacement and replacement[0] == "/":
            replacement = replacement[1:]
        pending = replacement + pending

    final = root.joinpath(*resolved_parts)
    try:
        final.relative_to(root)
    except ValueError:
        return False
    return final.exists() or final.is_symlink()


def _validate_guest_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ElfTargetError("guest path must be an absolute POSIX path")
    path = PurePosixPath(value)
    if any(part == ".." for part in path.parts):
        raise ElfTargetError("guest path must not contain '..'")
    if str(path) != value:
        raise ElfTargetError("guest path must be normalized")
    return path


def _validate_interpreter(value: str) -> str:
    path = _validate_guest_path(value)
    if path == PurePosixPath("/"):
        raise ElfTargetError("PT_INTERP must name a file")
    return str(path)


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
