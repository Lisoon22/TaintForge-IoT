from __future__ import annotations

import struct
from pathlib import Path


def write_elf(
    path: Path,
    *,
    arch: str = "x86_64",
    interpreter: str | None = None,
    pie: bool = False,
    executable: bool = True,
) -> Path:
    machines = {
        "i386": (1, 1, 3),
        "x86_64": (2, 1, 62),
        "arm": (1, 1, 40),
        "aarch64": (2, 1, 183),
        "mips": (1, 2, 8),
        "mipsel": (1, 1, 8),
    }
    elf_class_raw, data_raw, machine = machines[arch]
    byte_order = "<" if data_raw == 1 else ">"
    e_type = 3 if pie else 2
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = elf_class_raw
    ident[5] = data_raw
    ident[6] = 1

    interp_raw = (
        interpreter.encode("utf-8") + b"\x00"
        if interpreter is not None
        else b""
    )

    if elf_class_raw == 1:
        header_size = 52
        phentsize = 32
        phnum = 1 if interpreter is not None else 0
        phoff = header_size if phnum else 0
        interp_offset = header_size + phentsize if phnum else 0
        header = struct.pack(
            byte_order + "16sHHIIIIIHHHHHH",
            bytes(ident),
            e_type,
            machine,
            1,
            0x1000,
            phoff,
            0,
            0,
            header_size,
            phentsize,
            phnum,
            0,
            0,
            0,
        )
        phdr = (
            struct.pack(
                byte_order + "IIIIIIII",
                3,
                interp_offset,
                0,
                0,
                len(interp_raw),
                len(interp_raw),
                4,
                1,
            )
            if phnum
            else b""
        )
    else:
        header_size = 64
        phentsize = 56
        phnum = 1 if interpreter is not None else 0
        phoff = header_size if phnum else 0
        interp_offset = header_size + phentsize if phnum else 0
        header = struct.pack(
            byte_order + "16sHHIQQQIHHHHHH",
            bytes(ident),
            e_type,
            machine,
            1,
            0x400000,
            phoff,
            0,
            0,
            header_size,
            phentsize,
            phnum,
            0,
            0,
            0,
        )
        phdr = (
            struct.pack(
                byte_order + "IIQQQQQQ",
                3,
                4,
                interp_offset,
                0,
                0,
                len(interp_raw),
                len(interp_raw),
                1,
            )
            if phnum
            else b""
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + phdr + interp_raw)
    path.chmod(0o755 if executable else 0o644)
    return path
