from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


QEMU_STATIC_BY_ARCH = {
    "arm": "qemu-arm-static",
    "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static",
    "mipsel": "qemu-mipsel-static",
}


@dataclass(slots=True)
class RuntimeConfig:
    arch: str
    rootfs: str

    host_binary_path: str
    guest_binary_path: str

    qemu_required: bool
    qemu_binary_name: Optional[str]
    qemu_host_path: Optional[str]
    qemu_guest_path: Optional[str]

    libraries_ok: bool
    library_resolution_path: Optional[str]


class RuntimePreparationError(RuntimeError):
    pass


class RuntimePreparer:
    def __init__(self, out_dir: str | Path,arch: str, binary_path: str | Path, library_resolution_path: str | Path | None = None, allow_missing_libraries: bool = False):
        self.out_dir = Path(out_dir)
        self.rootfs = self.out_dir / "rootfs"
        self.arch = arch
        self.binary_path = Path(binary_path)
        self.library_resolution_path = (
            Path(library_resolution_path)
            if library_resolution_path is not None
            else None)
        self.allow_missing_libraries = allow_missing_libraries

    def prepare(self) -> RuntimeConfig:
        self._validate_rootfs()
        self._validate_binary()
        libraries_ok = self._check_libraries()

        guest_binary_path = self._copy_target_binary()

        qemu_required = self.arch in QEMU_STATIC_BY_ARCH
        qemu_binary_name = None
        qemu_host_path = None
        qemu_guest_path = None

        if qemu_required:
            qemu_binary_name = QEMU_STATIC_BY_ARCH[self.arch]
            qemu_host = self._find_executable(qemu_binary_name)

            if qemu_host is None:
                raise RuntimePreparationError(
                    f"Required QEMU binary not found: {qemu_binary_name}. "
                    f"Install qemu-user-static or ensure it is in PATH."
                )

            qemu_host_path = str(qemu_host)
            qemu_guest_path = self._copy_qemu_static(qemu_host)

        config = RuntimeConfig(
            arch=self.arch,
            rootfs=str(self.rootfs),
            host_binary_path=str(self.binary_path),
            guest_binary_path=guest_binary_path,
            qemu_required=qemu_required,
            qemu_binary_name=qemu_binary_name,
            qemu_host_path=qemu_host_path,
            qemu_guest_path=qemu_guest_path,
            libraries_ok=libraries_ok,
            library_resolution_path=(
                str(self.library_resolution_path)
                if self.library_resolution_path is not None
                else None)
        )

        self._save_runtime_config(config)

        return config

    def _validate_rootfs(self) -> None:
        if not self.rootfs.exists():
            raise RuntimePreparationError(f"rootfs does not exist: {self.rootfs}")

        if not self.rootfs.is_dir():
            raise RuntimePreparationError(f"rootfs path is not a directory: {self.rootfs}")

    def _validate_binary(self) -> None:
        if not self.binary_path.exists():
            raise RuntimePreparationError(f"binary does not exist: {self.binary_path}")

        if not self.binary_path.is_file():
            raise RuntimePreparationError(f"binary path is not a file: {self.binary_path}")

    def _check_libraries(self) -> bool:
        if self.library_resolution_path is None:
            return True

        if not self.library_resolution_path.exists():
            raise RuntimePreparationError(f"library resolution file does not exist: {self.library_resolution_path}")

        raw = json.loads(self.library_resolution_path.read_text(encoding="utf-8"))

        missing = raw.get("missing", [])

        if missing and not self.allow_missing_libraries:
            missing_names = [
                item.get("name", "<unknown>")
                for item in missing
            ]

            raise RuntimePreparationError(
                "Missing libraries detected: " + ", ".join(missing_names) + ". Use --allow-missing-libraries to continue anyway.")

        return not bool(missing)

    def _copy_target_binary(self) -> str:
        guest_bin_dir = self.rootfs / "bin"
        guest_bin_dir.mkdir(parents=True, exist_ok=True)

        dst = guest_bin_dir / "unpacked.elf"
        shutil.copy2(self.binary_path, dst)
        dst.chmod(0o755)

        return "/bin/unpacked.elf"

    def _copy_qemu_static(self, qemu_host_path: Path) -> str:
        guest_qemu_dir = self.rootfs / "usr/bin"
        guest_qemu_dir.mkdir(parents=True, exist_ok=True)

        dst = guest_qemu_dir / qemu_host_path.name
        shutil.copy2(qemu_host_path, dst)
        dst.chmod(0o755)

        return f"/usr/bin/{qemu_host_path.name}"

    def _find_executable(self, name: str) -> Optional[Path]:
        found = shutil.which(name)

        if found is None:
            return None

        return Path(found)

    def _save_runtime_config(self, config: RuntimeConfig) -> None:
        config_dir = self.out_dir / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        path = config_dir / "runtime.json"
        path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
