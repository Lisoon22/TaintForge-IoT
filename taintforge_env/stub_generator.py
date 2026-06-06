from pathlib import Path
import os

from .models import FileDependency


class StubFilesystemGenerator:
    def __init__(self, out_dir: str | Path, arch: str):
        self.out_dir = Path(out_dir)
        self.rootfs = self.out_dir / "rootfs"
        self.arch = arch

    def generate(self, file_dependencies: list[FileDependency]) -> None:
        self.generate_base_tree()
        self.generate_default_stubs()

        for dependency in file_dependencies:
            self.create_stub_for_dependency(dependency)

    def generate_base_tree(self) -> None:
        directories = [
            "proc",
            "dev",
            "tmp",
            "var",
            "var/run",
            "etc",
            "lib",
            "usr",
            "usr/lib",
            "bin",
        ]

        for directory in directories:
            path = self.rootfs / directory
            path.mkdir(parents=True, exist_ok=True)

    def generate_default_stubs(self) -> None:
        self.create_proc_stub("/proc/cpuinfo")
        self.create_proc_stub("/proc/meminfo")
        self.create_proc_stub("/proc/uptime")

        self.create_dev_stub("/dev/null")
        self.create_dev_stub("/dev/zero")
        self.create_dev_stub("/dev/urandom")

        self.create_config_stub("/etc/hosts")
        self.create_config_stub("/etc/resolv.conf")

    def create_stub_for_dependency(self, dep: FileDependency) -> None:
        guest_path = dep.path

        if guest_path.startswith("/proc/"):
            self.create_proc_stub(guest_path)
        elif guest_path.startswith("/dev/"):
            self.create_dev_stub(guest_path)
        elif guest_path.startswith("/etc/"):
            self.create_config_stub(guest_path)
        elif guest_path.startswith("/tmp/"):
            self.create_runtime_stub(guest_path)
        elif guest_path.startswith("/var/"):
            self.create_runtime_stub(guest_path)
        else:
            self.create_generic_stub(guest_path)

    def rootfs_path(self, guest_path: str) -> Path:
        relative = guest_path.lstrip("/")
        return self.rootfs / relative

    def create_proc_stub(self, guest_path: str) -> None:
        target = self.rootfs_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if guest_path == "/proc/cpuinfo":
            content = self.cpuinfo_content()
        elif guest_path == "/proc/meminfo":
            content = self.meminfo_content()
        elif guest_path == "/proc/uptime":
            content = self.uptime_content()
        elif guest_path == "/proc/self/maps":
            content = self.proc_self_maps_content()
        else:
            content = ""

        target.write_text(content, encoding="utf-8")

    def cpuinfo_content(self) -> str:
        if self.arch in {"arm", "aarch64"}:
            return (
                "Processor       : ARMv7 Processor rev 1 (v7l)\n"
                "BogoMIPS        : 38.40\n"
                "Features        : half thumb fastmult vfp edsp neon vfpv3 tls\n"
                "CPU implementer : 0x41\n"
                "CPU architecture: 7\n"
                "Hardware        : Generic IoT Board\n"
                "Revision        : 0000\n"
                "Serial          : 0000000000000000\n"
            )

        if self.arch in {"mips", "mipsel"}:
            return (
                "system type             : Atheros AR9330 rev 1\n"
                "machine                 : Generic MIPS IoT Router\n"
                "processor               : 0\n"
                "cpu model               : MIPS 24Kc V7.4\n"
                "BogoMIPS                : 265.42\n"
                "wait instruction        : yes\n"
                "microsecond timers      : yes\n"
            )

        return (
            "processor   : 0\n"
            "vendor_id   : GenuineIntel\n"
            "model name  : Generic Embedded CPU\n"
        )

    def meminfo_content(self) -> str:
        return (
            "MemTotal:          65536 kB\n"
            "MemFree:           32768 kB\n"
            "MemAvailable:      49152 kB\n"
            "Buffers:            1024 kB\n"
            "Cached:             8192 kB\n"
            "SwapCached:            0 kB\n"
        )

    def uptime_content(self) -> str:
        return "86400.00 43000.00\n"

    def proc_self_maps_content(self) -> str:
        return (
            "00400000-0040b000 r-xp 00000000 00:00 0 /bin/unpacked.elf\n"
            "0041b000-0041d000 rw-p 0000b000 00:00 0 /bin/unpacked.elf\n"
            "7fff0000-80000000 rw-p 00000000 00:00 0 [stack]\n"
        )

    def create_dev_stub(self, guest_path: str) -> None:
        target = self.rootfs_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if guest_path == "/dev/null":
            target.write_bytes(b"")
        elif guest_path == "/dev/zero":
            target.write_bytes(b"\x00" * 4096)
        elif guest_path == "/dev/urandom":
            target.write_bytes(os.urandom(4096))
        else:
            target.write_bytes(b"")

    def create_config_stub(self, guest_path: str) -> None:
        target = self.rootfs_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if guest_path == "/etc/hosts":
            content = (
                "127.0.0.1 localhost\n"
                "127.0.0.1 stub-c2.local\n"
            )
        elif guest_path == "/etc/resolv.conf":
            content = "nameserver 127.0.0.1\n"
        else:
            content = ""

        target.write_text(content, encoding="utf-8")

    def create_runtime_stub(self, guest_path: str) -> None:
        target = self.rootfs_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if guest_path.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
            return

        target.write_text("", encoding="utf-8")

    def create_generic_stub(self, guest_path: str) -> None:
        target = self.rootfs_path(guest_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        if guest_path.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.write_text("", encoding="utf-8")
