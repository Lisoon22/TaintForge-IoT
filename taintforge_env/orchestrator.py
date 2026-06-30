from __future__ import annotations
import textwrap
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .c2_record_policy import (
    C2RecordPolicy,
    C2RecordPolicyError,
    load_c2_record_policy,
)
from .egress_policy import EgressPolicy, EgressPolicyError, load_egress_policy
from .network_modes import (
    NetworkMode,
    requires_egress_policy,
    requires_record_policy,
)
from .run_manifest import (
    build_run_manifest,
    create_run_id,
    save_run_manifest,
)


class OrchestratorError(RuntimeError):
    pass


@dataclass(slots=True)
class OrchestratorConfig:
    taint_path: Path
    binary_path: Path
    sysroot_path: Path
    out_dir: Path

    timeout_seconds: int = 60
    network_mode: NetworkMode = NetworkMode.EMULATED
    egress_policy_path: Path | None = None
    record_policy_path: Path | None = None

    bind_ip: str = "10.10.0.1"
    namespace: str = "tf-iot-ns"
    catch_all_port: int = 40000
    udp_catch_all_port: int = 40001

    build_only: bool = False
    keep_namespace: bool = False
    keep_workdir: bool = False
    allow_missing_libraries: bool = False
    self_test_network: bool = False


class Phase2Orchestrator:
    def __init__(self, config: OrchestratorConfig):
        self.config = config
        self.project_root = Path.cwd()

        self.config_dir = self.config.out_dir / "config"
        self.logs_dir = self.config.out_dir / "logs"
        self.rootfs_dir = self.config.out_dir / "rootfs"

        self.run_id = create_run_id(self.config.binary_path)

        self.network_policy_path = self.config_dir / "network_policy.json"
        self.library_plan_path = self.config_dir / "library_plan.json"
        self.library_resolution_path = self.config_dir / "library_resolution.json"
        self.runtime_path = self.config_dir / "runtime.json"
        self.runtime_requirements_path = (
            self.config_dir / "runtime_requirements.json"
        )
        self.repair_plan_path = self.config_dir / "repair_plan.json"
        self.network_runner_path = self.config.out_dir / "run_network_sandbox.sh"
        self.run_manifest_path = self.config_dir / "run_manifest.json"
        self.copied_egress_policy_path = self.config_dir / "egress_policy.json"
        self.copied_record_policy_path = self.config_dir / "c2_record_policy.json"
        self.c2_capture_dir = self.config.out_dir / "captures" / self.run_id
        self.c2_broker_events_path = self.logs_dir / "c2_record_events.jsonl"

        self.egress_policy: EgressPolicy | None = None
        self.record_policy: C2RecordPolicy | None = None
        self.original_ip_forward: str | None = None
            
        self.processes: list[subprocess.Popen] = []


    def run_runtime_observer(self, phase: str) -> None:
        if phase not in {"before", "finalize"}:
            raise OrchestratorError(f"Unsupported observation phase: {phase}")

        print(f"[+] Runtime observation phase: {phase}")
        self.run_command(
            [
                "sudo",
                "env",
                f"PYTHONPATH={self.project_root}",
                sys.executable,
                "scripts/capture_runtime_observations.py",
                phase,
                "--run-dir",
                str(self.config.out_dir),
                "--rootfs",
                str(self.rootfs_dir),
            ]
        )



    def run_repair_planner(self) -> None:
        print("[+] Building passive repair plan")
        self.run_command(
            [
                sys.executable,
                "scripts/plan_repairs.py",
                "--requirements",
                str(self.runtime_requirements_path),
                "--out",
                str(self.repair_plan_path),
            ]
        )


    def clear_network_self_test_artifacts(self) -> None:
        print(
            "[+] Clearing network self-test artifacts "
            "before malware run"
        )

        events_path = self.logs_dir / "network_events.jsonl"
        archived_path = (
            self.logs_dir / "network_self_test_events.jsonl"
        )

        if events_path.exists():
            archived_path.unlink(missing_ok=True)
            events_path.replace(archived_path)

        events_path.parent.mkdir(parents=True, exist_ok=True)
        events_path.touch(exist_ok=True)

        for pattern in [
            "tcp_*_conn_*.bin",
            "catchall_tcp_*_conn_*.bin",
            "udp_*_datagram_*.bin",
        ]:
            for path in self.logs_dir.glob(pattern):
                path.unlink(missing_ok=True)

    def parse_strace_logs(self) -> None:
        print("[+] Parsing strace logs")

        self.run_command(
            [
                sys.executable,
                "scripts/parse_strace.py",
                "--log-dir",
                str(self.logs_dir),
                "--out",
                str(self.logs_dir / "syscall_events.jsonl"),
            ],
            check=False,
        )

    def run(self) -> None:
        self.print_header()

        try:
            self.check_dependencies()
            self.validate_network_configuration()
            self.prepare_workdir()
            self.copy_egress_policy_if_needed()
            self.copy_record_policy_if_needed()
            self.write_run_manifest()

            self.build_environment()

            if self.config.build_only:
                self.print_build_summary()
                return

            if self.config.network_mode == NetworkMode.NONE:
                self.ensure_sudo()
                self.run_runtime_observer("before")
                self.run_sample_direct()
                self.make_runtime_artifacts_readable()
                self.parse_strace_logs()
                self.run_runtime_observer("finalize")
                self.run_repair_planner()
                self.generate_report()
                self.print_run_summary()
                return

            if self.config.network_mode == NetworkMode.BROKERED_RECORD:
                self.ensure_sudo()
                self.disable_host_ip_forwarding()

                self.setup_network_namespace()
                self.start_transparent_logger()
                self.start_c2_record_broker()
                self.wait_for_transparent_logger()
                self.wait_for_c2_record_broker()

                self.run_runtime_observer("before")
                self.run_sample()
                self.make_runtime_artifacts_readable()
                self.parse_strace_logs()
                self.run_runtime_observer("finalize")
                self.run_repair_planner()
                self.generate_report()
                self.print_run_summary()
                return

            if self.config.network_mode == NetworkMode.REPLAY:
                raise OrchestratorError(
                    "Replay network backend is not implemented yet. "
                    "The mode is reserved and fails closed."
                )

            if self.config.network_mode == NetworkMode.BROKERED_FETCH:
                raise OrchestratorError(
                    "brokered_fetch policy is valid, but the egress broker "
                    "backend is not implemented yet. No internet access was enabled."
                )

            if self.config.network_mode == NetworkMode.BROKERED_RELAY:
                raise OrchestratorError(
                    "brokered_relay is intentionally disabled. "
                    "Implement bounded relay only after brokered_fetch and replay."
                )

            if self.config.network_mode != NetworkMode.EMULATED:
                raise OrchestratorError(
                    f"Unsupported network mode: {self.config.network_mode.value}"
                )

            self.ensure_sudo()
            self.disable_host_ip_forwarding()

            self.setup_network_namespace()
            self.start_transparent_logger()
            self.start_known_network_emulator()
            self.wait_for_transparent_logger()
            self.wait_for_known_emulator_if_needed()

            if self.config.self_test_network:
                self.run_network_self_test()
                self.clear_network_self_test_artifacts()

            self.run_runtime_observer("before")
            self.run_sample()

            self.make_runtime_artifacts_readable()

            self.parse_strace_logs()
            self.run_runtime_observer("finalize")
            self.run_repair_planner()
            self.generate_report()

            self.print_run_summary()

        finally:
            self.stop_processes()

            if not self.config.keep_namespace:
                self.cleanup_network_namespace()

            self.restore_host_ip_forwarding()
            self.fix_output_ownership()

    def print_header(self) -> None:
        print("[+] TaintForge-IoT Phase 2 orchestrator")
        print(f"[+] taint:   {self.config.taint_path}")
        print(f"[+] binary:  {self.config.binary_path}")
        print(f"[+] sysroot: {self.config.sysroot_path}")
        print(f"[+] out:     {self.config.out_dir}")
        print(f"[+] run id:  {self.run_id}")
        print(f"[+] network: {self.config.network_mode.value}")
        print()

    def check_dependencies(self) -> None:
        print("[+] Checking dependencies")

        required = [
            "readelf",
            "sudo",
            "strace",
            "timeout",
            "chroot",
            "mount",
            "unshare",
            "hostname",
            "bash",
        ]

        if self.config.network_mode in {
            NetworkMode.EMULATED,
            NetworkMode.BROKERED_RECORD,
        }:
            required.extend([
                "ip",
                "iptables",
                "ss",
                "conntrack",
            ])

        missing = [tool for tool in required if shutil.which(tool) is None]

        if missing:
            raise OrchestratorError(
                "Missing required tools: " + ", ".join(missing)
            )

        self.require_file(self.config.taint_path, "taint file")
        self.require_file(self.config.binary_path, "binary file")

        if not self.config.sysroot_path.exists():
            raise OrchestratorError(f"sysroot not found: {self.config.sysroot_path}")

    def validate_network_configuration(self) -> None:
        if requires_record_policy(self.config.network_mode):
            if self.config.record_policy_path is None:
                raise OrchestratorError(
                    "brokered_record requires a record policy"
                )
            if self.config.egress_policy_path is not None:
                raise OrchestratorError(
                    "brokered_record cannot use an egress policy"
                )
            if self.config.self_test_network:
                raise OrchestratorError(
                    "--self-test-network is disabled in brokered_record mode; "
                    "use the dedicated local broker smoke test first"
                )
            try:
                self.record_policy = load_c2_record_policy(
                    self.config.record_policy_path
                )
            except C2RecordPolicyError as exc:
                raise OrchestratorError(
                    f"Invalid record policy: {exc}"
                ) from exc
            return

        if self.config.record_policy_path is not None:
            raise OrchestratorError(
                "record_policy_path is only allowed for brokered_record"
            )

        if requires_egress_policy(self.config.network_mode):
            if self.config.egress_policy_path is None:
                raise OrchestratorError(
                    f"Network mode {self.config.network_mode.value} "
                    "requires an egress policy"
                )

            try:
                policy = load_egress_policy(
                    self.config.egress_policy_path
                )
            except EgressPolicyError as exc:
                raise OrchestratorError(
                    f"Invalid egress policy: {exc}"
                ) from exc

            if policy.mode != self.config.network_mode:
                raise OrchestratorError(
                    "Egress policy mode mismatch: "
                    f"policy={policy.mode.value}, "
                    f"network={self.config.network_mode.value}"
                )

            self.egress_policy = policy
            return

        if self.config.egress_policy_path is not None:
            raise OrchestratorError(
                "egress_policy_path is only allowed for "
                "brokered_fetch or brokered_relay"
            )

    def copy_egress_policy_if_needed(self) -> None:
        if self.config.egress_policy_path is None:
            return

        shutil.copy2(
            self.config.egress_policy_path,
            self.copied_egress_policy_path,
        )

    def copy_record_policy_if_needed(self) -> None:
        if self.config.record_policy_path is None:
            return
        shutil.copy2(
            self.config.record_policy_path,
            self.copied_record_policy_path,
        )

    def record_policy_summary(self) -> dict | None:
        if self.record_policy is None:
            return None
        return {
            "capture_kind": self.record_policy.capture_kind,
            "default_action": self.record_policy.default_action,
            "listen_port": self.record_policy.listen_port,
            "original_remote_ip": self.record_policy.target.original_ip,
            "original_remote_port": self.record_policy.target.original_port,
            "upstream_ip": self.record_policy.target.upstream_ip,
            "upstream_port": self.record_policy.target.upstream_port,
            "limits": {
                "max_connections": self.record_policy.limits.max_connections,
                "connect_timeout_seconds": self.record_policy.limits.connect_timeout_seconds,
                "session_timeout_seconds": self.record_policy.limits.session_timeout_seconds,
                "idle_timeout_seconds": self.record_policy.limits.idle_timeout_seconds,
                "max_client_bytes": self.record_policy.limits.max_client_bytes,
                "max_server_bytes": self.record_policy.limits.max_server_bytes,
            },
        }

    def egress_policy_summary(self) -> dict | None:
        if self.egress_policy is None:
            return None

        return {
            "mode": self.egress_policy.mode.value,
            "default_action": self.egress_policy.default_action,
            "rules_count": len(self.egress_policy.rules),
            "blocked_ports_count": len(
                self.egress_policy.blocked_ports
            ),
            "block_non_global_ips": (
                self.egress_policy.block_non_global_ips
            ),
            "global_limits": {
                "max_connections": (
                    self.egress_policy.global_limits.max_connections
                ),
                "max_uploaded_bytes": (
                    self.egress_policy.global_limits.max_uploaded_bytes
                ),
                "max_downloaded_bytes": (
                    self.egress_policy.global_limits.max_downloaded_bytes
                ),
                "max_duration_seconds": (
                    self.egress_policy.global_limits.max_duration_seconds
                ),
                "requests_per_second": (
                    self.egress_policy.global_limits.requests_per_second
                ),
            },
        }

    def write_run_manifest(self) -> None:
        policy_path = (
            self.copied_egress_policy_path
            if self.copied_egress_policy_path.exists()
            else None
        )

        manifest = build_run_manifest(
            run_id=self.run_id,
            taint_path=self.config.taint_path,
            binary_path=self.config.binary_path,
            sysroot_path=self.config.sysroot_path,
            out_dir=self.config.out_dir,
            network_mode=self.config.network_mode.value,
            timeout_seconds=self.config.timeout_seconds,
            bind_ip=self.config.bind_ip,
            namespace=self.config.namespace,
            catch_all_port=self.config.catch_all_port,
            udp_catch_all_port=self.config.udp_catch_all_port,
            build_only=self.config.build_only,
            allow_missing_libraries=(
                self.config.allow_missing_libraries
            ),
            self_test_network=self.config.self_test_network,
            egress_policy_path=policy_path,
            egress_policy_summary=self.egress_policy_summary(),
        )

        save_run_manifest(manifest, self.run_manifest_path)

        if self.record_policy is not None:
            raw_manifest = json.loads(
                self.run_manifest_path.read_text(encoding="utf-8")
            )
            raw_manifest["c2_record"] = {
                "policy_path": str(self.copied_record_policy_path),
                "capture_dir": str(self.c2_capture_dir),
                "summary": self.record_policy_summary(),
            }
            self.run_manifest_path.write_text(
                json.dumps(raw_manifest, indent=2) + "\n",
                encoding="utf-8",
            )

        print(f"[+] Run manifest: {self.run_manifest_path}")

    @staticmethod
    def require_file(path: Path, description: str) -> None:
        if not path.exists():
            raise OrchestratorError(f"{description} not found: {path}")
        if not path.is_file():
            raise OrchestratorError(f"{description} is not a file: {path}")

    def prepare_workdir(self) -> None:
        print("[+] Preparing workdir")

        if self.config.out_dir.exists() and not self.config.keep_workdir:
            shutil.rmtree(self.config.out_dir)

        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

    def build_environment(self) -> None:
        self.reconstruct_env()

        if self.config.network_mode == NetworkMode.BROKERED_RECORD:
            self.configure_record_network_policy()

        self.analyze_libraries()
        self.resolve_libraries()
        self.prepare_runtime()

        if self.config.network_mode in {
            NetworkMode.EMULATED,
            NetworkMode.BROKERED_RECORD,
        }:
            self.generate_network_runner()
        else:
            print("[+] Network sandbox runner skipped")

    def reconstruct_env(self) -> None:
        print("[+] Reconstructing rootfs and network policy")

        self.run_command(
            [
                sys.executable,
                "scripts/reconstruct_env.py",
                "--taint",
                str(self.config.taint_path),
                "--out",
                str(self.config.out_dir),
                "--bind-ip",
                self.config.bind_ip,
                "--catch-all-port",
                str(self.config.catch_all_port),
            ]
        )

    def configure_record_network_policy(self) -> None:
        if self.record_policy is None:
            raise OrchestratorError("record policy was not loaded")

        raw = json.loads(
            self.network_policy_path.read_text(encoding="utf-8")
        )
        raw["mode"] = "brokered_record"
        raw["allow_internet"] = False
        raw["services"] = [
            {
                "service_type": "tcp",
                "role": "brokered_record",
                "remote_ip": self.record_policy.target.original_ip,
                "remote_port": self.record_policy.target.original_port,
                "domain": None,
                "bind_ip": self.config.bind_ip,
                "bind_port": self.record_policy.listen_port,
                "protocol_hint": "brokered_record",
            }
        ]
        self.network_policy_path.write_text(
            json.dumps(raw, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            "[+] Record target routed to bounded broker: "
            f"{self.record_policy.target.original_ip}:"
            f"{self.record_policy.target.original_port} -> "
            f"{self.config.bind_ip}:{self.record_policy.listen_port}"
        )

    def analyze_libraries(self) -> None:
        print("[+] Analyzing ELF libraries")

        self.run_command(
            [
                sys.executable,
                "scripts/analyze_libraries.py",
                "--taint",
                str(self.config.taint_path),
                "--binary",
                str(self.config.binary_path),
                "--out",
                str(self.library_plan_path),
            ]
        )

    def resolve_libraries(self) -> None:
        print("[+] Resolving libraries")

        self.run_command(
            [
                sys.executable,
                "scripts/resolve_libraries.py",
                "--plan",
                str(self.library_plan_path),
                "--rootfs",
                str(self.rootfs_dir),
                "--sysroot",
                str(self.config.sysroot_path),
                "--out",
                str(self.library_resolution_path),
            ]
        )

    def prepare_runtime(self) -> None:
        print("[+] Preparing runtime")

        cmd = [
            sys.executable,
            "scripts/prepare_runtime.py",
            "--taint",
            str(self.config.taint_path),
            "--binary",
            str(self.config.binary_path),
            "--out",
            str(self.config.out_dir),
            "--library-resolution",
            str(self.library_resolution_path),
        ]

        if self.config.allow_missing_libraries:
            cmd.append("--allow-missing-libraries")

        self.run_command(cmd)

    def generate_network_runner(self) -> None:
        print("[+] Generating network sandbox runner")

        self.run_command(
            [
                sys.executable,
                "scripts/generate_network_sandbox_runner.py",
                "--runtime",
                str(self.runtime_path),
                "--policy",
                str(self.network_policy_path),
                "--out",
                str(self.network_runner_path),
                "--namespace",
                self.config.namespace,
                "--timeout",
                str(self.config.timeout_seconds),
            ]
        )

    def ensure_sudo(self) -> None:
        print("[+] Checking sudo")
        self.run_command(["sudo", "-v"])

    def disable_host_ip_forwarding(self) -> None:
        print("[+] Disabling host IPv4 forwarding")

        current = Path(
            "/proc/sys/net/ipv4/ip_forward"
        ).read_text().strip()

        if current not in {"0", "1"}:
            raise OrchestratorError(
                f"Unexpected host ip_forward value: {current}"
            )

        self.original_ip_forward = current

        if current != "0":
            self.run_command(
                ["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"]
            )

        value = Path(
            "/proc/sys/net/ipv4/ip_forward"
        ).read_text().strip()

        if value != "0":
            raise OrchestratorError("Host ip_forward is not disabled")

    def restore_host_ip_forwarding(self) -> None:
        if self.original_ip_forward is None:
            return

        current = Path(
            "/proc/sys/net/ipv4/ip_forward"
        ).read_text().strip()

        if current != self.original_ip_forward:
            print(
                "[+] Restoring host IPv4 forwarding to "
                f"{self.original_ip_forward}"
            )
            self.run_command(
                [
                    "sudo",
                    "sysctl",
                    "-w",
                    (
                        "net.ipv4.ip_forward="
                        f"{self.original_ip_forward}"
                    ),
                ],
                check=False,
            )

        self.original_ip_forward = None

    def setup_network_namespace(self) -> None:
        print("[+] Setting up network namespace")

        self.run_command(
            ["bash", str(self.network_runner_path), "cleanup"],
            check=False,
        )

        self.run_command(
            ["bash", str(self.network_runner_path), "setup"],
        )

        self.validate_namespace_rules()

    def validate_namespace_rules(self) -> None:
        print("[+] Validating iptables rules")

        output = self.capture_command(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                self.config.namespace,
                "iptables",
                "-t",
                "nat",
                "-S",
                "OUTPUT",
            ]
        )

        if "TF_TCP_CATCHALL" not in output:
            raise OrchestratorError("Missing TF_TCP_CATCHALL in nat OUTPUT")

        if "TF_UDP_CATCHALL" not in output:
            raise OrchestratorError("Missing TF_UDP_CATCHALL in nat OUTPUT")

        tcp_chain = self.capture_command(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                self.config.namespace,
                "iptables",
                "-t",
                "nat",
                "-S",
                "TF_TCP_CATCHALL",
            ]
        )

        udp_chain = self.capture_command(
            [
                "sudo",
                "ip",
                "netns",
                "exec",
                self.config.namespace,
                "iptables",
                "-t",
                "nat",
                "-S",
                "TF_UDP_CATCHALL",
            ]
        )

        if f"REDIRECT --to-ports {self.config.catch_all_port}" not in tcp_chain:
            raise OrchestratorError("Missing TCP catch-all REDIRECT rule")

        if f"REDIRECT --to-ports {self.config.udp_catch_all_port}" not in udp_chain:
            raise OrchestratorError("Missing UDP catch-all REDIRECT rule")

    def start_transparent_logger(self) -> None:
        print("[+] Starting transparent TCP/UDP logger")

        stdout_path = self.logs_dir / "transparent_logger_stdout.log"
        stderr_path = self.logs_dir / "transparent_logger_stderr.log"

        cmd = [
            "sudo",
            "ip",
            "netns",
            "exec",
            self.config.namespace,
            "env",
            f"PYTHONPATH={self.project_root}",
            sys.executable,
            "scripts/start_transparent_logger.py",
            "--log-dir",
            str(self.logs_dir.resolve()),
            "--tcp-bind-ip",
            "127.0.0.1",
            "--tcp-port",
            str(self.config.catch_all_port),
            "--udp-bind-ip",
            "127.0.0.1",
            "--udp-port",
            str(self.config.udp_catch_all_port),
        ]

        self.start_process(cmd, stdout_path, stderr_path)

    def start_c2_record_broker(self) -> None:
        if self.record_policy is None:
            raise OrchestratorError("record policy was not loaded")

        print("[+] Starting bounded C2 recording broker")
        stdout_path = self.logs_dir / "c2_record_broker_stdout.log"
        stderr_path = self.logs_dir / "c2_record_broker_stderr.log"

        cmd = [
            sys.executable,
            "scripts/start_c2_record_broker.py",
            "--policy",
            str(self.copied_record_policy_path),
            "--bind-ip",
            self.config.bind_ip,
            "--capture-dir",
            str(self.c2_capture_dir),
            "--run-id",
            self.run_id,
            "--event-log",
            str(self.c2_broker_events_path),
        ]
        self.start_process(cmd, stdout_path, stderr_path)

    def wait_for_c2_record_broker(self) -> None:
        if self.record_policy is None:
            raise OrchestratorError("record policy was not loaded")
        print("[+] Waiting for C2 recording broker")
        self.wait_for_host_port(
            self.config.bind_ip,
            self.record_policy.listen_port,
            timeout=5,
        )

    def start_known_network_emulator(self) -> None:
        if not self.network_policy_has_known_tcp_services():
            print("[!] No known TCP services; skipping mini-FakeNet")
            return

        print("[+] Starting known TCP mini-FakeNet")

        stdout_path = self.logs_dir / "network_emulator_stdout.log"
        stderr_path = self.logs_dir / "network_emulator_stderr.log"

        cmd = [
            sys.executable,
            "scripts/start_network_emulator.py",
            "--policy",
            str(self.network_policy_path),
            "--log-dir",
            str(self.logs_dir),
        ]

        self.start_process(cmd, stdout_path, stderr_path)

    def network_policy_has_known_tcp_services(self) -> bool:
        raw = json.loads(self.network_policy_path.read_text(encoding="utf-8"))

        for service in raw.get("services", []):
            if service.get("service_type") == "tcp":
                return True

        return False

    def wait_for_transparent_logger(self) -> None:
        print("[+] Waiting for transparent logger")

        self.wait_for_netns_port(self.config.catch_all_port, timeout=5)
        self.wait_for_netns_port(self.config.udp_catch_all_port, timeout=5)

    def wait_for_known_emulator_if_needed(self) -> None:
        if not self.network_policy_has_known_tcp_services():
            return

        print("[+] Waiting for known TCP mini-FakeNet")

        raw = json.loads(self.network_policy_path.read_text(encoding="utf-8"))

        for service in raw.get("services", []):
            if service.get("service_type") != "tcp":
                continue

            bind_ip = service.get("bind_ip")
            bind_port = int(service.get("bind_port"))

            self.wait_for_host_port(bind_ip, bind_port, timeout=5)

    def wait_for_netns_port(self, port: int, timeout: int) -> None:
        deadline = time.time() + timeout

        while time.time() < deadline:
            self.check_processes_alive()

            output = self.capture_command(
                [
                    "sudo",
                    "ip",
                    "netns",
                    "exec",
                    self.config.namespace,
                    "ss",
                    "-lntup",
                ],
                check=False,
            )

            if f":{port}" in output:
                return

            time.sleep(0.2)

        raise OrchestratorError(f"Timed out waiting for netns listener: {port}")

    def wait_for_host_port(self, bind_ip: str, port: int, timeout: int) -> None:
        deadline = time.time() + timeout

        while time.time() < deadline:
            self.check_processes_alive()

            output = self.capture_command(["ss", "-lntup"], check=False)

            if bind_ip in output and f":{port}" in output:
                return

            time.sleep(0.2)

        raise OrchestratorError(f"Timed out waiting for host listener: {bind_ip}:{port}")

    def run_network_self_test(self) -> None:
        print("[+] Running controlled network self-test")

        raw_policy = json.loads(
            self.network_policy_path.read_text(encoding="utf-8")
        )

        known_tcp_targets = [
            service
            for service in raw_policy.get("services", [])
            if service.get("service_type") == "tcp"
            and service.get("remote_ip")
            and service.get("remote_port")
        ]

        known_target = None
        if known_tcp_targets:
            first = known_tcp_targets[0]
            known_target = {
                "ip": first["remote_ip"],
                "port": int(first["remote_port"]),
            }

        test_config = {
            "known_target": known_target,
            "unknown_tcp_target": {
                "ip": "91.200.10.5",
                "port": 5555,
            },
            "udp_target": {
                "ip": "1.2.3.4",
                "port": 9999,
            },
            "dns_target": {
                "ip": "8.8.8.8",
                "port": 53,
            },
        }

        code = self.build_network_self_test_code(test_config)

        stdout_path = self.logs_dir / "network_self_test_stdout.log"
        stderr_path = self.logs_dir / "network_self_test_stderr.log"

        cmd = [
            "sudo",
            "ip",
            "netns",
            "exec",
            self.config.namespace,
            sys.executable,
            "-c",
            code,
        ]

        print("[cmd]", " ".join(cmd[:6]) + " <self-test-code>")

        result = subprocess.run(
            cmd,
            cwd=self.project_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")

        if result.stdout:
            print(result.stdout, end="")

        if result.stderr:
            print(result.stderr, end="")

        if result.returncode != 0:
            raise OrchestratorError(
                "Network self-test command failed. "
                f"See {stdout_path} and {stderr_path}"
            )

        time.sleep(0.5)

        self.validate_network_self_test_events(test_config)


    @staticmethod
    def build_network_self_test_code(test_config: dict) -> str:
        config_json = json.dumps(test_config)

        return textwrap.dedent(
            f"""
            import json
            import socket
            import time

            config = json.loads({config_json!r})


            def tcp_test(name, host, port, payload):
                print(f"[self-test] TCP {{name}} -> {{host}}:{{port}}")
                sock = socket.create_connection((host, port), timeout=3)

                try:
                    sock.sendall(payload)
                    sock.settimeout(3)
                    response = sock.recv(1024)
                    print(f"[self-test] TCP {{name}} response={{response.hex()}}")
                finally:
                    sock.close()


            def udp_test(name, host, port, payload):
                print(f"[self-test] UDP {{name}} -> {{host}}:{{port}}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

                try:
                    sock.sendto(payload, (host, port))
                finally:
                    sock.close()


            known = config.get("known_target")
            if known is not None:
                tcp_test(
                    "known",
                    known["ip"],
                    int(known["port"]),
                    b"known-self-test",
                )
            else:
                print("[self-test] No known TCP target in policy; skipping known TCP test")

            unknown = config["unknown_tcp_target"]
            tcp_test(
                "unknown",
                unknown["ip"],
                int(unknown["port"]),
                b"unknown-self-test",
            )

            udp = config["udp_target"]
            udp_test(
                "generic",
                udp["ip"],
                int(udp["port"]),
                b"udp-self-test",
            )

            dns = config["dns_target"]
            udp_test(
                "dns-like",
                dns["ip"],
                int(dns["port"]),
                b"\\x12\\x34fake-dns-query",
            )

            time.sleep(0.2)
            """
        ).strip()


    def validate_network_self_test_events(self, test_config: dict) -> None:
        print("[+] Validating network self-test events")

        events_path = self.logs_dir / "network_events.jsonl"

        if not events_path.exists():
            raise OrchestratorError(
                "network_events.jsonl was not created during self-test"
            )

        events: list[dict] = []

        for line in events_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        known_target = test_config.get("known_target")
        if known_target is not None:
            if not self.has_event(
                events,
                listener_type="known",
                original_ip=known_target["ip"],
                original_port=int(known_target["port"]),
            ):
                raise OrchestratorError(
                    "Self-test failed: known TCP event was not logged"
                )

        unknown = test_config["unknown_tcp_target"]
        if not self.has_event(
            events,
            listener_type="catch_all_transparent",
            original_ip=unknown["ip"],
            original_port=int(unknown["port"]),
        ):
            raise OrchestratorError(
                "Self-test failed: unknown TCP catch-all event was not logged"
            )

        udp = test_config["udp_target"]
        if not self.has_event(
            events,
            listener_type="udp_transparent",
            original_ip=udp["ip"],
            original_port=int(udp["port"]),
        ):
            raise OrchestratorError(
                "Self-test failed: generic UDP event was not logged"
            )

        dns = test_config["dns_target"]
        if not self.has_event(
            events,
            listener_type="udp_transparent",
            original_ip=dns["ip"],
            original_port=int(dns["port"]),
            udp_role="dns",
        ):
            raise OrchestratorError(
                "Self-test failed: DNS-like UDP event was not logged"
            )

        print("[+] Network self-test passed")

    @staticmethod
    def has_event(
        events: list[dict],
        listener_type: str,
        original_ip: str,
        original_port: int,
        udp_role: str | None = None,
    ) -> bool:
        for event in events:
            if event.get("listener_type") != listener_type:
                continue

            if event.get("original_remote_ip") != original_ip:
                continue

            if int(event.get("original_remote_port") or 0) != original_port:
                continue

            if udp_role is not None and event.get("udp_role") != udp_role:
                continue

            return True

        return False
    
    def run_sample_direct(self) -> None:
        print("[+] Running sample directly without network sandbox")

        runtime = json.loads(self.runtime_path.read_text(encoding="utf-8"))

        rootfs = Path(runtime["rootfs"])
        if not rootfs.is_absolute():
            rootfs = self.project_root / rootfs

        guest_binary = runtime.get("guest_binary", "/bin/unpacked.elf")
        qemu_required = bool(runtime.get("qemu_required", False))

        if qemu_required:
            raise OrchestratorError(
                "Direct run for qemu_required=True is not implemented yet. "
                "Use controlled network mode or add direct QEMU launcher."
            )

        proc_dir = rootfs / "proc"
        proc_dir.mkdir(parents=True, exist_ok=True)

        stdout_path = self.logs_dir / "runtime_stdout.log"
        stderr_path = self.logs_dir / "runtime_stderr.log"
        strace_base = self.logs_dir / "strace"

        mounted_proc = False

        try:
            if not proc_dir.is_mount():
                self.run_command([
                    "sudo",
                    "mount",
                    "-t",
                    "proc",
                    "proc",
                    str(proc_dir),
                ])
                mounted_proc = True

            cmd = [
                "sudo",
                "timeout",
                str(self.config.timeout_seconds),
                "strace",
                "-ff",
                "-o",
                str(strace_base),
                "chroot",
                str(rootfs),
                guest_binary,
            ]

            print("[cmd]", " ".join(cmd))

            with stdout_path.open("w", encoding="utf-8") as stdout_file, \
                stderr_path.open("w", encoding="utf-8") as stderr_file:
                result = subprocess.run(
                    cmd,
                    cwd=self.project_root,
                    text=True,
                    stdout=stdout_file,
                    stderr=stderr_file,
                )

            if result.returncode != 0:
                print(
                    f"[!] Direct sample runner exited with code {result.returncode}. "
                    "For malware this can be normal: crash/timeout/non-zero exit."
                )

        finally:
            if mounted_proc:
                self.run_command(
                    ["sudo", "umount", str(proc_dir)],
                    check=False,
                )

    def run_sample(self) -> None:
        print("[+] Running sample")

        result = subprocess.run(
            ["bash", str(self.network_runner_path), "run"],
            cwd=self.project_root,
            text=True,
        )

        if result.returncode != 0:
            print(
                f"[!] Sample runner exited with code {result.returncode}. "
                "For malware this can be normal: crash/timeout/non-zero exit."
            )

    def check_processes_alive(self) -> None:
        for proc in self.processes:
            if proc.poll() is not None:
                raise OrchestratorError(
                    f"Background process exited early with code {proc.returncode}"
                )

    def stop_processes(self) -> None:
        if not self.processes:
            return

        print("[+] Stopping background services")

        for proc in self.processes:
            if proc.poll() is None:
                proc.terminate()

        deadline = time.time() + 3

        for proc in self.processes:
            while proc.poll() is None and time.time() < deadline:
                time.sleep(0.1)

            if proc.poll() is None:
                proc.kill()

        self.processes.clear()

    def cleanup_network_namespace(self) -> None:
        if not self.network_runner_path.exists():
            return

        print("[+] Cleaning network namespace")

        self.run_command(
            ["bash", str(self.network_runner_path), "cleanup"],
            check=False,
        )

    def fix_output_ownership(self) -> None:
        if not self.config.out_dir.exists():
            return

        user = os.environ.get("SUDO_USER") or os.environ.get("USER")

        if not user:
            return

        print("[+] Fixing output ownership")

        self.run_command(
            ["sudo", "chown", "-R", f"{user}:{user}", str(self.config.out_dir)],
            check=False,
        )


    def make_runtime_artifacts_readable(self) -> None:
        """
        Runtime artifacts are created by root inside the isolated sandbox.

        Give the invoking user ownership before syscall parsing and report
        generation. Keep this separate from final cleanup so post-processing
        can access strace and security files immediately after execution.
        """
        if not self.logs_dir.exists():
            return

        user = os.environ.get("SUDO_USER") or os.environ.get("USER")

        if not user:
            raise OrchestratorError(
                "Cannot determine invoking user for runtime artifact ownership"
            )

        print("[+] Normalizing runtime artifact ownership")

        self.run_command(
            [
                "sudo",
                "chown",
                "-R",
                f"{user}:{user}",
                str(self.logs_dir),
            ],
            check=True,
        )

    def print_build_summary(self) -> None:
        print()
        print("[+] Build-only pipeline finished")
        print(f"[+] rootfs:              {self.rootfs_dir}")
        print(f"[+] network policy:     {self.network_policy_path}")
        print(f"[+] library plan:       {self.library_plan_path}")
        print(f"[+] library resolution: {self.library_resolution_path}")
        print(f"[+] runtime:            {self.runtime_path}")
        print(f"[+] run manifest:       {self.run_manifest_path}")
        if self.network_runner_path.exists():
            print(f"[+] network runner:     {self.network_runner_path}")


    def generate_report(self) -> None:
        print("[+] Generating run report")

        self.run_command(
            [
                sys.executable,
                "scripts/generate_report.py",
                "--out",
                str(self.config.out_dir),
            ]
        )

    def print_run_summary(self) -> None:
        print()
        print("[+] Run finished")
        print(f"[+] logs: {self.logs_dir}")

        events_path = self.logs_dir / "network_events.jsonl"

        if events_path.exists():
            summary = self.summarize_network_events(events_path)
            print("[+] Network summary:")
            for key, value in summary.items():
                print(f"    {key}: {value}")
        else:
            print("[!] No network_events.jsonl produced")

        print("[+] Useful files:")
        print(f"    run manifest: {self.run_manifest_path}")
        print(f"    report json: {self.config.out_dir / 'report.json'}")
        print(f"    report md: {self.config.out_dir / 'report.md'}")
        print(f"    runtime stdout: {self.logs_dir / 'runtime_stdout.log'}")
        print(f"    runtime stderr: {self.logs_dir / 'runtime_stderr.log'}")
        print(f"    observation lifecycle: {self.config_dir / 'observation_lifecycle.json'}")
        print(f"    rootfs diff: {self.config_dir / 'rootfs_diff.json'}")
        print(f"    runtime requirements: {self.runtime_requirements_path}")
        print(f"    repair plan: {self.repair_plan_path}")
        print(f"    transparent logger stdout: {self.logs_dir / 'transparent_logger_stdout.log'}")
        print(f"    transparent logger stderr: {self.logs_dir / 'transparent_logger_stderr.log'}")
        print(f"    network emulator stdout: {self.logs_dir / 'network_emulator_stdout.log'}")
        print(f"    network emulator stderr: {self.logs_dir / 'network_emulator_stderr.log'}")
        if self.config.network_mode == NetworkMode.BROKERED_RECORD:
            print(f"    C2 captures: {self.c2_capture_dir}")
            print(f"    C2 broker events: {self.c2_broker_events_path}")
            print(f"    C2 broker stdout: {self.logs_dir / 'c2_record_broker_stdout.log'}")
            print(f"    C2 broker stderr: {self.logs_dir / 'c2_record_broker_stderr.log'}")

    @staticmethod
    def summarize_network_events(path: Path) -> dict[str, int]:
        summary = {
            "known_tcp_events": 0,
            "unknown_tcp_events": 0,
            "udp_datagrams": 0,
            "payload_files": 0,
        }

        payload_files: set[str] = set()

        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            listener_type = event.get("listener_type")

            if listener_type == "known":
                summary["known_tcp_events"] += 1
            elif listener_type == "catch_all_transparent":
                summary["unknown_tcp_events"] += 1
            elif listener_type == "udp_transparent":
                summary["udp_datagrams"] += 1

            payload_file = event.get("payload_file")
            if payload_file:
                payload_files.add(payload_file)

        summary["payload_files"] = len(payload_files)
        return summary

    def start_process(
        self,
        cmd: list[str],
        stdout_path: Path,
        stderr_path: Path,
    ) -> None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)

        stdout_file = stdout_path.open("w", encoding="utf-8")
        stderr_file = stderr_path.open("w", encoding="utf-8")

        print("[cmd]", " ".join(cmd))

        proc = subprocess.Popen(
            cmd,
            cwd=self.project_root,
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
        )

        self.processes.append(proc)

    def run_command(
        self,
        cmd: list[str],
        check: bool = True,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.project_root)

        print("[cmd]", " ".join(cmd))

        result = subprocess.run(
            cmd,
            cwd=self.project_root,
            env=env,
            text=True,
        )

        if check and result.returncode != 0:
            raise OrchestratorError(f"Command failed with exit code {result.returncode}: {' '.join(cmd)}")

        return result

    def capture_command(
        self,
        cmd: list[str],
        check: bool = True,
    ) -> str:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.project_root)

        result = subprocess.run(
            cmd,
            cwd=self.project_root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if check and result.returncode != 0:
            raise OrchestratorError(
                f"Command failed with exit code {result.returncode}: "
                f"{' '.join(cmd)}\n{result.stderr}"
            )

        return result.stdout
