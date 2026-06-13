from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


class OrchestratorError(RuntimeError):
    pass


@dataclass(slots=True)
class OrchestratorConfig:
    taint_path: Path
    binary_path: Path
    sysroot_path: Path
    out_dir: Path

    timeout_seconds: int = 60
    network_mode: str = "controlled"

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

        self.network_policy_path = self.config_dir / "network_policy.json"
        self.library_plan_path = self.config_dir / "library_plan.json"
        self.library_resolution_path = self.config_dir / "library_resolution.json"
        self.runtime_path = self.config_dir / "runtime.json"
        self.network_runner_path = self.config.out_dir / "run_network_sandbox.sh"

        self.processes: list[subprocess.Popen] = []

    def run(self) -> None:
        self.print_header()

        try:
            self.check_dependencies()
            self.prepare_workdir()
            self.build_environment()

            if self.config.build_only:
                self.print_build_summary()
                return

            if self.config.network_mode != "controlled":
                raise OrchestratorError(
                    f"Only controlled network mode is supported now, got: {self.config.network_mode}"
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

            self.run_sample()

            self.print_run_summary()

        finally:
            self.stop_processes()

            if not self.config.keep_namespace:
                self.cleanup_network_namespace()

            self.fix_output_ownership()

    def print_header(self) -> None:
        print("[+] TaintForge-IoT Phase 2 orchestrator")
        print(f"[+] taint:   {self.config.taint_path}")
        print(f"[+] binary:  {self.config.binary_path}")
        print(f"[+] sysroot: {self.config.sysroot_path}")
        print(f"[+] out:     {self.config.out_dir}")
        print(f"[+] network: {self.config.network_mode}")
        print()

    def check_dependencies(self) -> None:
        print("[+] Checking dependencies")

        required = [
            "readelf",
            "ip",
            "iptables",
            "ss",
            "sudo",
            "conntrack",
        ]

        missing = [tool for tool in required if shutil.which(tool) is None]

        if missing:
            raise OrchestratorError(
                "Missing required tools: " + ", ".join(missing)
            )

        self.require_file(self.config.taint_path, "taint file")
        self.require_file(self.config.binary_path, "binary file")

        if not self.config.sysroot_path.exists():
            raise OrchestratorError(f"sysroot not found: {self.config.sysroot_path}")

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
        self.analyze_libraries()
        self.resolve_libraries()
        self.prepare_runtime()
        self.generate_network_runner()

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
        self.run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])

        value = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        if value != "0":
            raise OrchestratorError("Host ip_forward is not disabled")

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

        return f"""
import json
import socket
import sys
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

    def print_build_summary(self) -> None:
        print()
        print("[+] Build-only pipeline finished")
        print(f"[+] rootfs:              {self.rootfs_dir}")
        print(f"[+] network policy:     {self.network_policy_path}")
        print(f"[+] library plan:       {self.library_plan_path}")
        print(f"[+] library resolution: {self.library_resolution_path}")
        print(f"[+] runtime:            {self.runtime_path}")
        print(f"[+] network runner:     {self.network_runner_path}")

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
        print(f"    runtime stdout: {self.logs_dir / 'runtime_stdout.log'}")
        print(f"    runtime stderr: {self.logs_dir / 'runtime_stderr.log'}")
        print(f"    transparent logger stdout: {self.logs_dir / 'transparent_logger_stdout.log'}")
        print(f"    transparent logger stderr: {self.logs_dir / 'transparent_logger_stderr.log'}")
        print(f"    network emulator stdout: {self.logs_dir / 'network_emulator_stdout.log'}")
        print(f"    network emulator stderr: {self.logs_dir / 'network_emulator_stderr.log'}")

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
            raise OrchestratorError(
                "Command failed with exit code {result.returncode}: {' '.join(cmd)}"
            )

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
                "Command failed with exit code {result.returncode}: {' '.join(cmd)}\n{result.stderr}"
            )

        return result.stdout
