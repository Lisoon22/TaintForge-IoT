from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PREVIEW_CHARS = 4000


class ReportGenerationError(RuntimeError):
    pass


class RunReportGenerator:
    def __init__(self, out_dir: str | Path):
        self.out_dir = Path(out_dir)
        self.config_dir = self.out_dir / "config"
        self.logs_dir = self.out_dir / "logs"

        self.runtime_path = self.config_dir / "runtime.json"
        self.network_policy_path = self.config_dir / "network_policy.json"
        self.library_plan_path = self.config_dir / "library_plan.json"
        self.library_resolution_path = self.config_dir / "library_resolution.json"
        self.network_events_path = self.logs_dir / "network_events.jsonl"
        self.runtime_status_path = self.logs_dir / "runtime_status.json"

        self.report_json_path = self.out_dir / "report.json"
        self.report_md_path = self.out_dir / "report.md"

    def generate(self) -> dict[str, Any]:
        if not self.out_dir.exists():
            raise ReportGenerationError(f"out_dir does not exist: {self.out_dir}")

        runtime = self.load_json_optional(self.runtime_path)
        network_policy = self.load_json_optional(self.network_policy_path)
        library_plan = self.load_json_optional(self.library_plan_path)
        library_resolution = self.load_json_optional(self.library_resolution_path)
        network_events = self.load_jsonl_optional(self.network_events_path)
        runtime_status = self.load_json_optional(self.runtime_status_path)

        report = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "out_dir": str(self.out_dir),
            "paths": self.build_paths_section(),
            "runtime": self.build_runtime_section(runtime=runtime, runtime_status=runtime_status),
            "libraries": self.build_libraries_section(
                library_plan=library_plan,
                library_resolution=library_resolution,
            ),
            "network": self.build_network_section(
                network_policy=network_policy,
                network_events=network_events,
            ),
            "artifacts": self.build_artifacts_section(network_events),
            "logs": self.build_logs_section(),
            "security": self.build_security_section(network_policy),
        }

        self.save_json_report(report)
        self.save_markdown_report(report)

        return report

    def build_paths_section(self) -> dict[str, str]:
        return {
            "runtime": self.rel(self.runtime_path),
            "network_policy": self.rel(self.network_policy_path),
            "library_plan": self.rel(self.library_plan_path),
            "library_resolution": self.rel(self.library_resolution_path),
            "network_events": self.rel(self.network_events_path),
            "runtime_status": self.rel(self.runtime_status_path),
            "runtime_stdout": self.rel(self.logs_dir / "runtime_stdout.log"),
            "runtime_stderr": self.rel(self.logs_dir / "runtime_stderr.log"),
            "report_json": self.rel(self.report_json_path),
            "report_md": self.rel(self.report_md_path),
        }

    def build_runtime_section(self, runtime: dict[str, Any], runtime_status: dict[str, Any]) -> dict[str, Any]:
        host_binary_path = runtime.get("host_binary_path")
        host_binary_info = None

        if host_binary_path:
            host_binary_info = self.file_info(Path(host_binary_path))

        return {
            "arch": runtime.get("arch"),
            "rootfs": runtime.get("rootfs"),
            "host_binary_path": host_binary_path,
            "host_binary": host_binary_info,
            "guest_binary_path": runtime.get("guest_binary_path"),
            "qemu_required": runtime.get("qemu_required"),
            "qemu_binary_name": runtime.get("qemu_binary_name"),
            "qemu_host_path": runtime.get("qemu_host_path"),
            "qemu_guest_path": runtime.get("qemu_guest_path"),
            "libraries_ok": runtime.get("libraries_ok"),
            "library_resolution_path": runtime.get("library_resolution_path"),
            "status": runtime_status,
            "stdout_preview": self.read_text_optional(self.logs_dir / "runtime_stdout.log"),
            "stderr_preview": self.read_text_optional(self.logs_dir / "runtime_stderr.log"),
        }

    def build_libraries_section(
        self,
        library_plan: dict[str, Any],
        library_resolution: dict[str, Any],
    ) -> dict[str, Any]:
        requirements = library_plan.get("requirements", [])
        resolved = library_resolution.get("resolved", [])
        missing = library_resolution.get("missing", [])

        return {
            "requirements_count": len(requirements),
            "resolved_count": len(resolved),
            "missing_count": len(missing),
            "requirements": requirements,
            "resolved": resolved,
            "missing": missing,
        }

    def build_network_section(
        self,
        network_policy: dict[str, Any],
        network_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        services = network_policy.get("services", [])
        catch_all = network_policy.get("catch_all", {})

        events_by_type = Counter(
            str(event.get("event", "unknown"))
            for event in network_events
        )

        listener_types = Counter(
            str(event.get("listener_type", "unknown"))
            for event in network_events
        )

        known_tcp_events = [
            event for event in network_events
            if event.get("listener_type") == "known"
        ]

        unknown_tcp_events = [
            event for event in network_events
            if event.get("listener_type") == "catch_all_transparent"
        ]

        udp_events = [
            event for event in network_events
            if event.get("listener_type") == "udp_transparent"
        ]

        dns_events = [
            event for event in udp_events
            if event.get("udp_role") == "dns"
        ]

        return {
            "mode": network_policy.get("mode"),
            "allow_internet": network_policy.get("allow_internet"),
            "services_count": len(services),
            "services": services,
            "catch_all": catch_all,
            "events_total": len(network_events),
            "events_by_type": dict(events_by_type),
            "listener_types": dict(listener_types),
            "known_tcp_events": len(known_tcp_events),
            "unknown_tcp_events": len(unknown_tcp_events),
            "udp_datagrams": len(udp_events),
            "dns_datagrams": len(dns_events),
            "known_tcp_targets": self.unique_targets(known_tcp_events),
            "unknown_tcp_targets": self.unique_targets(unknown_tcp_events),
            "udp_targets": self.unique_targets(udp_events),
        }

    def build_artifacts_section(
        self,
        network_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        payload_names = sorted(
            {
                event.get("payload_file")
                for event in network_events
                if event.get("payload_file")
            }
        )

        payload_files = []

        for name in payload_names:
            path = self.logs_dir / str(name)
            payload_files.append(self.file_info(path))

        log_files = []

        if self.logs_dir.exists():
            for path in sorted(self.logs_dir.iterdir()):
                if path.is_file() and path.suffix != ".bin":
                    log_files.append(self.file_info(path))

        return {
            "payload_count": len(payload_files),
            "payload_files": payload_files,
            "log_files": log_files,
        }

    def build_logs_section(self) -> dict[str, Any]:
        return {
            "runtime_stdout": self.read_text_optional(
                self.logs_dir / "runtime_stdout.log"
            ),
            "runtime_stderr": self.read_text_optional(
                self.logs_dir / "runtime_stderr.log"
            ),
            "network_self_test_stdout": self.read_text_optional(
                self.logs_dir / "network_self_test_stdout.log"
            ),
            "network_self_test_stderr": self.read_text_optional(
                self.logs_dir / "network_self_test_stderr.log"
            ),
            "transparent_logger_stdout": self.read_text_optional(
                self.logs_dir / "transparent_logger_stdout.log"
            ),
            "transparent_logger_stderr": self.read_text_optional(
                self.logs_dir / "transparent_logger_stderr.log"
            ),
            "network_emulator_stdout": self.read_text_optional(
                self.logs_dir / "network_emulator_stdout.log"
            ),
            "network_emulator_stderr": self.read_text_optional(
                self.logs_dir / "network_emulator_stderr.log"
            ),
        }

    def build_security_section(self, network_policy: dict[str, Any]) -> dict[str, Any]:
        return {
            "chroot_enabled": True,
            "network_namespace_enabled": True,
            "iptables_default_deny_expected": True,
            "host_ip_forwarding_expected": False,
            "allow_internet": bool(network_policy.get("allow_internet", False)),
            "known_endpoint_dnat": True,
            "tcp_catch_all_redirect": bool(
                network_policy.get("catch_all", {}).get("enabled", False)
            ),
            "udp_catch_all_redirect": bool(
                network_policy.get("catch_all", {}).get("udp_enabled", False)
            ),
            "resource_limits": "disabled_in_v1_timeout_only",
        }

    def save_json_report(self, report: dict[str, Any]) -> None:
        self.report_json_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def save_markdown_report(self, report: dict[str, Any]) -> None:
        content = self.render_markdown(report)
        self.report_md_path.write_text(content, encoding="utf-8")

    def render_markdown(self, report: dict[str, Any]) -> str:
        runtime = report["runtime"]
        libraries = report["libraries"]
        network = report["network"]
        artifacts = report["artifacts"]
        security = report["security"]
        logs = report["logs"]

        lines: list[str] = []

        lines.append("# TaintForge-IoT Phase 2 Run Report")
        lines.append("")
        lines.append(f"Generated at UTC: `{report['generated_at_utc']}`")
        lines.append(f"Output directory: `{report['out_dir']}`")
        lines.append("")

        lines.append("## Runtime")
        lines.append("")
        lines.append(f"- Architecture: `{runtime.get('arch')}`")
        lines.append(f"- RootFS: `{runtime.get('rootfs')}`")
        lines.append(f"- Host binary: `{runtime.get('host_binary_path')}`")
        lines.append(f"- Guest binary: `{runtime.get('guest_binary_path')}`")
        lines.append(f"- QEMU required: `{runtime.get('qemu_required')}`")
        lines.append(f"- QEMU guest path: `{runtime.get('qemu_guest_path')}`")
        lines.append(f"- Libraries OK: `{runtime.get('libraries_ok')}`")
        lines.append("")

        status = runtime.get("status") or {}

        if status:
            lines.append("### Runtime status")
            lines.append("")
            lines.append(f"- Exit code: `{status.get('exit_code')}`")
            lines.append(f"- Timed out: `{status.get('timed_out')}`")
            lines.append(f"- Timeout seconds: `{status.get('timeout_seconds')}`")
            lines.append(f"- Duration seconds: `{status.get('duration_seconds')}`")
            lines.append(f"- Started at UTC: `{status.get('started_at_utc')}`")
            lines.append(f"- Finished at UTC: `{status.get('finished_at_utc')}`")
            lines.append(f"- Command: `{status.get('command')}`")
            lines.append("")

        host_binary = runtime.get("host_binary")
        if host_binary:
            lines.append("### Host binary metadata")
            lines.append("")
            lines.append(f"- Exists: `{host_binary.get('exists')}`")
            lines.append(f"- Size: `{host_binary.get('size_bytes')}` bytes")
            lines.append(f"- SHA256: `{host_binary.get('sha256')}`")
            lines.append("")

        lines.append("## Libraries")
        lines.append("")
        lines.append(f"- Requirements: `{libraries['requirements_count']}`")
        lines.append(f"- Resolved: `{libraries['resolved_count']}`")
        lines.append(f"- Missing: `{libraries['missing_count']}`")
        lines.append("")

        if libraries["resolved"]:
            lines.append("### Resolved libraries")
            lines.append("")
            lines.append("| Name | Kind | Guest path | Source path |")
            lines.append("|---|---|---|---|")

            for item in libraries["resolved"]:
                lines.append(
                    "| "
                    f"{self.md(item.get('name'))} | "
                    f"{self.md(item.get('kind'))} | "
                    f"`{item.get('guest_path')}` | "
                    f"`{item.get('source_path')}` |"
                )

            lines.append("")

        if libraries["missing"]:
            lines.append("### Missing libraries")
            lines.append("")
            lines.append("| Name | Kind | Guest path |")
            lines.append("|---|---|---|")

            for item in libraries["missing"]:
                lines.append(
                    "| "
                    f"{self.md(item.get('name'))} | "
                    f"{self.md(item.get('kind'))} | "
                    f"`{item.get('guest_path')}` |"
                )

            lines.append("")

        lines.append("## Network")
        lines.append("")
        lines.append(f"- Mode: `{network.get('mode')}`")
        lines.append(f"- Allow internet: `{network.get('allow_internet')}`")
        lines.append(f"- Known services: `{network.get('services_count')}`")
        lines.append(f"- Total events: `{network.get('events_total')}`")
        lines.append(f"- Known TCP events: `{network.get('known_tcp_events')}`")
        lines.append(f"- Unknown TCP events: `{network.get('unknown_tcp_events')}`")
        lines.append(f"- UDP datagrams: `{network.get('udp_datagrams')}`")
        lines.append(f"- DNS datagrams: `{network.get('dns_datagrams')}`")
        lines.append("")

        if network["services"]:
            lines.append("### Known services")
            lines.append("")
            lines.append("| Role | Remote | Local bind | Protocol hint |")
            lines.append("|---|---|---|---|")

            for service in network["services"]:
                remote = f"{service.get('remote_ip')}:{service.get('remote_port')}"
                local = f"{service.get('bind_ip')}:{service.get('bind_port')}"
                lines.append(
                    "| "
                    f"{self.md(service.get('role'))} | "
                    f"`{remote}` | "
                    f"`{local}` | "
                    f"{self.md(service.get('protocol_hint'))} |"
                )

            lines.append("")

        lines.append("### Observed targets")
        lines.append("")
        lines.append(f"- Known TCP targets: `{network.get('known_tcp_targets')}`")
        lines.append(f"- Unknown TCP targets: `{network.get('unknown_tcp_targets')}`")
        lines.append(f"- UDP targets: `{network.get('udp_targets')}`")
        lines.append("")

        lines.append("### Event types")
        lines.append("")
        if network["events_by_type"]:
            for name, count in sorted(network["events_by_type"].items()):
                lines.append(f"- `{name}`: `{count}`")
        else:
            lines.append("- No network events recorded.")
        lines.append("")

        lines.append("## Artifacts")
        lines.append("")
        lines.append(f"- Payload files: `{artifacts['payload_count']}`")
        lines.append("")

        if artifacts["payload_files"]:
            lines.append("| File | Size | SHA256 |")
            lines.append("|---|---:|---|")

            for item in artifacts["payload_files"]:
                lines.append(
                    "| "
                    f"`{item.get('path')}` | "
                    f"{item.get('size_bytes')} | "
                    f"`{item.get('sha256')}` |"
                )

            lines.append("")

        lines.append("## Security model")
        lines.append("")
        for key, value in security.items():
            lines.append(f"- `{key}`: `{value}`")
        lines.append("")

        lines.append("## Runtime stdout preview")
        lines.append("")
        lines.append("```text")
        lines.append(logs.get("runtime_stdout") or "")
        lines.append("```")
        lines.append("")

        lines.append("## Runtime stderr preview")
        lines.append("")
        lines.append("```text")
        lines.append(logs.get("runtime_stderr") or "")
        lines.append("```")
        lines.append("")

        lines.append("## Network self-test stdout preview")
        lines.append("")
        lines.append("```text")
        lines.append(logs.get("network_self_test_stdout") or "")
        lines.append("```")
        lines.append("")

        return "\n".join(lines)

    def load_json_optional(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {
                "_error": f"Invalid JSON: {path}",
            }

    def load_jsonl_optional(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []

        events = []

        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return events

    def read_text_optional(self, path: Path, limit: int = PREVIEW_CHARS) -> str:
        if not path.exists():
            return ""

        data = path.read_text(encoding="utf-8", errors="replace")

        if len(data) <= limit:
            return data

        return data[:limit] + "\n...[truncated]..."

    def file_info(self, path: Path) -> dict[str, Any]:
        return {
            "path": self.rel(path),
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() and path.is_file() else None,
            "sha256": self.sha256(path) if path.exists() and path.is_file() else None,
        }

    @staticmethod
    def sha256(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    @staticmethod
    def unique_targets(events: list[dict[str, Any]]) -> list[str]:
        targets = set()

        for event in events:
            ip = event.get("original_remote_ip")
            port = event.get("original_remote_port")

            if ip is None or port is None:
                continue

            targets.add(f"{ip}:{port}")

        return sorted(targets)

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.out_dir))
        except ValueError:
            return str(path)

    @staticmethod
    def md(value: Any) -> str:
        if value is None:
            return ""

        return str(value).replace("|", "\\|")


def generate_report(out_dir: str | Path) -> dict[str, Any]:
    generator = RunReportGenerator(out_dir=out_dir)
    return generator.generate()
