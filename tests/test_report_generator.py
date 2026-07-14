from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.report_generator import generate_report


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


class ReportGeneratorTests(unittest.TestCase):
    def test_prebuilt_artifacts_are_reported_from_canonical_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            config = run_dir / "config"
            logs = run_dir / "logs"
            config.mkdir(parents=True)
            logs.mkdir()
            binary = run_dir / "sample"
            binary.write_bytes(b"ELF fixture")

            write_json(
                config / "runtime.json",
                {
                    "arch": "i386",
                    "rootfs": str(run_dir / "rootfs"),
                    "host_binary_path": str(binary),
                    "guest_binary_path": "/bin/unpacked.elf",
                    "qemu_required": False,
                    "libraries_ok": True,
                },
            )
            write_json(
                config / "prebuilt_execution.json",
                {
                    "guest_exit_code": 0,
                    "timed_out": False,
                    "execution_backend": "native",
                    "trace_backend": "strace",
                    "target_arch": "i386",
                },
            )
            write_json(
                config / "prebuilt_runner_manifest.json",
                {
                    "timeout_seconds": 30,
                    "isolation": {
                        "chroot": True,
                        "network_namespace": True,
                        "pid_namespace": True,
                        "mount_namespace": True,
                        "uts_namespace": True,
                        "ipc_namespace": True,
                        "user_namespace": False,
                        "proc_private_mount": True,
                    },
                },
            )
            write_json(
                config / "network_backend_manifest.json",
                {
                    "state": "cleaned",
                    "allow_internet": False,
                    "host_ip_forwarding_modified": False,
                    "plan": {
                        "catch_all_enabled": True,
                        "host_services": [{"remote_ip": "198.51.100.10"}],
                    },
                },
            )
            write_json(
                config / "network_policy.json",
                {
                    "mode": "controlled",
                    "allow_internet": False,
                    "services": [],
                    "catch_all": {"enabled": True, "udp_enabled": True},
                },
            )
            write_json(config / "library_plan.json", {"requirements": []})
            write_json(
                config / "library_resolution.json",
                {"resolved": [], "missing": []},
            )
            write_json(
                config / "rootfs_diff.json",
                {
                    "created_count": 1,
                    "modified_count": 0,
                    "deleted_count": 0,
                    "created": [{"path": "/tmp/result", "type": "file"}],
                    "modified": [],
                    "deleted": [],
                },
            )
            write_json(
                config / "target_state_evaluation.json",
                {
                    "goal_id": "phase2_demo",
                    "reached": True,
                    "reason": "marker observed",
                    "matched_rules": 2,
                    "total_rules": 2,
                    "spec_sha256": "a" * 64,
                    "evaluation_sha256": "b" * 64,
                    "rules": [],
                },
            )
            (logs / "runtime_stdout.log").write_text(
                "TAINTFORGE_PHASE2_MILESTONE\n",
                encoding="utf-8",
            )
            (logs / "runtime_stderr.log").write_text("", encoding="utf-8")
            (logs / "syscall_events.jsonl").write_text(
                json.dumps(
                    {
                        "event": "syscall",
                        "execution_context": "host_wrapper",
                        "syscall": "execve",
                        "paths": ["/usr/bin/chroot"],
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "event": "syscall",
                        "execution_context": "guest",
                        "syscall": "write",
                        "category": "filesystem",
                        "paths": ["/tmp/result"],
                        "success": True,
                        "high_risk": False,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            write_json(
                logs / "syscall_events.summary.json",
                {
                    "events_total": 2,
                    "by_context": {"host_wrapper": 1, "guest": 1},
                    "host_wrapper_paths": ["/usr/bin/chroot"],
                    "all_paths": ["/tmp/result", "/usr/bin/chroot"],
                },
            )

            report = generate_report(run_dir)

        self.assertEqual(report["runtime"]["status"]["exit_code"], 0)
        self.assertEqual(report["runtime"]["status"]["timeout_seconds"], 30)
        self.assertEqual(report["filesystem"]["created_count"], 1)
        self.assertEqual(report["syscalls"]["events_total"], 1)
        self.assertEqual(
            report["syscalls"]["by_context"],
            {"host_wrapper": 1, "guest": 1},
        )
        self.assertTrue(report["target_state"]["reached"])
        self.assertTrue(report["security"]["chroot_enabled"])
        self.assertTrue(report["security"]["network_namespace_enabled"])
        self.assertFalse(report["security"]["user_namespace_enabled"])
        self.assertFalse(report["security"]["allow_internet"])
        self.assertTrue(report["security"]["known_endpoint_dnat"])

    def test_security_claims_remain_unknown_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            (run_dir / "config").mkdir(parents=True)
            (run_dir / "logs").mkdir()
            report = generate_report(run_dir)

        self.assertIsNone(report["security"]["chroot_enabled"])
        self.assertIsNone(report["security"]["network_namespace_enabled"])
        self.assertIsNone(report["security"]["iptables_default_deny_expected"])
        self.assertEqual(report["security"]["evidence_sources"], [])

    def test_disconnected_runtime_does_not_claim_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            config = run_dir / "config"
            logs = run_dir / "logs"
            config.mkdir(parents=True)
            logs.mkdir()
            write_json(
                config / "network_policy.json",
                {
                    "mode": "local_test",
                    "allow_internet": False,
                    "services": [],
                    "catch_all": {"enabled": True, "udp_enabled": True},
                },
            )
            write_json(
                logs / "security_status.json",
                {
                    "isolation_ready": True,
                    "chroot": True,
                    "network_namespace": True,
                    "network_mode": "none",
                    "network_connected": False,
                    "network_default_deny": True,
                },
            )
            report = generate_report(run_dir)

        self.assertFalse(report["security"]["allow_internet"])
        self.assertFalse(report["security"]["known_endpoint_dnat"])
        self.assertFalse(report["security"]["tcp_catch_all_redirect"])
        self.assertFalse(report["security"]["udp_catch_all_redirect"])


if __name__ == "__main__":
    unittest.main()
