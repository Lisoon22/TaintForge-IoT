from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from taintforge_env.iteration_controller import (
    IterationController,
    SessionState,
)
from taintforge_env.prebuilt_runner import (
    CommandResult,
    PrebuiltRootfsRunner,
    PrebuiltRunnerConfig,
    PrebuiltRunnerError,
)


class FakeExecutor:
    def __init__(self, *, guest_exit_code: int = 0, infrastructure_fail: bool = False):
        self.guest_exit_code = guest_exit_code
        self.infrastructure_fail = infrastructure_fail
        self.commands: list[list[str]] = []

    def run(
        self,
        command,
        *,
        cwd: Path,
        check: bool = True,
        stdout_path: Path | None = None,
        stderr_path: Path | None = None,
    ) -> CommandResult:
        cmd = [str(value) for value in command]
        self.commands.append(cmd)
        if stdout_path is not None:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text("guest stdout\n", encoding="utf-8")
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_path.write_text("", encoding="utf-8")

        if any(value.endswith("capture_runtime_observations.py") for value in cmd):
            script_index = next(i for i, value in enumerate(cmd) if value.endswith("capture_runtime_observations.py"))
            phase = cmd[script_index + 1]
            run_dir = Path(cmd[cmd.index("--run-dir") + 1])
            config = run_dir / "config"
            config.mkdir(parents=True, exist_ok=True)
            if phase == "before":
                _write_json(config / "rootfs_before.json", {"entries_count": 3})
            elif phase == "finalize":
                _write_json(config / "rootfs_after.json", {"entries_count": 3})
                _write_json(
                    config / "rootfs_diff.json",
                    {
                        "created_count": 0,
                        "modified_count": 0,
                        "deleted_count": 0,
                    },
                )
                _write_json(
                    config / "runtime_requirements.json",
                    {
                        "schema_version": 1,
                        "requirements": [],
                        "warnings": [],
                    },
                )
                _write_json(
                    config / "observation_lifecycle.json",
                    {"status": "completed"},
                )
            return CommandResult(0)

        if any(value.endswith("parse_strace.py") for value in cmd):
            out = Path(cmd[cmd.index("--out") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(
                    {
                        "event": "syscall",
                        "execution_context": "guest",
                        "syscall": "write",
                        "success": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            return CommandResult(0)

        if any(value.endswith("plan_repairs.py") for value in cmd):
            requirements = Path(cmd[cmd.index("--requirements") + 1])
            out = Path(cmd[cmd.index("--out") + 1])
            source_hash = hashlib.sha256(requirements.read_bytes()).hexdigest()
            _write_json(
                out,
                {
                    "schema_version": 1,
                    "planner_version": 1,
                    "source_requirements": str(requirements),
                    "source_sha256": source_hash,
                    "decisions": [],
                },
            )
            return CommandResult(0)

        if any(value.endswith("generate_report.py") for value in cmd):
            run_dir = Path(cmd[cmd.index("--out") + 1])
            _write_json(run_dir / "report.json", {"status": "ok"})
            (run_dir / "report.md").write_text("# Report\n", encoding="utf-8")
            return CommandResult(0)

        if cmd and cmd[-1].endswith("run_prebuilt_sandbox.sh") and "unshare" in cmd:
            if self.infrastructure_fail:
                return CommandResult(1, stderr="unshare failed")
            script = Path(cmd[-1])
            run_dir = script.parent
            logs = run_dir / "logs"
            logs.mkdir(parents=True, exist_ok=True)
            (logs / "malware_started").write_text("now\n", encoding="utf-8")
            (logs / "guest_exit_code").write_text(
                f"{self.guest_exit_code}\n",
                encoding="utf-8",
            )
            (logs / "strace.1").write_text("write(1, \\\"x\\\", 1) = 1\n")
            return CommandResult(self.guest_exit_code)

        return CommandResult(0)


class FakeNetworkResult:
    def __init__(self, manifest_path: Path) -> None:
        self.manifest_path = manifest_path


class FakeNetworkBackend:
    def __init__(self, config, executor) -> None:
        self.config = config
        self.executor = executor
        self.manifest_path = config.run_dir / "config" / "network_backend_manifest.json"
        self.cleaned = False

    def setup(self):
        config_dir = self.config.run_dir / "config"
        logs_dir = self.config.run_dir / "logs"
        requested = config_dir / "network_policy_requested.json"
        requested.write_text(
            (config_dir / "network_policy.json").read_text(),
            encoding="utf-8",
        )
        _write_json(
            config_dir / "network_policy.json",
            {
                "mode": "controlled",
                "allow_internet": False,
                "services": [],
                "catch_all": {"enabled": True},
            },
        )
        _write_json(
            self.manifest_path,
            {
                "state": "ready",
                "allow_internet": False,
                "namespace": "tf-test",
            },
        )
        (logs_dir / "network_events.jsonl").write_text(
            json.dumps(
                {
                    "event": "tcp_connection_open",
                    "original_remote_ip": "203.0.113.10",
                    "original_remote_port": 48101,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return FakeNetworkResult(self.manifest_path)

    def guest_command(self, sandbox_script: Path):
        return [
            "sudo",
            "ip",
            "netns",
            "exec",
            "tf-test",
            "unshare",
            "--mount",
            "--pid",
            "--fork",
            "--uts",
            "--ipc",
            "--",
            "bash",
            str(sandbox_script),
        ]

    def cleanup(self, *, finalize_logs: bool = True):
        self.cleaned = True
        _write_json(
            self.manifest_path,
            {
                "state": "cleaned",
                "allow_internet": False,
                "namespace": "tf-test",
            },
        )


class PrebuiltRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()
        for relative in (
            "scripts/capture_runtime_observations.py",
            "scripts/parse_strace.py",
            "scripts/plan_repairs.py",
            "scripts/generate_report.py",
        ):
            path = self.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# placeholder\n", encoding="utf-8")

        self.binary = self.base / "sample"
        self.binary.write_bytes(b"ELF-test")
        self.seed = self.base / "seed-rootfs"
        (self.seed / "bin").mkdir(parents=True)
        (self.seed / "proc").mkdir()
        guest = self.seed / "bin" / "unpacked.elf"
        guest.write_bytes(b"guest")
        guest.chmod(0o755)

        self.template = self.base / "template-run"
        (self.template / "config").mkdir(parents=True)
        _write_json(
            self.template / "config" / "runtime.json",
            {
                "rootfs": str(self.seed),
                "host_binary": str(self.binary),
                "guest_binary": "/bin/unpacked.elf",
                "qemu_required": False,
            },
        )
        _write_json(
            self.template / "config" / "library_plan.json",
            {"requirements": []},
        )
        _write_json(
            self.template / "config" / "library_resolution.json",
            {"resolved": [], "missing": []},
        )
        _write_json(
            self.template / "config" / "network_policy.json",
            {"mode": "local_test", "allow_internet": False, "services": []},
        )

        self.session = self.base / "session"
        IterationController.initialize(
            session_dir=self.session,
            snapshot_store=self.base / "snapshots",
            seed_rootfs=self.seed,
            max_iterations=3,
        )
        IterationController(self.session).prepare_next()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_runner(
        self,
        executor: FakeExecutor | None = None,
        *,
        target_spec: Path | None = None,
        network_mode: str = "none",
        network_self_test: bool = False,
        network_backend_factory=None,
    ) -> PrebuiltRootfsRunner:
        return PrebuiltRootfsRunner(
            PrebuiltRunnerConfig(
                session_dir=self.session,
                iteration_index=0,
                template_run_dir=self.template,
                project_root=self.project,
                timeout_seconds=5,
                target_spec_path=target_spec,
                network_mode=network_mode,
                network_self_test=network_self_test,
            ),
            executor=executor or FakeExecutor(),
            network_backend_factory=network_backend_factory,
        )

    def test_validate_binds_exact_prepared_rootfs(self) -> None:
        context = self.make_runner().validate()
        self.assertEqual(context.iteration.index, 0)
        self.assertEqual(
            context.execution_rootfs,
            self.session / "iterations" / "0000" / "execution" / "rootfs",
        )
        self.assertEqual(context.guest_binary, "/bin/unpacked.elf")

    def test_tampered_execution_rootfs_is_rejected_before_claim(self) -> None:
        rootfs = self.session / "iterations" / "0000" / "execution" / "rootfs"
        (rootfs / "tmp").mkdir()
        with self.assertRaisesRegex(
            PrebuiltRunnerError,
            "no longer matches",
        ):
            self.make_runner().validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_qemu_runtime_fails_closed(self) -> None:
        runtime_path = self.template / "config" / "runtime.json"
        runtime = json.loads(runtime_path.read_text())
        runtime["qemu_required"] = True
        _write_json(runtime_path, runtime)
        with self.assertRaisesRegex(PrebuiltRunnerError, "qemu_required"):
            self.make_runner().validate()

    def test_missing_guest_binary_is_rejected(self) -> None:
        runtime_path = self.template / "config" / "runtime.json"
        runtime = json.loads(runtime_path.read_text())
        runtime["guest_binary"] = "/bin/missing"
        _write_json(runtime_path, runtime)
        with self.assertRaisesRegex(PrebuiltRunnerError, "guest binary is absent"):
            self.make_runner().validate()

    def test_runtime_template_symlink_is_rejected(self) -> None:
        runtime_path = self.template / "config" / "runtime.json"
        real = self.base / "runtime-real.json"
        runtime_path.replace(real)
        runtime_path.symlink_to(real)
        with self.assertRaisesRegex(PrebuiltRunnerError, "symlink"):
            self.make_runner().validate()

    def test_run_closes_iteration_and_rewrites_runtime(self) -> None:
        executor = FakeExecutor(guest_exit_code=0)
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()

        self.assertEqual(result.guest_exit_code, 0)
        self.assertEqual(result.stop_reason, "no_automatic_repairs")
        manifest = IterationController(self.session).load()
        self.assertEqual(manifest.state, SessionState.COMPLETED)
        runtime = json.loads(
            (result.run_dir / "config" / "runtime.json").read_text()
        )
        self.assertEqual(
            runtime["rootfs"],
            str(self.session / "iterations" / "0000" / "execution" / "rootfs"),
        )
        self.assertEqual(runtime["prebuilt_environment"]["iteration_index"], 0)
        self.assertTrue(
            (self.session / "iterations" / "0000" / "artifacts" / "repair_plan.json").is_file()
        )

    def test_target_spec_marks_iteration_goal_reached(self) -> None:
        target = self.base / "target.json"
        _write_json(
            target,
            {
                "schema_version": 1,
                "goal_id": "guest_write_reached",
                "description": "guest write syscall reached",
                "mode": "all",
                "rules": [
                    {
                        "id": "write",
                        "type": "event_count",
                        "source": "syscall",
                        "where": {"syscall": "write", "success": True},
                        "min_count": 1,
                    }
                ],
            },
        )
        runner = self.make_runner(FakeExecutor(), target_spec=target)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertTrue(result.target_reached)
        self.assertEqual(result.stop_reason, "goal_reached")
        self.assertTrue(result.target_evaluation_path.is_file())
        evaluation = json.loads(result.target_evaluation_path.read_text())
        self.assertTrue(evaluation["reached"])
        copied = result.run_dir / "config" / "target_state_spec.json"
        self.assertTrue(copied.is_file())
        manifest = IterationController(self.session).load()
        self.assertEqual(manifest.state, SessionState.COMPLETED)
        self.assertEqual(manifest.stop_reason, "goal_reached")

    def test_invalid_target_spec_is_rejected_before_claim(self) -> None:
        target = self.base / "invalid-target.json"
        target.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(PrebuiltRunnerError, "schema"):
            self.make_runner(target_spec=target).validate()
        self.assertFalse(
            (self.session / "iterations" / "0000" / "execution_attempt.json").exists()
        )

    def test_timeout_is_observation_not_runner_failure(self) -> None:
        runner = self.make_runner(FakeExecutor(guest_exit_code=124))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertTrue(result.timed_out)
        self.assertEqual(result.guest_exit_code, 124)

    def test_sandbox_uses_private_namespaces(self) -> None:
        executor = FakeExecutor()
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            runner.run_and_complete()
        unshare = next(command for command in executor.commands if command[:2] == ["sudo", "unshare"])
        for option in ("--mount", "--pid", "--uts", "--ipc", "--net"):
            self.assertIn(option, unshare)
        script = (
            self.session / "iterations" / "0000" / "run" / "run_prebuilt_sandbox.sh"
        ).read_text()
        self.assertIn("mount --make-rprivate /", script)
        self.assertIn("ip link set lo up", script)
        self.assertIn("mount -t proc", script)

    def test_observer_explicitly_allows_external_rootfs(self) -> None:
        executor = FakeExecutor()
        runner = self.make_runner(executor)
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            runner.run_and_complete()
        observer_commands = [
            command
            for command in executor.commands
            if any(value.endswith("capture_runtime_observations.py") for value in command)
        ]
        self.assertEqual(len(observer_commands), 2)
        self.assertTrue(
            all("--allow-external-rootfs" in command for command in observer_commands)
        )

    def test_controlled_network_run_uses_named_namespace_backend(self) -> None:
        executor = FakeExecutor()
        created: list[FakeNetworkBackend] = []

        def factory(config, command_executor):
            backend = FakeNetworkBackend(config, command_executor)
            created.append(backend)
            return backend

        runner = self.make_runner(
            executor,
            network_mode="controlled",
            network_self_test=True,
            network_backend_factory=factory,
        )
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            result = runner.run_and_complete()
        self.assertEqual(result.network_mode, "controlled")
        self.assertTrue(result.network_manifest_path.is_file())
        self.assertTrue(created[0].cleaned)
        execution = next(
            command
            for command in executor.commands
            if command and command[-1].endswith("run_prebuilt_sandbox.sh")
        )
        self.assertEqual(execution[:4], ["sudo", "ip", "netns", "exec"])
        self.assertNotIn("--net", execution)
        runtime = json.loads(
            (result.run_dir / "config" / "runtime.json").read_text()
        )
        self.assertEqual(runtime["network_mode"], "controlled")
        self.assertFalse(runtime["allow_internet"])
        self.assertTrue(
            (result.run_dir / "logs" / "network_events.jsonl").is_file()
        )

    def test_controlled_network_requires_template_policy(self) -> None:
        (self.template / "config" / "network_policy.json").unlink()
        with self.assertRaisesRegex(PrebuiltRunnerError, "network policy"):
            self.make_runner(network_mode="controlled").validate()

    def test_network_self_test_requires_controlled_mode(self) -> None:
        with self.assertRaisesRegex(PrebuiltRunnerError, "requires"):
            self.make_runner(network_self_test=True)

    def test_infrastructure_failure_records_retry_safe_claim(self) -> None:
        runner = self.make_runner(FakeExecutor(infrastructure_fail=True))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            with self.assertRaisesRegex(PrebuiltRunnerError, "infrastructure failed"):
                runner.run_and_complete()
        claim = json.loads(
            (
                self.session
                / "iterations"
                / "0000"
                / "execution_attempt.json"
            ).read_text()
        )
        self.assertEqual(claim["stage"], "failed")
        self.assertFalse(claim["malware_started"])
        self.assertTrue(claim["retry_safe"])


    def test_claim_blocks_manual_completion_while_runner_is_active(self) -> None:
        claim = self.session / "iterations" / "0000" / "execution_attempt.json"
        _write_json(
            claim,
            {
                "session_id": IterationController(self.session).load().session_id,
                "iteration_index": 0,
                "stage": "executing",
            },
        )
        with self.assertRaisesRegex(Exception, "not ready for completion"):
            IterationController(self.session).complete_iteration(
                iteration_index=0,
                artifacts_dir=self.template,
            )

    def test_retry_safe_failure_can_be_reset(self) -> None:
        runner = self.make_runner(FakeExecutor(infrastructure_fail=True))
        with patch.object(runner, "_check_host_dependencies", return_value=None):
            with self.assertRaises(PrebuiltRunnerError):
                runner.run_and_complete()
        runner.reset_safe_failure()
        iteration = self.session / "iterations" / "0000"
        self.assertFalse((iteration / "execution_attempt.json").exists())
        self.assertFalse((iteration / "run").exists())
        runner.validate()

    def test_failure_after_guest_start_cannot_be_reset(self) -> None:
        iteration = self.session / "iterations" / "0000"
        _write_json(
            iteration / "execution_attempt.json",
            {
                "stage": "failed",
                "malware_started": True,
                "retry_safe": False,
            },
        )
        with self.assertRaisesRegex(
            PrebuiltRunnerError,
            "after malware started",
        ):
            self.make_runner().reset_safe_failure()

    def test_existing_claim_prevents_second_execution(self) -> None:
        claim = self.session / "iterations" / "0000" / "execution_attempt.json"
        _write_json(claim, {"stage": "failed"})
        with self.assertRaisesRegex(PrebuiltRunnerError, "execution attempt"):
            self.make_runner().validate()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
