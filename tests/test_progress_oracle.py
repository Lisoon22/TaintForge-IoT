from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.progress_oracle import (
    ProgressClassification,
    ProgressOracle,
    ProgressOracleError,
)
from taintforge_env.repair_plan import (
    RepairActionKind,
    RepairDisposition,
    RepairPriority,
    RepairRisk,
    make_decision_id,
)


class ProgressOracleTests(unittest.TestCase):
    def test_observation_filters_host_wrapper_and_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_artifacts(root, automatic=True)
            append_jsonl(
                root / "logs" / "syscall_events.jsonl",
                {
                    "event": "syscall",
                    "execution_context": "host_wrapper",
                    "syscall": "execve",
                    "path": "/usr/bin/chroot",
                    "return_value": 0,
                },
            )
            append_jsonl(
                root / "logs" / "syscall_events.jsonl",
                {
                    "event": "syscall",
                    "execution_context": "guest",
                    "syscall": "openat",
                    "path": "/etc/device.conf",
                    "return_value": -1,
                    "errno": "ENOENT",
                },
            )
            oracle = ProgressOracle()
            first = oracle.observe(root, environment_snapshot_id="env_1234")
            second = oracle.observe(root, environment_snapshot_id="env_1234")
            self.assertEqual(first.state_fingerprint, second.state_fingerprint)
            self.assertEqual(first.metrics.guest_events_total, 1)
            self.assertEqual(first.normalized_guest_events[0]["path"], "/etc/device.conf")

    def test_plan_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_artifacts(root, automatic=True)
            plan_path = root / "config" / "repair_plan.json"
            raw = json.loads(plan_path.read_text(encoding="utf-8"))
            raw["source_sha256"] = "0" * 64
            plan_path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(ProgressOracleError):
                ProgressOracle().observe(root, environment_snapshot_id="env_1234")

    def test_progress_detects_new_guest_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_dir = root / "first"
            second_dir = root / "second"
            write_artifacts(first_dir, automatic=True)
            write_artifacts(second_dir, automatic=True)
            append_jsonl(
                first_dir / "logs" / "syscall_events.jsonl",
                guest_syscall("openat", "/etc/a", "ENOENT"),
            )
            append_jsonl(
                second_dir / "logs" / "syscall_events.jsonl",
                guest_syscall("openat", "/etc/a", "ENOENT"),
            )
            append_jsonl(
                second_dir / "logs" / "syscall_events.jsonl",
                guest_syscall("connect", None, "ECONNREFUSED", remote_ip="1.2.3.4", remote_port=80),
            )
            oracle = ProgressOracle()
            first = oracle.observe(first_dir, environment_snapshot_id="env_a")
            second = oracle.observe(second_dir, environment_snapshot_id="env_b")
            decision = oracle.compare(first, second)
            self.assertEqual(decision.classification, ProgressClassification.PROGRESS)
            self.assertEqual(decision.new_guest_events, 1)

    def test_explicit_goal_is_only_success_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_artifacts(root, automatic=False)
            observation = ProgressOracle().observe(
                root,
                environment_snapshot_id="env_goal",
                goal_reached=True,
                goal_reason="main loop marker reached",
            )
            decision = ProgressOracle().compare(None, observation)
            self.assertEqual(decision.classification, ProgressClassification.GOAL_REACHED)


def write_artifacts(root: Path, *, automatic: bool) -> None:
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    requirement_id = "req_test"
    requirements = {
        "schema_version": 1,
        "requirements": [
            {
                "requirement_id": requirement_id,
                "kind": "filesystem",
                "resource": "/var/run/mirai",
                "operation": "directory_exists",
                "status": "unmet",
                "blocking": "likely",
                "confidence": 1.0,
                "repairable": True,
                "errno": "ENOENT",
                "evidence": [],
                "details": {},
            }
        ],
    }
    requirements_path = root / "config" / "runtime_requirements.json"
    requirements_path.write_text(json.dumps(requirements, indent=2) + "\n", encoding="utf-8")
    source_sha = hashlib.sha256(requirements_path.read_bytes()).hexdigest()
    disposition = (
        RepairDisposition.AUTO_CANDIDATE
        if automatic
        else RepairDisposition.REVIEW_REQUIRED
    )
    action = (
        RepairActionKind.CREATE_DIRECTORY
        if automatic
        else RepairActionKind.PROVIDE_FILE
    )
    resource = "/var/run/mirai" if automatic else "/etc/device.conf"
    decision_id = make_decision_id(requirement_id, action, disposition, resource)
    plan = {
        "schema_version": 1,
        "planner_version": 1,
        "generated_at_utc": "2026-01-01T00:00:00+00:00",
        "source_requirements": str(requirements_path),
        "source_sha256": source_sha,
        "warnings": [],
        "decisions": [
            {
                "decision_id": decision_id,
                "requirement_id": requirement_id,
                "requirement_kind": "filesystem",
                "resource": resource,
                "operation": "directory_exists" if automatic else "path_exists",
                "action": action.value,
                "disposition": disposition.value,
                "priority": RepairPriority.CRITICAL.value,
                "risk": (RepairRisk.LOW if automatic else RepairRisk.MEDIUM).value,
                "automatic_allowed": automatic,
                "reason": "test decision",
                "parameters": {"mode": "0755", "parents": True} if automatic else {"create_empty": False},
            }
        ],
    }
    (root / "config" / "repair_plan.json").write_text(
        json.dumps(plan, indent=2) + "\n",
        encoding="utf-8",
    )


def guest_syscall(
    syscall: str,
    path: str | None,
    errno: str | None,
    *,
    remote_ip: str | None = None,
    remote_port: int | None = None,
) -> dict:
    return {
        "event": "syscall",
        "execution_context": "guest",
        "syscall": syscall,
        "path": path,
        "return_value": -1 if errno else 0,
        "errno": errno,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
    }


def append_jsonl(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value) + "\n")


if __name__ == "__main__":
    unittest.main()
