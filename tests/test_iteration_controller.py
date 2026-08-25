from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from taintforge_env.attempt import AttemptOutcome, AttemptStore
from taintforge_env.environment_manifest import EnvironmentManifestStore
from taintforge_env.iteration_controller import (
    IterationController,
    IterationControllerError,
    IterationRecord,
    IterationState,
    SessionManifest,
    SessionState,
    StopReason,
)
from taintforge_env.progress_oracle import ProgressOracle
from taintforge_env.repair_applier import RepairApplier
from taintforge_env.repair_plan import (
    RepairActionKind,
    RepairDisposition,
    RepairPriority,
    RepairRisk,
    make_decision_id,
)


SAMPLE_SHA256 = hashlib.sha256(b"test-packed-sample").hexdigest()
GOAL_ID = "test_explicit_goal"


class IterationControllerTests(unittest.TestCase):
    def test_initialize_and_prepare_baseline_clone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = make_seed(root)
            session = root / "session"
            store = root / "store"
            manifest = IterationController.initialize(
                session_dir=session,
                snapshot_store=store,
                seed_rootfs=seed,
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            prepared = IterationController(session).prepare_next()
            self.assertEqual(prepared.record.index, 0)
            self.assertEqual(prepared.environment_snapshot_id, manifest.seed_snapshot_id)
            semantic = EnvironmentManifestStore(
                manifest.environment_manifest_store
            ).load(0)
            self.assertEqual(
                semantic.manifest_id,
                manifest.seed_environment_manifest_id,
            )
            self.assertEqual(
                semantic.rootfs_snapshot_id,
                prepared.environment_snapshot_id,
            )
            contract = AttemptStore(session / "attempts").load_contract(
                prepared.attempt_id
            )
            self.assertEqual(
                contract.environment_manifest_id,
                semantic.manifest_id,
            )
            self.assertEqual(contract.packed_binary_sha256, SAMPLE_SHA256)
            self.assertEqual(
                (prepared.execution_rootfs / "etc" / "seed.conf").read_text(),
                "seed\n",
            )
            (prepared.execution_rootfs / "etc" / "seed.conf").write_text("mutated\n")
            snapshot_file = store / manifest.seed_snapshot_id / "rootfs" / "etc" / "seed.conf"
            self.assertEqual(snapshot_file.read_text(), "seed\n")

    def test_next_iteration_applies_repair_to_clean_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = make_seed(root)
            session = root / "session"
            store = root / "store"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=store,
                seed_rootfs=seed,
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            first = controller.prepare_next()
            # Simulate malware pollution in X0. This must never become E1.
            (first.execution_rootfs / "tmp" / "malware-state").parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            (first.execution_rootfs / "tmp" / "malware-state").write_text("dirty")
            artifacts = root / "artifacts0"
            write_artifacts(artifacts, automatic=True, resource="/var/run/mirai")
            first_completed = controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
                guest_exit_code=1,
            )
            first_result = AttemptStore(session / "attempts").load_result(
                first_completed.attempt_id
            )
            self.assertEqual(first_result.outcome, AttemptOutcome.REPAIR_REQUIRED)
            self.assertIsNotNone(first_result.failure_fingerprint)
            second = controller.prepare_next()
            self.assertTrue((second.execution_rootfs / "var" / "run" / "mirai").is_dir())
            self.assertFalse((second.execution_rootfs / "tmp" / "malware-state").exists())
            self.assertNotEqual(first.environment_snapshot_id, second.environment_snapshot_id)
            semantic = EnvironmentManifestStore(
                controller.load().environment_manifest_store
            ).load(1)
            self.assertEqual(semantic.manifest_id, second.environment_manifest_id)
            self.assertEqual(semantic.rootfs_snapshot_id, second.environment_snapshot_id)
            self.assertEqual(len(semantic.entries), 1)
            self.assertEqual(semantic.entries[0].resource_id, "fs:/var/run/mirai")
            self.assertEqual(semantic.entries[0].provider, "static_directory")
            self.assertEqual(
                semantic.entries[0].first_seen_attempt_id,
                first_completed.attempt_id,
            )

    def test_no_automatic_repairs_stops_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(artifacts, automatic=False, resource="/etc/device.conf")
            record = controller.complete_iteration(iteration_index=0, artifacts_dir=artifacts)
            self.assertEqual(record.stop_reason, StopReason.NO_AUTOMATIC_REPAIRS.value)
            self.assertEqual(controller.load().state, SessionState.COMPLETED)

    def test_timeout_transitions_session_to_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(
                artifacts,
                automatic=True,
                resource="/var/run/mirai",
            )
            record = controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
                guest_exit_code=124,
                timed_out=True,
            )

            self.assertEqual(
                record.stop_reason,
                StopReason.EXECUTION_TIMED_OUT.value,
            )
            self.assertEqual(controller.load().state, SessionState.FAILED)
            result = AttemptStore(session / "attempts").load_result(
                record.attempt_id
            )
            self.assertEqual(result.outcome, AttemptOutcome.TIMED_OUT)
            with self.assertRaisesRegex(
                IterationControllerError,
                "not active",
            ):
                controller.prepare_next()

    def test_next_manifest_rejects_tampered_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(
                artifacts,
                automatic=True,
                resource="/var/run/mirai",
            )
            completed = controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
            )
            observation = session / str(completed.observation)
            observation.write_text(
                observation.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                IterationControllerError,
                "exact observation",
            ):
                controller.prepare_next()

    def test_next_manifest_rejects_tampered_repair_application(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(
                artifacts,
                automatic=True,
                resource="/var/run/mirai",
            )
            controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
            )
            original_apply = RepairApplier.apply_file

            def apply_and_tamper(applier, **kwargs):
                report = original_apply(applier, **kwargs)
                output = Path(kwargs["out_path"])
                payload = json.loads(output.read_text(encoding="utf-8"))
                payload["results"] = []
                output.write_text(
                    json.dumps(payload, indent=2) + "\n",
                    encoding="utf-8",
                )
                return report

            with patch.object(
                RepairApplier,
                "apply_file",
                new=apply_and_tamper,
            ):
                with self.assertRaisesRegex(
                    IterationControllerError,
                    "missing decision results",
                ):
                    controller.prepare_next()

    def test_manifest_records_observed_existing_directory_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = make_seed(root)
            existing = seed / "var" / "run" / "mirai"
            existing.mkdir(parents=True, mode=0o700)
            existing.chmod(0o700)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=seed,
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(
                artifacts,
                automatic=True,
                resource="/var/run/mirai",
            )
            controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
            )
            controller.prepare_next()
            semantic = EnvironmentManifestStore(
                controller.load().environment_manifest_store
            ).load(1)

            self.assertTrue(
                semantic.entries[0].value_id.startswith("directory-0700-")
            )

    def test_goal_marker_stops_session(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(artifacts, automatic=True, resource="/var/run/mirai")
            record = controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
                goal_reached=True,
                goal_reason="explicit main-loop checkpoint",
            )
            self.assertEqual(record.stop_reason, StopReason.GOAL_REACHED.value)

    def test_budget_exhaustion_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=1,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(artifacts, automatic=True, resource="/var/run/mirai")
            record = controller.complete_iteration(iteration_index=0, artifacts_dir=artifacts)
            self.assertEqual(record.stop_reason, StopReason.BUDGET_EXHAUSTED.value)

    def test_stale_plan_is_rejected_before_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(artifacts, automatic=True, resource="/var/run/mirai")
            requirements = artifacts / "config" / "runtime_requirements.json"
            requirements.write_text(requirements.read_text() + "\n", encoding="utf-8")
            with self.assertRaises(IterationControllerError):
                controller.complete_iteration(iteration_index=0, artifacts_dir=artifacts)
            self.assertEqual(controller.load().iterations[0].state.value, "prepared")

    def test_verify_detects_artifact_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(artifacts, automatic=False, resource="/etc/device.conf")
            controller.complete_iteration(iteration_index=0, artifacts_dir=artifacts)
            copied = session / "iterations" / "0000" / "artifacts" / "runtime_requirements.json"
            copied.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(IterationControllerError):
                controller.verify()

    def test_fixed_point_stops_when_environment_and_artifacts_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            seed = make_seed(root)
            (seed / "var" / "run" / "mirai").mkdir(parents=True)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=seed,
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=3,
            )
            controller = IterationController(session)
            controller.prepare_next()
            first_artifacts = root / "artifacts0"
            write_artifacts(first_artifacts, automatic=True, resource="/var/run/mirai")
            first = controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=first_artifacts,
            )
            self.assertIsNone(first.stop_reason)
            second_prepared = controller.prepare_next()
            self.assertEqual(
                second_prepared.environment_snapshot_id,
                controller.load().seed_snapshot_id,
            )
            second_artifacts = root / "artifacts1"
            write_artifacts(second_artifacts, automatic=True, resource="/var/run/mirai")
            second = controller.complete_iteration(
                iteration_index=1,
                artifacts_dir=second_artifacts,
            )
            self.assertEqual(second.stop_reason, StopReason.FIXED_POINT.value)

    def test_missing_session_path_is_not_created(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(IterationControllerError):
                IterationController(missing).load()
            self.assertFalse(missing.exists())

    def test_cycle_detection_matches_non_adjacent_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            base = IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
                max_iterations=5,
            )
            artifacts_a = root / "a"
            artifacts_b = root / "b"
            write_artifacts(artifacts_a, automatic=True, resource="/var/run/a")
            write_artifacts(artifacts_b, automatic=True, resource="/var/run/b")
            oracle = ProgressOracle()
            observation_a = oracle.observe(
                artifacts_a,
                environment_snapshot_id="env_state_a",
            )
            observation_b = oracle.observe(
                artifacts_b,
                environment_snapshot_id="env_state_b",
            )
            for index, observation in enumerate((observation_a, observation_b)):
                directory = session / "iterations" / f"{index:04d}"
                directory.mkdir(parents=True)
                observation_path = directory / "observation.json"
                observation.save(observation_path)
            manifest = SessionManifest(
                session_id=base.session_id,
                session_dir=base.session_dir,
                snapshot_store=base.snapshot_store,
                seed_snapshot_id=base.seed_snapshot_id,
                environment_manifest_store=base.environment_manifest_store,
                seed_environment_manifest_id=base.seed_environment_manifest_id,
                sample_sha256=base.sample_sha256,
                packed_binary_sha256=base.packed_binary_sha256,
                goal_id=base.goal_id,
                max_iterations=5,
                iterations=(
                    IterationRecord(
                        index=0,
                        state=IterationState.COMPLETED,
                        directory="iterations/0000",
                        environment_snapshot_id="env_state_a",
                        parent_snapshot_id=None,
                        environment_manifest_id=base.seed_environment_manifest_id,
                        environment_manifest_version=0,
                        attempt_id="attempt-000-000000000000",
                        attempt_contract=(
                            "attempts/attempt-000-000000000000/contract.json"
                        ),
                        observation="iterations/0000/observation.json",
                    ),
                    IterationRecord(
                        index=1,
                        state=IterationState.COMPLETED,
                        directory="iterations/0001",
                        environment_snapshot_id="env_state_b",
                        parent_snapshot_id="env_state_a",
                        environment_manifest_id="manifest-v0001-0000000000000000",
                        environment_manifest_version=1,
                        attempt_id="attempt-001-000000000000",
                        attempt_contract=(
                            "attempts/attempt-001-000000000000/contract.json"
                        ),
                        observation="iterations/0001/observation.json",
                    ),
                ),
            )
            reason = IterationController(session)._decide_stop_reason(
                manifest=manifest,
                iteration_index=2,
                observation=observation_a,
            )
            self.assertEqual(reason, StopReason.CYCLE_DETECTED)

    def test_iteration_manifest_rejects_path_traversal(self) -> None:
        with self.assertRaises(IterationControllerError):
            IterationRecord.from_dict(
                {
                    "index": 0,
                    "state": "prepared",
                    "directory": "../../outside",
                    "environment_snapshot_id": "env_test",
                    "parent_snapshot_id": None,
                }
            )

    def test_cannot_prepare_twice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
            )
            controller = IterationController(session)
            controller.prepare_next()
            with self.assertRaises(IterationControllerError):
                controller.prepare_next()

    def test_verify_rejects_terminal_attempt_marked_active(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = root / "session"
            IterationController.initialize(
                session_dir=session,
                snapshot_store=root / "store",
                seed_rootfs=make_seed(root),
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=SAMPLE_SHA256,
                goal_id=GOAL_ID,
            )
            controller = IterationController(session)
            controller.prepare_next()
            artifacts = root / "artifacts"
            write_artifacts(
                artifacts,
                automatic=False,
                resource="/etc/device.conf",
            )
            controller.complete_iteration(
                iteration_index=0,
                artifacts_dir=artifacts,
            )
            session_path = session / "session.json"
            payload = json.loads(session_path.read_text(encoding="utf-8"))
            payload["state"] = "active"
            payload["stop_reason"] = None
            session_path.write_text(
                json.dumps(payload, indent=2) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                IterationControllerError,
                "session state",
            ):
                controller.verify()


def make_seed(root: Path) -> Path:
    seed = root / "seed"
    (seed / "etc").mkdir(parents=True)
    (seed / "tmp").mkdir()
    (seed / "etc" / "seed.conf").write_text("seed\n", encoding="utf-8")
    return seed


def write_artifacts(root: Path, *, automatic: bool, resource: str) -> None:
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(parents=True, exist_ok=True)
    requirement_id = "req_test"
    operation = "directory_exists" if automatic else "path_exists"
    requirements = {
        "schema_version": 1,
        "requirements": [
            {
                "requirement_id": requirement_id,
                "kind": "filesystem",
                "resource": resource,
                "operation": operation,
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
    action = RepairActionKind.CREATE_DIRECTORY if automatic else RepairActionKind.PROVIDE_FILE
    disposition = (
        RepairDisposition.AUTO_CANDIDATE
        if automatic
        else RepairDisposition.REVIEW_REQUIRED
    )
    plan = {
        "schema_version": 1,
        "planner_version": 1,
        "generated_at_utc": "2026-01-01T00:00:00+00:00",
        "source_requirements": str(requirements_path),
        "source_sha256": source_sha,
        "warnings": [],
        "decisions": [
            {
                "decision_id": make_decision_id(requirement_id, action, disposition, resource),
                "requirement_id": requirement_id,
                "requirement_kind": "filesystem",
                "resource": resource,
                "operation": operation,
                "action": action.value,
                "disposition": disposition.value,
                "priority": RepairPriority.CRITICAL.value,
                "risk": (RepairRisk.LOW if automatic else RepairRisk.MEDIUM).value,
                "automatic_allowed": automatic,
                "reason": "test decision",
                "parameters": (
                    {"mode": "0755", "parents": True}
                    if automatic
                    else {"create_empty": False}
                ),
            }
        ],
    }
    (root / "config" / "repair_plan.json").write_text(
        json.dumps(plan, indent=2) + "\n",
        encoding="utf-8",
    )
    with (root / "logs" / "syscall_events.jsonl").open("w", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "event": "syscall",
                    "execution_context": "guest",
                    "syscall": "openat",
                    "path": resource,
                    "return_value": -1,
                    "errno": "ENOENT",
                }
            )
            + "\n"
        )


if __name__ == "__main__":
    unittest.main()
