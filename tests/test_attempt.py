import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from taintforge_env.attempt import (
    AttemptContract,
    AttemptOutcome,
    AttemptProgress,
    AttemptResult,
    AttemptStore,
    AttemptValidationError,
    ExecutionStage,
    RunPurpose,
    StageTransition,
    make_failure_fingerprint,
)


SAMPLE_SHA256 = "1" * 64
BINARY_SHA256 = "2" * 64


class AttemptContractTests(unittest.TestCase):
    def make_contract(self) -> AttemptContract:
        return AttemptContract.create(
            attempt_index=3,
            purpose=RunPurpose.DISCOVERY,
            sample_sha256=SAMPLE_SHA256,
            packed_binary_sha256=BINARY_SHA256,
            environment_manifest_id="manifest-v0003-0123456789abcdef",
            environment_manifest_version=3,
            goal_id="confirmed-oep-and-boundary",
            initial_stage=ExecutionStage.PRE_OEP_DISCOVERY,
        )

    def test_contract_round_trip_and_digest(self) -> None:
        contract = self.make_contract()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "attempt-003-contract.json"
            contract.save(path)
            loaded = AttemptContract.load(path)

        self.assertEqual(loaded, contract)
        self.assertEqual(len(contract.contract_sha256), 64)
        self.assertTrue(contract.attempt_id.startswith("attempt-003-"))

    def test_contract_digest_detects_tampering(self) -> None:
        contract = self.make_contract()
        raw = contract.to_dict()
        raw["goal_id"] = "different-goal"

        with self.assertRaisesRegex(
            AttemptValidationError, "contract digest mismatch"
        ):
            AttemptContract.from_dict(raw)

    def test_fuzzing_contract_requires_validated_boundary(self) -> None:
        with self.assertRaisesRegex(
            AttemptValidationError, "validated boundary"
        ):
            AttemptContract.create(
                attempt_index=0,
                purpose=RunPurpose.FUZZING,
                sample_sha256=SAMPLE_SHA256,
                packed_binary_sha256=BINARY_SHA256,
                environment_manifest_id="manifest-v0000-0123456789abcdef",
                environment_manifest_version=0,
                goal_id="fuzzing",
                initial_stage=ExecutionStage.PRE_OEP_DISCOVERY,
            )

    def test_oep_transition_keeps_one_attempt_identity(self) -> None:
        contract = self.make_contract()
        transitions = (
            StageTransition(
                sequence=0,
                from_stage=ExecutionStage.PRE_OEP_DISCOVERY,
                to_stage=ExecutionStage.OEP_CANDIDATE,
                reason="write-execute candidate observed",
                evidence_event_id="phase1:event-41",
            ),
            StageTransition(
                sequence=1,
                from_stage=ExecutionStage.OEP_CANDIDATE,
                to_stage=ExecutionStage.OEP_VALIDATION,
                reason="candidate passed initial scoring",
                evidence_event_id="phase1:event-58",
            ),
            StageTransition(
                sequence=2,
                from_stage=ExecutionStage.OEP_VALIDATION,
                to_stage=ExecutionStage.POST_OEP_STABILIZATION,
                reason="OEP confirmed without relaunch",
                evidence_event_id="phase1:event-73",
            ),
        )
        result = AttemptResult(
            attempt_id=contract.attempt_id,
            contract_sha256=contract.contract_sha256,
            outcome=AttemptOutcome.EXITED,
            initial_stage=contract.initial_stage,
            final_stage=ExecutionStage.POST_OEP_STABILIZATION,
            progress=AttemptProgress(
                goal_reached=False,
                oracle_reason=None,
                guest_events_total=73,
            ),
            transitions=transitions,
        )

        loaded = AttemptResult.from_dict(result.to_dict())
        self.assertEqual(loaded.attempt_id, contract.attempt_id)
        self.assertEqual(len(loaded.result_sha256), 64)
        self.assertEqual(
            loaded.final_stage, ExecutionStage.POST_OEP_STABILIZATION
        )
        self.assertEqual(len(loaded.transitions), 3)

    def test_invalid_stage_jump_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            AttemptValidationError, "invalid execution-stage transition"
        ):
            StageTransition(
                sequence=0,
                from_stage=ExecutionStage.PRE_OEP_DISCOVERY,
                to_stage=ExecutionStage.POST_OEP_STABILIZATION,
                reason="invalid shortcut",
                evidence_event_id="phase1:event-1",
            )

    def test_failure_fingerprint_is_deterministic(self) -> None:
        first = make_failure_fingerprint(
            outcome=AttemptOutcome.REPAIR_REQUIRED,
            stage=ExecutionStage.PRE_OEP_DISCOVERY,
            exit_code=1,
            error_code="ENOENT",
            blocking_resource="/var/run/mirai",
        )
        second = make_failure_fingerprint(
            outcome=AttemptOutcome.REPAIR_REQUIRED,
            stage=ExecutionStage.PRE_OEP_DISCOVERY,
            exit_code=1,
            error_code="ENOENT",
            blocking_resource="/var/run/mirai",
        )
        self.assertEqual(first, second)

    def test_repair_required_result_needs_failure_fingerprint(self) -> None:
        contract = self.make_contract()
        with self.assertRaisesRegex(
            AttemptValidationError, "requires a failure fingerprint"
        ):
            AttemptResult(
                attempt_id=contract.attempt_id,
                contract_sha256=contract.contract_sha256,
                outcome=AttemptOutcome.REPAIR_REQUIRED,
                initial_stage=contract.initial_stage,
                final_stage=contract.initial_stage,
                progress=AttemptProgress(
                    goal_reached=False,
                    oracle_reason=None,
                    guest_events_total=4,
                ),
            )

    def test_attempt_store_links_result_to_exact_contract(self) -> None:
        contract = self.make_contract()
        result = AttemptResult(
            attempt_id=contract.attempt_id,
            contract_sha256=contract.contract_sha256,
            outcome=AttemptOutcome.EXITED,
            initial_stage=contract.initial_stage,
            final_stage=contract.initial_stage,
            progress=AttemptProgress(
                goal_reached=False,
                oracle_reason=None,
                guest_events_total=8,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = AttemptStore(Path(temporary) / "attempts")
            contract_path = store.save_contract(contract)
            result_path = store.save_result(result)
            loaded_contract, loaded_result = store.verify_attempt(
                contract.attempt_id,
                require_result=True,
            )

            self.assertEqual(loaded_contract, contract)
            self.assertEqual(loaded_result, result)
            self.assertEqual(contract_path.name, "contract.json")
            self.assertEqual(result_path.name, "result.json")

    def test_attempt_store_rejects_conflicting_contract(self) -> None:
        contract = self.make_contract()
        conflicting = replace(contract, goal_id="different-goal")
        with tempfile.TemporaryDirectory() as temporary:
            store = AttemptStore(Path(temporary) / "attempts")
            store.save_contract(contract)
            with self.assertRaisesRegex(AttemptValidationError, "immutable"):
                store.save_contract(conflicting)

    def test_attempt_store_rejects_result_for_another_contract_digest(self) -> None:
        contract = self.make_contract()
        result = AttemptResult(
            attempt_id=contract.attempt_id,
            contract_sha256="f" * 64,
            outcome=AttemptOutcome.EXITED,
            initial_stage=contract.initial_stage,
            final_stage=contract.initial_stage,
            progress=AttemptProgress(
                goal_reached=False,
                oracle_reason=None,
                guest_events_total=1,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = AttemptStore(Path(temporary) / "attempts")
            store.save_contract(contract)
            with self.assertRaisesRegex(
                AttemptValidationError,
                "does not match persisted contract",
            ):
                store.save_result(result)

    def test_attempt_store_rejects_symlinked_contract(self) -> None:
        contract = self.make_contract()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = AttemptStore(root / "attempts")
            contract_path = store.save_contract(contract)
            outside = root / "outside-contract.json"
            contract.save(outside)
            contract_path.unlink()
            contract_path.symlink_to(outside)

            with self.assertRaisesRegex(
                AttemptValidationError,
                "contract is invalid",
            ):
                store.load_contract(contract.attempt_id)


if __name__ == "__main__":
    unittest.main()
