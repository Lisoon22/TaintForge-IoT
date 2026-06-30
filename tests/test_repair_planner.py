from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.repair_plan import (
    RepairActionKind,
    RepairDisposition,
    RepairPriority,
)
from taintforge_env.repair_planner import RepairPlanner, RepairPlanningError
from taintforge_env.requirements import (
    BlockingAssessment,
    RequirementKind,
    RequirementReport,
    RequirementStatus,
    RuntimeRequirement,
    make_requirement_id,
)


class RepairPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = RepairPlanner()

    def test_missing_directory_is_only_automatic_candidate(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/var/run/mirai",
            operation="directory_exists",
            status=RequirementStatus.UNMET,
            blocking=BlockingAssessment.LIKELY,
            confidence=1.0,
            repairable=True,
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(decision.action, RepairActionKind.CREATE_DIRECTORY)
        self.assertEqual(
            decision.disposition,
            RepairDisposition.AUTO_CANDIDATE,
        )
        self.assertEqual(decision.priority, RepairPriority.CRITICAL)
        self.assertTrue(decision.automatic_allowed)
        self.assertEqual(dict(decision.parameters)["mode"], "0755")
        self.assertTrue(dict(decision.parameters)["parents"])

    def test_missing_file_never_becomes_empty_file_automatic_repair(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/etc/device.conf",
            operation="path_exists",
            status=RequirementStatus.UNMET,
            repairable=True,
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(decision.action, RepairActionKind.PROVIDE_FILE)
        self.assertEqual(
            decision.disposition,
            RepairDisposition.REVIEW_REQUIRED,
        )
        self.assertFalse(decision.automatic_allowed)
        self.assertFalse(dict(decision.parameters)["create_empty"])

    def test_provided_requirement_produces_no_repair(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/var/run/malware.pid",
            operation="path_writable",
            status=RequirementStatus.PROVIDED,
            repairable=True,
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(decision.action, RepairActionKind.NONE)
        self.assertEqual(
            decision.disposition,
            RepairDisposition.NOT_REQUIRED,
        )
        self.assertFalse(decision.automatic_allowed)

    def test_fatal_signal_requires_manual_analysis(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.EXECUTION,
            resource="SIGSEGV",
            operation="avoid_fatal_signal",
            status=RequirementStatus.UNMET,
            blocking=BlockingAssessment.LIKELY,
            repairable=False,
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(decision.action, RepairActionKind.NONE)
        self.assertEqual(
            decision.disposition,
            RepairDisposition.MANUAL_ANALYSIS,
        )
        self.assertEqual(decision.priority, RepairPriority.CRITICAL)

    def test_unknown_tcp_endpoint_requires_protocol_review(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.NETWORK,
            resource="tcp://91.200.10.5:5555",
            operation="connect",
            status=RequirementStatus.UNKNOWN,
            repairable=True,
            details={"listener_type": "catch_all_transparent"},
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(
            decision.action,
            RepairActionKind.CONFIGURE_TCP_SERVICE,
        )
        self.assertEqual(
            decision.disposition,
            RepairDisposition.REVIEW_REQUIRED,
        )
        self.assertFalse(decision.automatic_allowed)
        parameters = dict(decision.parameters)
        self.assertEqual(parameters["remote_ip"], "91.200.10.5")
        self.assertEqual(parameters["remote_port"], 5555)

    def test_transport_response_without_semantic_confirmation_still_needs_review(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.NETWORK,
            resource="tcp://91.200.10.5:5555",
            operation="connect",
            status=RequirementStatus.PROVIDED,
            repairable=True,
            details={
                "response_observed": "true",
                "semantic_satisfaction": "unknown",
            },
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(
            decision.action,
            RepairActionKind.CONFIGURE_TCP_SERVICE,
        )
        self.assertEqual(
            decision.disposition,
            RepairDisposition.REVIEW_REQUIRED,
        )
        self.assertFalse(decision.automatic_allowed)

    def test_pseudo_filesystem_directory_is_not_automatic(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/proc/device-tree",
            operation="directory_exists",
            status=RequirementStatus.UNMET,
            repairable=True,
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(decision.action, RepairActionKind.CREATE_DIRECTORY)
        self.assertEqual(
            decision.disposition,
            RepairDisposition.MANUAL_ANALYSIS,
        )
        self.assertFalse(decision.automatic_allowed)

    def test_low_confidence_directory_is_downgraded_to_review(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/var/lib/malware",
            operation="directory_exists",
            status=RequirementStatus.UNMET,
            confidence=0.70,
            repairable=True,
        )

        decision = self.only_decision(self.plan(requirement))

        self.assertEqual(
            decision.disposition,
            RepairDisposition.REVIEW_REQUIRED,
        )
        self.assertFalse(decision.automatic_allowed)

    def test_decision_ids_and_order_are_deterministic(self) -> None:
        first = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/tmp/a",
            operation="directory_exists",
            status=RequirementStatus.UNMET,
            blocking=BlockingAssessment.UNKNOWN,
            repairable=True,
        )
        second = self.requirement(
            kind=RequirementKind.LIBRARY,
            resource="libc.so.6",
            operation="library_available",
            status=RequirementStatus.UNMET,
            blocking=BlockingAssessment.LIKELY,
            repairable=True,
        )

        plan_a = self.plan(first, second)
        plan_b = self.plan(second, first)

        self.assertEqual(
            [item.decision_id for item in plan_a.decisions],
            [item.decision_id for item in plan_b.decisions],
        )
        self.assertEqual(
            [item.resource for item in plan_a.decisions],
            ["libc.so.6", "/tmp/a"],
        )

    def test_plan_file_writes_hash_and_rejects_tampered_requirement_id(self) -> None:
        requirement = self.requirement(
            kind=RequirementKind.FILESYSTEM,
            resource="/var/run/test",
            operation="directory_exists",
            status=RequirementStatus.UNMET,
            repairable=True,
        )
        report = RequirementReport(requirements=(requirement,))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            requirements_path = tmp_path / "runtime_requirements.json"
            plan_path = tmp_path / "repair_plan.json"
            report.save(requirements_path)

            plan = self.planner.plan_file(requirements_path, plan_path)
            saved = json.loads(plan_path.read_text(encoding="utf-8"))

            self.assertEqual(len(plan.source_sha256), 64)
            self.assertEqual(saved["source_sha256"], plan.source_sha256)
            self.assertEqual(saved["summary"]["automatic_candidates"], 1)

            raw = json.loads(requirements_path.read_text(encoding="utf-8"))
            raw["requirements"][0]["requirement_id"] = "req_tampered"
            requirements_path.write_text(
                json.dumps(raw),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                RepairPlanningError,
                "requirement_id mismatch",
            ):
                self.planner.plan_file(requirements_path, plan_path)

    def plan(self, *requirements: RuntimeRequirement):
        report = RequirementReport(requirements=tuple(requirements))
        return self.planner.plan(
            report,
            source_requirements="runtime_requirements.json",
            source_sha256="0" * 64,
        )

    @staticmethod
    def requirement(
        *,
        kind: RequirementKind,
        resource: str,
        operation: str,
        status: RequirementStatus,
        blocking: BlockingAssessment = BlockingAssessment.UNKNOWN,
        confidence: float = 1.0,
        repairable: bool,
        details: dict[str, str] | None = None,
    ) -> RuntimeRequirement:
        return RuntimeRequirement(
            requirement_id=make_requirement_id(kind, operation, resource),
            kind=kind,
            resource=resource,
            operation=operation,
            status=status,
            blocking=blocking,
            confidence=confidence,
            repairable=repairable,
            details=tuple(sorted((details or {}).items())),
        )

    @staticmethod
    def only_decision(plan):
        if len(plan.decisions) != 1:
            raise AssertionError(
                f"expected one decision, got {len(plan.decisions)}"
            )
        return plan.decisions[0]


if __name__ == "__main__":
    unittest.main()
