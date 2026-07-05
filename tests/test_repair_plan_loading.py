from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from taintforge_env.repair_plan import (
    RepairActionKind,
    RepairDecision,
    RepairDisposition,
    RepairPlan,
    RepairPlanValidationError,
    RepairPriority,
    RepairRisk,
    make_decision_id,
)


class RepairPlanLoadingTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        decision = self.decision()
        plan = RepairPlan(
            source_requirements="runtime_requirements.json",
            source_sha256="a" * 64,
            decisions=(decision,),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "repair_plan.json"
            plan.save(path)
            loaded = RepairPlan.load(path)

        self.assertEqual(loaded.source_sha256, "a" * 64)
        self.assertEqual(loaded.decisions, (decision,))

    def test_tampered_decision_id_is_rejected(self) -> None:
        decision = self.decision()
        plan = RepairPlan(
            source_requirements="runtime_requirements.json",
            source_sha256="b" * 64,
            decisions=(decision,),
        )
        raw = plan.to_dict()
        raw["decisions"][0]["decision_id"] = "repair_tampered"

        with self.assertRaisesRegex(
            RepairPlanValidationError,
            "decision_id mismatch",
        ):
            RepairPlan.from_dict(raw)

    def test_invalid_automatic_disposition_is_rejected(self) -> None:
        decision = self.decision()
        raw = RepairPlan(
            source_requirements="runtime_requirements.json",
            source_sha256="c" * 64,
            decisions=(decision,),
        ).to_dict()
        raw["decisions"][0]["disposition"] = "review_required"
        raw["decisions"][0]["decision_id"] = make_decision_id(
            decision.requirement_id,
            decision.action,
            RepairDisposition.REVIEW_REQUIRED,
            decision.resource,
        )

        with self.assertRaisesRegex(
            RepairPlanValidationError,
            "automatic_allowed requires",
        ):
            RepairPlan.from_dict(raw)

    @staticmethod
    def decision() -> RepairDecision:
        requirement_id = "req_0123456789abcdef"
        action = RepairActionKind.CREATE_DIRECTORY
        disposition = RepairDisposition.AUTO_CANDIDATE
        resource = "/var/run/mirai"
        return RepairDecision(
            decision_id=make_decision_id(
                requirement_id,
                action,
                disposition,
                resource,
            ),
            requirement_id=requirement_id,
            requirement_kind="filesystem",
            resource=resource,
            operation="directory_exists",
            action=action,
            disposition=disposition,
            priority=RepairPriority.CRITICAL,
            risk=RepairRisk.LOW,
            automatic_allowed=True,
            reason="test",
            parameters=(("mode", "0755"), ("parents", True)),
        )


if __name__ == "__main__":
    unittest.main()
