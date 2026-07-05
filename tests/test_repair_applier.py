from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from taintforge_env.repair_applier import (
    RepairApplicationError,
    RepairApplicationState,
    RepairApplier,
    RepairResultStatus,
)
from taintforge_env.repair_plan import (
    RepairActionKind,
    RepairDecision,
    RepairDisposition,
    RepairPlan,
    RepairPriority,
    RepairRisk,
    make_decision_id,
)


class RepairApplierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.applier = RepairApplier()

    def test_applies_authorized_directory_repair(self) -> None:
        with self.workspace() as ws:
            plan_path = self.write_plan(
                ws,
                self.auto_directory("/var/run/mirai"),
            )
            report = self.apply(ws, plan_path)

            target = ws["rootfs"] / "var" / "run" / "mirai"
            self.assertTrue(target.is_dir())
            self.assertEqual(report.state, RepairApplicationState.COMPLETED)
            self.assertEqual(report.summary()["applied_total"], 1)
            self.assertEqual(
                report.results[0].status,
                RepairResultStatus.APPLIED,
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o755)

    def test_reapplication_is_idempotent(self) -> None:
        with self.workspace() as ws:
            plan_path = self.write_plan(
                ws,
                self.auto_directory("/var/run/mirai"),
            )
            self.apply(ws, plan_path)
            report = self.apply(ws, plan_path)

            self.assertEqual(report.summary()["applied_total"], 0)
            self.assertEqual(
                report.summary()["already_satisfied_total"],
                1,
            )

    def test_dry_run_does_not_mutate_rootfs(self) -> None:
        with self.workspace() as ws:
            plan_path = self.write_plan(
                ws,
                self.auto_directory("/opt/malware/state"),
            )
            report = self.apply(ws, plan_path, dry_run=True)

            self.assertEqual(report.state, RepairApplicationState.DRY_RUN)
            self.assertFalse((ws["rootfs"] / "opt").exists())
            self.assertEqual(
                report.results[0].status,
                RepairResultStatus.PLANNED,
            )

    def test_requirements_hash_mismatch_is_rejected_before_mutation(self) -> None:
        with self.workspace() as ws:
            plan_path = self.write_plan(
                ws,
                self.auto_directory("/var/run/mirai"),
            )
            ws["requirements"].write_text("tampered\n", encoding="utf-8")

            with self.assertRaisesRegex(
                RepairApplicationError,
                "SHA-256 does not match",
            ):
                self.apply(ws, plan_path)

            self.assertFalse((ws["rootfs"] / "var").exists())

    def test_review_required_decision_is_not_applied(self) -> None:
        with self.workspace() as ws:
            decision = self.decision(
                resource="/etc/device.conf",
                action=RepairActionKind.PROVIDE_FILE,
                disposition=RepairDisposition.REVIEW_REQUIRED,
                automatic_allowed=False,
                parameters=(("create_empty", False),),
            )
            plan_path = self.write_plan(ws, decision)
            report = self.apply(ws, plan_path)

            self.assertEqual(
                report.results[0].status,
                RepairResultStatus.NOT_SELECTED,
            )
            self.assertFalse((ws["rootfs"] / "etc").exists())

    def test_symbolic_link_ancestor_is_rejected(self) -> None:
        with self.workspace() as ws:
            outside = ws["base"] / "outside"
            outside.mkdir()
            os.symlink(outside, ws["rootfs"] / "var")

            plan_path = self.write_plan(
                ws,
                self.auto_directory("/var/run/mirai"),
            )

            with self.assertRaisesRegex(
                RepairApplicationError,
                "crosses a symbolic link",
            ):
                self.apply(ws, plan_path)

            self.assertFalse((outside / "run").exists())
            failure = json.loads(ws["out"].read_text(encoding="utf-8"))
            self.assertEqual(failure["state"], "failed")

    def test_non_directory_ancestor_is_rejected(self) -> None:
        with self.workspace() as ws:
            (ws["rootfs"] / "var").write_text("not a dir", encoding="utf-8")
            plan_path = self.write_plan(
                ws,
                self.auto_directory("/var/run/mirai"),
            )

            with self.assertRaisesRegex(
                RepairApplicationError,
                "ancestor is not a directory",
            ):
                self.apply(ws, plan_path)

    def test_pseudo_filesystem_path_is_rejected_even_if_plan_is_tampered(self) -> None:
        with self.workspace() as ws:
            plan_path = self.write_plan(
                ws,
                self.auto_directory("/proc/device-tree"),
            )

            with self.assertRaisesRegex(
                RepairApplicationError,
                "pseudo-filesystem semantics",
            ):
                self.apply(ws, plan_path)

    def test_unsupported_automatic_action_fails_closed(self) -> None:
        with self.workspace() as ws:
            decision = self.decision(
                resource="/etc/device.conf",
                action=RepairActionKind.PROVIDE_FILE,
                disposition=RepairDisposition.AUTO_CANDIDATE,
                automatic_allowed=True,
                parameters=(("create_empty", True),),
            )
            plan_path = self.write_plan(ws, decision)

            with self.assertRaisesRegex(
                RepairApplicationError,
                "automatic action provide_file is not enabled",
            ):
                self.apply(ws, plan_path)

            self.assertFalse((ws["rootfs"] / "etc").exists())

    def apply(
        self,
        ws: dict[str, Path],
        plan_path: Path,
        *,
        dry_run: bool = False,
    ):
        return self.applier.apply_file(
            plan_path=plan_path,
            requirements_path=ws["requirements"],
            rootfs=ws["rootfs"],
            out_path=ws["out"],
            dry_run=dry_run,
        )

    def write_plan(
        self,
        ws: dict[str, Path],
        *decisions: RepairDecision,
    ) -> Path:
        source_hash = hashlib.sha256(
            ws["requirements"].read_bytes()
        ).hexdigest()
        plan = RepairPlan(
            source_requirements=str(ws["requirements"]),
            source_sha256=source_hash,
            decisions=tuple(decisions),
        )
        plan_path = ws["base"] / "repair_plan.json"
        plan.save(plan_path)
        return plan_path

    def auto_directory(self, resource: str) -> RepairDecision:
        return self.decision(
            resource=resource,
            action=RepairActionKind.CREATE_DIRECTORY,
            disposition=RepairDisposition.AUTO_CANDIDATE,
            automatic_allowed=True,
            parameters=(("mode", "0755"), ("parents", True)),
        )

    @staticmethod
    def decision(
        *,
        resource: str,
        action: RepairActionKind,
        disposition: RepairDisposition,
        automatic_allowed: bool,
        parameters: tuple[tuple[str, object], ...],
    ) -> RepairDecision:
        requirement_id = "req_" + hashlib.sha256(
            resource.encode("utf-8")
        ).hexdigest()[:16]
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
            automatic_allowed=automatic_allowed,
            reason="test decision",
            parameters=parameters,
        )

    class workspace:
        def __init__(self, outer: RepairApplierTests | None = None):
            self.temp = tempfile.TemporaryDirectory()

        def __enter__(self) -> dict[str, Path]:
            base = Path(self.temp.__enter__())
            rootfs = base / "rootfs"
            rootfs.mkdir()
            requirements = base / "runtime_requirements.json"
            requirements.write_text(
                '{"schema_version":1,"requirements":[]}\n',
                encoding="utf-8",
            )
            return {
                "base": base,
                "rootfs": rootfs,
                "requirements": requirements,
                "out": base / "repair_application.json",
            }

        def __exit__(self, exc_type, exc, tb):
            return self.temp.__exit__(exc_type, exc, tb)


if __name__ == "__main__":
    unittest.main()
