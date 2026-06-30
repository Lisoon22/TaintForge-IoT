from __future__ import annotations

import unittest

from taintforge_env.requirements import (
    BlockingAssessment,
    RequirementKind,
    RequirementReport,
    RequirementStatus,
    RequirementValidationError,
    make_requirement_id,
)


class RequirementReportLoadingTests(unittest.TestCase):
    def test_round_trip_from_dict(self) -> None:
        requirement_id = make_requirement_id(
            RequirementKind.FILESYSTEM,
            "path_exists",
            "/etc/device.conf",
        )
        raw = {
            "schema_version": 1,
            "generated_at_utc": "2026-06-30T00:00:00+00:00",
            "summary": {},
            "warnings": ["example warning"],
            "requirements": [
                {
                    "requirement_id": requirement_id,
                    "kind": "filesystem",
                    "resource": "/etc/device.conf",
                    "operation": "path_exists",
                    "status": "unmet",
                    "blocking": "likely",
                    "confidence": 1.0,
                    "repairable": True,
                    "errno": "ENOENT",
                    "evidence": [
                        {
                            "source": "syscall",
                            "summary": "openat failed with ENOENT",
                            "raw": "openat(...) = -1 ENOENT",
                            "event_index": 0,
                        }
                    ],
                    "details": {"syscall": "openat"},
                }
            ],
        }

        report = RequirementReport.from_dict(raw)
        requirement = report.requirements[0]

        self.assertEqual(requirement.kind, RequirementKind.FILESYSTEM)
        self.assertEqual(requirement.status, RequirementStatus.UNMET)
        self.assertEqual(requirement.blocking, BlockingAssessment.LIKELY)
        self.assertEqual(dict(requirement.details)["syscall"], "openat")
        self.assertEqual(report.warnings, ("example warning",))

    def test_unknown_schema_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            RequirementValidationError,
            "unsupported runtime requirements schema_version",
        ):
            RequirementReport.from_dict(
                {
                    "schema_version": 99,
                    "generated_at_utc": "2026-06-30T00:00:00+00:00",
                    "warnings": [],
                    "requirements": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
