from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class MakefileStaticAnalysisTests(unittest.TestCase):
    def test_analyze_static_requires_sample(self) -> None:
        result = subprocess.run(
            ["make", "--no-print-directory", "analyze-static"],
            cwd=PROJECT_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("usage: make analyze-static SAMPLE=", result.stderr)

    def test_analyze_static_dry_run_forwards_configuration(self) -> None:
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "--just-print",
                "analyze-static",
                "SAMPLE=/tmp/reviewer-sample",
                "ANALYZE_OUT=workdir/reviewer-sample",
                "ANALYZE_NETWORK=none",
                "ANALYZE_ARGS=--phase2-timeout 90",
            ],
            cwd=PROJECT_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            'scripts/run_static_pipeline.py "/tmp/reviewer-sample"',
            result.stdout,
        )
        self.assertIn('--out "workdir/reviewer-sample"', result.stdout)
        self.assertIn('--network "none"', result.stdout)
        self.assertIn("--phase2-timeout 90", result.stdout)


if __name__ == "__main__":
    unittest.main()
