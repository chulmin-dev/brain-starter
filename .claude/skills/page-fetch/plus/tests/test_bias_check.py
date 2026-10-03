"""P25 (2026-06-12) — bias_check plus/ scan + EXCLUDED_SUBPATHS tests.

Verifies:
  1. plus/ is now in SCAN_ROOTS_STRICT_OFF (bias_check scans it by default).
  2. plus/tests/ is excluded from scanning (EXCLUDED_SUBPATHS["plus"] = {"tests"}).
  3. EXCLUDED_SUBPATHS walk-filter correctly skips plus/tests/ subtrees.
  4. bias_check returns exit 0 (clean) on the real codebase after P25 annotations.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

import engine.bias_check as bc


class P25ScanRootsTest(unittest.TestCase):
    """plus/ must be in default scan roots (SCAN_ROOTS_STRICT_OFF)."""

    def test_plus_in_strict_off_roots(self):
        self.assertIn(
            "plus", bc.SCAN_ROOTS_STRICT_OFF,
            "P25: plus/ must be in SCAN_ROOTS_STRICT_OFF so bias_check covers it by default",
        )

    def test_engine_still_in_strict_off_roots(self):
        self.assertIn("engine", bc.SCAN_ROOTS_STRICT_OFF)

    def test_plus_in_strict_on_roots(self):
        self.assertIn("plus", bc.SCAN_ROOTS_STRICT_ON)


class P25ExcludedSubpathsTest(unittest.TestCase):
    """plus/tests/ must be in EXCLUDED_SUBPATHS so regression tests are skipped."""

    def test_plus_tests_excluded(self):
        excluded = bc.EXCLUDED_SUBPATHS.get("plus", set())
        self.assertIn(
            "tests", excluded,
            "P25: plus/tests/ must be excluded from plus/ scan (regression tests "
            "document brand names they guard against)",
        )

    def test_engine_tests_not_excluded(self):
        # engine/tests/ must remain in scope — it has no brand references.
        excluded = bc.EXCLUDED_SUBPATHS.get("engine", set())
        self.assertNotIn(
            "tests", excluded,
            "engine/tests/ must not be excluded — P25 only targets plus/tests/",
        )


class P25CleanScanTest(unittest.TestCase):
    """Running bias_check on the real codebase must exit 0 (clean) after P25."""

    def test_bias_check_clean(self):
        """The default scan (engine/ + plus/, excluding plus/tests/) must be clean.

        This is a live integration test — it runs the actual scanner against the
        real skill codebase, so it catches any new violation introduced after P25.
        """
        result = bc.main(["--root", str(_SKILL_ROOT)])
        self.assertEqual(
            result, 0,
            "bias_check must exit 0 (clean) after P25 NOTE-BIAS-OK annotations",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
