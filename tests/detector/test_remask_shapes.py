"""scripts/remask_admission/shapes.py gives the shapes the Native Mod gives (tests/fixtures/remask_shapes.json).

The Mod side of the same fixture is tests/mod/test_remask_admission.mjs. Values are synthetic; messages print
only the expected shape and the length.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "remask_admission"))

import shapes  # noqa: E402


class RemaskShapes(unittest.TestCase):
    def test_fixture_cases(self) -> None:
        cases = json.loads((ROOT / "tests" / "fixtures" / "remask_shapes.json").read_text(encoding="utf-8"))["cases"]
        self.assertGreater(len(cases), 20)
        for value, expected in cases:
            with self.subTest(shape=expected, length=len(value)):
                self.assertEqual(shapes.value_shape(value), expected)

    def test_rule_list_and_matching(self) -> None:
        rules = shapes.high_confidence_rules()
        self.assertIn(("gitleaks", "private-key"), rules)
        self.assertNotIn(("credsweeper", "Password"), rules)
        self.assertTrue(shapes.is_high_confidence(rules, ["credsweeper", "gitleaks"], "Password+private-key"))
        self.assertFalse(shapes.is_high_confidence(rules, ["credsweeper"], "private-key"), "rule of another adapter")
        self.assertFalse(shapes.is_high_confidence(rules, ["promptguard-rules"], "secret-assignment"))


if __name__ == "__main__":
    unittest.main()
