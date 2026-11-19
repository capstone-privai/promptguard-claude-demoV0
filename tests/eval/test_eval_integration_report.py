"""scripts/eval_integration/report.py helpers on synthetic rows: shapes, character overlap, newly missed, tiers."""

from __future__ import annotations

import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "eval_integration"))

import report  # noqa: E402
from configs import BASELINE, CONFIGS, SETTINGS  # noqa: E402


class Configs(unittest.TestCase):
    def test_three_to_six_add_one_thing_to_two(self) -> None:
        off = CONFIGS["2-off"][1]
        for name, changed in (("3-filters", {"PG_DETECTOR_FILTERS"}), ("4-filters-dummy", {"PG_DETECTOR_FILTERS", "PG_DETECTOR_FILTER_DUMMY"}),
                              ("5-floor", {"PG_REMASK_SHORT", "PG_SHELL_POSITIONAL_MIN"}), ("6-hex", {"PG_RULE_HEX_KEY"})):
            env = CONFIGS[name][1]
            self.assertEqual({k for k in SETTINGS if env[k] != off[k]}, changed, name)
            self.assertEqual(BASELINE[name], "2-off")
        self.assertEqual({k for k in SETTINGS if CONFIGS["7-all"][1][k] == off[k]}, set())
        self.assertIsNone(CONFIGS["1-main"][1])


class Helpers(unittest.TestCase):
    def test_shape(self) -> None:
        self.assertEqual(report.shape("9f86d081884c7d65"), "16진수 16-31자")
        self.assertEqual(report.shape("q7Z"), "영숫자 <4자")
        self.assertEqual(report.shape("Synth.Pass9q"), "기호 포함 8-15자")
        self.assertEqual(report.shape("12345678"), "숫자 8-15자")

    def test_overlap_counts_characters(self) -> None:
        self.assertEqual(report.overlap(report.merge([(0, 10), (5, 12)]), report.merge([(8, 20)])), 4)
        self.assertEqual(report.overlap([(0, 3)], [(3, 6)]), 0)

    def run_rows(self, covered: set, rules_over: dict | None = None, removed: dict | None = None) -> dict:
        gold = [{"session_id": "s", "item_id": 1, "span_id": i, "start": i * 10, "end": i * 10 + 5, "type": "PASSWORD"} for i in range(3)]
        return {"gold": gold, "covered": covered, "rules_over": rules_over or {}, "removed": removed or {}, "value_of": lambda r: "SynthValue9q"}

    def test_newly_missed_names_the_rule_and_the_filter(self) -> None:
        base = self.run_rows({("s", 1, 0), ("s", 1, 1)}, rules_over={("s", 1, 0): {"promptguard-rules:secret-assignment"}})
        now = self.run_rows({("s", 1, 1)}, removed={("s", 1): [{"start": 0, "end": 5, "filter": "code_fragment"}]})
        self.assertEqual(report.newly_missed(base, now), Counter({("PASSWORD", "promptguard-rules:secret-assignment", "code_fragment", "영숫자 8-15자"): 1}))

    def test_tiers_and_solo_rules(self) -> None:
        high = {("credsweeper", "JSON Web Token")}
        finding = lambda adapter, rule, confidence, ids: {"session_id": "s", "item_id": 1, "adapter": adapter, "rule_id": rule,  # noqa: E731
                                                          "confidence": confidence, "overlaps_gold": bool(ids), "gold_span_ids": ids}
        run = {"findings": [finding("credsweeper", "JSON Web Token", "moderate", [0]), finding("promptguard-rules", "secret-assignment", "moderate", [0]),
                            finding("promptguard-rules", "secret-assignment", "moderate", [1]), finding("shell-aware", "function_argument", "ambiguous", [2]),
                            finding("promptguard-rules", "basic-auth", "strong", [3]), finding("shell-aware", "function_argument", "ambiguous", [])]}
        counts, solo = report.tiers(run, high)
        self.assertEqual(counts["바로 가림"], Counter({"TP": 2}))
        self.assertEqual(counts["애매함"], Counter({"TP": 3, "FP": 1}))
        self.assertEqual(solo, Counter({"promptguard-rules:secret-assignment": 1, "shell-aware:function_argument": 1}))


if __name__ == "__main__":
    unittest.main()
