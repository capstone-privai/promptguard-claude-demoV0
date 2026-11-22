"""scripts/eval_integration/report.py helpers on synthetic rows: shapes, character overlap, newly missed, tiers, the
re-mask-only count of configuration 8 and the re-mask false positives by catcher; and one report built from synthetic
run folders, which must hold no value."""

from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "eval_integration"))
sys.path.insert(0, str(ROOT / "src" / "detector"))

import instrument  # noqa: E402
import report  # noqa: E402
from configs import ALL_SETS, BASELINE, CONFIGS, NEEDS_VERIFIER, NEW_DEFAULTS, POLICY, REMASK, SETTINGS  # noqa: E402
from pgdetector import settings as detector_settings  # noqa: E402


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

    def test_two_to_seven_keep_the_re_mask_on(self) -> None:
        for name in ("2-off", "3-filters", "4-filters-dummy", "5-floor", "6-hex", "7-all"):
            self.assertEqual(CONFIGS[name][1][REMASK], "on", name)

    def test_eight_is_the_new_defaults_with_the_re_mask_off(self) -> None:
        env = CONFIGS["8-defaults-no-remask"][1]
        self.assertEqual(env, {**NEW_DEFAULTS, REMASK: "off", POLICY: "union"})
        self.assertEqual(set(env), set(SETTINGS) | {REMASK, POLICY}, "every setting given")
        for name, value in detector_settings.DEFAULTS.items():
            if name in NEW_DEFAULTS:
                self.assertEqual(NEW_DEFAULTS[name], value, name)
        self.assertEqual(BASELINE["8-defaults-no-remask"], "7-all")
        self.assertIn("8-defaults-no-remask", ALL_SETS)


    def test_nine_is_the_new_defaults_with_the_verifier(self) -> None:
        env = CONFIGS["9-defaults-verifier"][1]
        self.assertEqual(env, {**NEW_DEFAULTS, REMASK: "on", POLICY: "verifier"})
        self.assertEqual(BASELINE["9-defaults-verifier"], "7-all")
        self.assertIn("9-defaults-verifier", ALL_SETS)
        self.assertEqual(NEEDS_VERIFIER, ("9-defaults-verifier",))
        for name, (_, env, _) in CONFIGS.items():
            if name not in ("1-main", "9-defaults-verifier"):
                self.assertEqual(env[POLICY], "union", f"{name}: the default policy, set explicitly")


class Verifier(unittest.TestCase):
    TEXT = "pw=SynthKeptValue9q tok=SynthLeftValue7x"

    def module(self, scores: dict, error: Exception | None = None):
        text = self.TEXT

        class Stage:
            threshold = 0.5

            def score(self, *_args):
                if error:
                    raise error
                return []

        class PromptGuardAdapter:
            def __init__(self) -> None:
                self.detector = types.SimpleNamespace(verifier=Stage())
                self._filter_queue, self._filter_session = [7], "s"

            def _scan(self, scanned, source):
                failed = False
                try:
                    self.detector.verifier.score(scanned, source, [])
                except Exception:
                    failed = True
                candidates = []
                for value, score in scores.items():
                    start = text.index(value)
                    candidates.append({"strength": "ambiguous", "start": start, "end": start + len(value), "rule_id": "r", "detectors": ["d"],
                                       **({} if failed else {"verifier_score": score})})
                candidates.append({"strength": "strong", "start": 0, "end": 2})
                return {"candidates": candidates}

        return types.SimpleNamespace(PromptGuardAdapter=PromptGuardAdapter)

    def test_the_recorder_keeps_spans_scores_and_failures_only(self) -> None:
        rows: list = []
        module = self.module({"SynthKeptValue9q": 0.9, "SynthLeftValue7x": 0.1})
        instrument.install_verifier_recorder(module, rows)
        module.PromptGuardAdapter()._scan(self.TEXT, "tool_output")
        (row,) = rows
        self.assertEqual((row["session_id"], row["item_id"], row["timeout"], row["failure"]), ("s", 7, False, False))
        self.assertEqual([(c["score"], c["masked"]) for c in row["ambiguous"]], [(0.9, True), (0.1, False)])
        self.assertNotIn("SynthKeptValue9q", json.dumps(rows))

    def test_a_timeout_is_fail_closed(self) -> None:
        rows: list = []
        module = self.module({"SynthKeptValue9q": 0.9}, RuntimeError("verifier timed out"))
        instrument.install_verifier_recorder(module, rows)
        module.PromptGuardAdapter()._scan(self.TEXT, "tool_output")
        self.assertEqual((rows[0]["timeout"], rows[0]["failure"], rows[0]["ambiguous"][0]["masked"]), (True, True, True))

    def test_stats(self) -> None:
        left = self.TEXT.index("SynthLeftValue7x")
        run = {"gold": [{"session_id": "s", "item_id": 7, "span_id": 0, "start": left, "end": left + 16}], "covered": set(),
               "verifier": [{"session_id": "s", "item_id": 7, "timeout": False, "failure": False,
                             "ambiguous": [{"start": 3, "end": 19, "masked": True}, {"start": left, "end": left + 16, "masked": False}]},
                            {"session_id": "s", "item_id": 8, "timeout": True, "failure": True, "ambiguous": [{"start": 0, "end": 4, "masked": True}]}]}
        self.assertEqual(report.verifier_stats(run), Counter({"items": 2, "masked": 2, "left": 1, "left_gold": 1, "timeout": 1, "fail_closed": 1}))


class NoRemask(unittest.TestCase):
    def test_the_session_still_fills_its_map_and_does_not_re_mask(self) -> None:
        class ModSession:
            def __init__(self) -> None:
                self.reverse = {}

            def _remask(self, text, out, edits):
                return out.replace("SynthValue9q", "[X_1]"), edits + ["remask"]

        module = types.SimpleNamespace(ModSession=ModSession)
        instrument.install_no_remask(module)
        session = module.ModSession()
        session.reverse["SynthValue9q"] = "[X_1]"
        self.assertEqual(session._remask("t", "a SynthValue9q", ["detector"]), ("a SynthValue9q", ["detector"]))
        self.assertEqual(session.reverse, {"SynthValue9q": "[X_1]"})


class RemaskOnly(unittest.TestCase):
    def test_covered_by_seven_and_not_by_eight(self) -> None:
        gold = [{"session_id": "s", "item_id": 1, "span_id": i, "start": i, "end": i + 1} for i in range(4)]
        values = ["SynthA9q", "SynthA9q", "SynthB9q", "SynthC9q"]
        seven = {"gold": gold, "covered": {("s", 1, 0), ("s", 1, 1), ("s", 1, 2)}, "value_of": lambda r: values[r["span_id"]]}
        eight = {"gold": gold, "covered": {("s", 1, 2), ("s", 1, 3)}}
        self.assertEqual(report.remask_only(seven, eight), (2, 1))


class RemaskByCatcher(unittest.TestCase):
    def test_the_first_finding_of_the_value_names_the_catcher(self) -> None:
        texts = {("s", 1): "pw=SynthA9q", ("s", 2): "x SynthA9q", ("s", 3): "y SynthA9q SynthB9q", ("t", 1): "z SynthB9q"}

        def finding(session: str, item: int, start: int, end: int, adapter: str, rule: str) -> dict:
            return {"session_id": session, "item_id": item, "start": start, "end": end, "adapter": adapter, "rule_id": rule}

        def edit(session: str, item: int, start: int, end: int) -> dict:
            return {"session_id": session, "item_id": item, "start": start, "end": end}

        run = {
            "value_of": lambda r: texts[(r["session_id"], r["item_id"])][r["start"]:r["end"]],
            # the value's first finding (item 1) is by two rules at the same place; a later one (item 3) does not count
            "all_findings": [finding("s", 1, 3, 11, "promptguard-rules", "secret-assignment"), finding("s", 1, 3, 11, "credsweeper", "Password"),
                             finding("s", 3, 2, 10, "shell-aware", "function_argument")],
            # the second value has no finding in its session t
            "remask_fp_edits": [edit("s", 2, 2, 10), edit("s", 3, 2, 10), edit("t", 1, 2, 10)],
        }
        distinct, spans, values = report.remask_fp_by_catcher(run)
        both = "credsweeper:Password, promptguard-rules:secret-assignment"
        self.assertEqual(distinct, 2)
        self.assertEqual(spans, Counter({both: 2, report.NO_CATCHER: 1}))
        self.assertEqual(values, Counter({both: 1, report.NO_CATCHER: 1}))


class BuildFromSyntheticRuns(unittest.TestCase):
    """report.build over synthetic run folders of 7 and 8: the new column and table, and no value in the report."""

    SECRET = "SynthGold9qValue"
    NOISE = "SynthNoise7x"

    @staticmethod
    def rows(items: list[dict]) -> str:
        return "".join(json.dumps(item) + "\n" for item in items)

    def write_run(self, out: Path, config: str, sessions: Path, edits: list[dict], spans: list[dict], first: str) -> None:
        run = out / config / "cred" / "run1"
        run.mkdir(parents=True)
        (run / "run_meta.json").write_text(json.dumps({"dataset": {"sessions_path": str(sessions)}}), encoding="utf-8")
        (run / "metrics.json").write_text(json.dumps({"fp_per_1k_lines": 0.0}), encoding="utf-8")
        (run / "eval_config.json").write_text(json.dumps({"config": config}), encoding="utf-8")
        (run / "per_span.jsonl").write_text(self.rows(spans), encoding="utf-8")
        (run / "per_edit.jsonl").write_text(self.rows(edits), encoding="utf-8")
        found = {"session_id": "s", "item_id": 0, "start": 3, "end": 3 + len(self.SECRET), "valid": True, "scored": True, "adapter": "promptguard-rules",
                 "rule_id": "secret-assignment", "confidence": "moderate", "overlaps_gold": True, "gold_span_ids": [0]}
        noise = {**found, "start": first.index(self.NOISE), "end": len(first), "rule_id": "hex-key", "overlaps_gold": False, "gold_span_ids": []}
        (run / "per_finding.jsonl").write_text(self.rows([found, noise]), encoding="utf-8")
        (run / "filters.jsonl").write_text(self.rows([{"session_id": "s", "item_id": 0, "filtered": {}, "removed": []}]), encoding="utf-8")

    def test_report(self) -> None:
        first, later = f"pw={self.SECRET} k={self.NOISE}", f"echo {self.SECRET} {self.NOISE}"

        def gold(status: str) -> list[dict]:
            return [{"session_id": "s", "item_id": 0, "span_id": 0, "start": 3, "end": 3 + len(self.SECRET), "scored": True, "status": "exact", "type": "PASSWORD"},
                    {"session_id": "s", "item_id": 1, "span_id": 1, "start": 5, "end": 5 + len(self.SECRET), "scored": True, "status": status, "type": "PASSWORD"}]

        def edit(item: int, start: int, end: int, overlaps_gold: bool) -> dict:
            return {"session_id": "s", "item_id": item, "start": start, "end": end, "scored": True, "overlaps_gold": overlaps_gold}

        detector_edits = [edit(0, 3, 3 + len(self.SECRET), True), edit(0, first.index(self.NOISE), len(first), False)]
        remask_edits = [edit(1, 5, 5 + len(self.SECRET), True), edit(1, later.index(self.NOISE), len(later), False)]
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            sessions = out / "sessions_from_cred.jsonl"
            sessions.write_text(json.dumps({"session_id": "s", "items": [{"item_id": 0, "text": first}, {"item_id": 1, "text": later}]}) + "\n", encoding="utf-8")
            self.write_run(out, "7-all", sessions, detector_edits + remask_edits, gold("exact"), first)
            self.write_run(out, "8-defaults-no-remask", sessions, detector_edits, gold("missed"), first)
            manifest = {"creddata": "cred", "nine": [], "traffic": [], "configs": ["7-all", "8-defaults-no-remask"]}
            (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            text = report.build(out, out, ROOT).read_text(encoding="utf-8")
        self.assertNotIn(self.SECRET, text)
        self.assertNotIn(self.NOISE, text)
        row = next(line for line in text.splitlines() if line.startswith("| 8-defaults-no-remask"))
        self.assertTrue(row.rstrip().endswith("| 1 / 1 |"), "re-mask only: one span, one value")
        self.assertIn("재마스킹 오탐 1개, 고유 값 1개", text)
        self.assertIn("| promptguard-rules:hex-key | 1 | 1 |", text)


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
