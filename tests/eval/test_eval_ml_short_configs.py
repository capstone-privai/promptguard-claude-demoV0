"""The six ml-span cells of the integration measurement: ML on x {drop, strong, keep} x {union, verifier}
(PG_ML_SHORT_VALUES). They are asked for by name and leave the nine as they were."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "eval_integration"))
sys.path.insert(0, str(ROOT / "src" / "detector"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import report  # noqa: E402
import runtime  # noqa: E402
import test_eval_integration_report as existing  # noqa: E402
import configs  # noqa: E402
from configs import ALL_SETS, ALL_SETTINGS, BASELINE, CONFIGS, NEEDS_VERIFIER, NEW_DEFAULTS, POLICY, REMASK  # noqa: E402

NINE = ("1-main", "2-off", "3-filters", "4-filters-dummy", "5-floor", "6-hex", "7-all", "8-defaults-no-remask", "9-defaults-verifier")
# name: (PG_ML_SHORT_VALUES, policy, newly missed is counted against)
CELLS = {
    "10-ml-drop": ("drop", "union", "7-all"),
    "11-ml-strong": ("strong", "union", "10-ml-drop"),
    "12-ml-keep": ("keep", "union", "10-ml-drop"),
    "13-ml-drop-verifier": ("drop", "verifier", "10-ml-drop"),
    "14-ml-strong-verifier": ("strong", "verifier", "13-ml-drop-verifier"),
    "15-ml-keep-verifier": ("keep", "verifier", "13-ml-drop-verifier"),
}


class MLShortCells(unittest.TestCase):
    def test_six_cells_on_the_new_defaults_with_ml_span_on(self) -> None:
        self.assertEqual(tuple(CONFIGS), NINE + tuple(CELLS))
        for name, (mode, policy, baseline) in CELLS.items():
            system, env, label = CONFIGS[name]
            self.assertEqual(system, "branch", name)
            self.assertEqual(env, {**NEW_DEFAULTS, REMASK: "on", POLICY: policy, "PG_DETECTOR_ENABLE": "ml-span", "PG_ML_SHORT_VALUES": mode}, name)
            self.assertEqual(BASELINE[name], baseline, name)
            self.assertIn("ml-span", label)
            self.assertIn(mode, label)

    def test_they_are_asked_for_by_name(self) -> None:
        self.assertEqual(configs.ML_CONFIGS, tuple(CELLS))
        self.assertEqual(configs.DEFAULT_CONFIGS, NINE, "a run without --configs is the nine, which need no model weights")
        self.assertFalse(set(CELLS) & set(ALL_SETS), "ML cells run on CredData-trajectory and the traffic sets")

    def test_the_verifier_cells_need_the_bundle(self) -> None:
        self.assertEqual(NEEDS_VERIFIER, ("9-defaults-verifier", "13-ml-drop-verifier", "14-ml-strong-verifier", "15-ml-keep-verifier"))
        for name, (_, env, _) in CONFIGS.items():
            if env is not None:
                self.assertEqual(env[POLICY] == "verifier", name in NEEDS_VERIFIER, name)

    def test_the_shell_cannot_set_it_for_another_configuration(self) -> None:
        # scorer_child removes ALL_SETTINGS before it applies a configuration's own.
        self.assertIn("PG_ML_SHORT_VALUES", ALL_SETTINGS)
        # An --env-file may turn a model on for the nine (on-prem scoring) and names the bundle the ML cells run
        # (PG_ML_CHECKPOINT), so the enable list and the checkpoint are left to the shell.
        self.assertNotIn("PG_DETECTOR_ENABLE", ALL_SETTINGS)
        self.assertNotIn("PG_ML_CHECKPOINT", ALL_SETTINGS)

    def test_a_run_records_it(self) -> None:
        environ = {"PG_ML_SHORT_VALUES": "keep", "PG_DETECTOR_ENABLE": "ml-span"}
        self.assertEqual(runtime.recorded_overrides(environ), environ)


class Report(unittest.TestCase):
    def test_the_cells_are_rows_and_strong_is_counted_against_drop(self) -> None:
        helper = existing.BuildFromSyntheticRuns("test_report")
        secret, noise = helper.SECRET, helper.NOISE
        first, later = f"pw={secret} k={noise}", f"echo {secret} {noise}"

        def gold(status: str) -> list[dict]:
            return [{"session_id": "s", "item_id": 0, "span_id": 0, "start": 3, "end": 3 + len(secret), "scored": True, "status": "exact", "type": "PASSWORD"},
                    {"session_id": "s", "item_id": 1, "span_id": 1, "start": 5, "end": 5 + len(secret), "scored": True, "status": status, "type": "PASSWORD"}]

        def edit(item: int, start: int, end: int) -> dict:
            return {"session_id": "s", "item_id": item, "start": start, "end": end, "scored": True, "overlaps_gold": True}

        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            sessions = out / "sessions_from_cred.jsonl"
            sessions.write_text(json.dumps({"session_id": "s", "items": [{"item_id": 0, "text": first}, {"item_id": 1, "text": later}]}) + "\n", encoding="utf-8")
            both = [edit(0, 3, 3 + len(secret)), edit(1, 5, 5 + len(secret))]
            helper.write_run(out, "10-ml-drop", sessions, both, gold("exact"), first)
            helper.write_run(out, "11-ml-strong", sessions, both[:1], gold("missed"), first)
            (out / "manifest.json").write_text(json.dumps({"creddata": "cred", "nine": [], "traffic": [], "configs": ["10-ml-drop", "11-ml-strong"]}), encoding="utf-8")
            text = report.build(out, out, ROOT).read_text(encoding="utf-8")
        self.assertNotIn(secret, text)
        self.assertNotIn(noise, text)
        self.assertIn(f"| 10-ml-drop ({CONFIGS['10-ml-drop'][2]}) |", text)
        self.assertIn(f"| 11-ml-strong ({CONFIGS['11-ml-strong'][2]}) |", text)
        self.assertRegex(text, r"(?m)^\| 11-ml-strong \| 10-ml-drop \| PASSWORD \|", "newly missed under strong, against drop")


if __name__ == "__main__":
    unittest.main()
