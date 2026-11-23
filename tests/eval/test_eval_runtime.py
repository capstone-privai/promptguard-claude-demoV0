"""scripts/eval_integration/runtime.py: the on-prem env file, and the settings a run records (names, never paths)."""

from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "eval_integration"))

import instrument  # noqa: E402
import report  # noqa: E402
import runtime  # noqa: E402


class EnvFile(unittest.TestCase):
    def test_reads_keys_and_values_and_skips_comments(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "p.env"
            path.write_text("# comment\n\nPG_ML_DEVICE=cuda\n  PG_ML_TIMEOUT_SECONDS = 60 \n# PG_DETECTOR_ENABLE=ml-span\nexport PG_VERIFIER_DEVICE=cuda\n", encoding="utf-8")
            self.assertEqual(runtime.read_env_file(path), {"PG_ML_DEVICE": "cuda", "PG_ML_TIMEOUT_SECONDS": "60", "PG_VERIFIER_DEVICE": "cuda"})

    def test_an_unfilled_placeholder_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "p.env"
            path.write_text("PG_ML_CHECKPOINT=models/<bundle folder>\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                runtime.read_env_file(path)
            self.assertIn("PG_ML_CHECKPOINT", str(caught.exception))

    def test_the_shipped_profile_has_placeholders_to_fill(self) -> None:
        with self.assertRaises(ValueError):
            runtime.read_env_file(ROOT / "src" / "detector" / "profiles" / "onprem.env")


class Recorded(unittest.TestCase):
    def test_overrides_keep_values_and_only_the_name_of_a_path(self) -> None:
        environ = {"PG_ML_DEVICE": "cuda", "PG_ML_TIMEOUT_SECONDS": "60", "PG_ML_CHECKPOINT": "/srv/private/models/span-onprem-qwen",
                   "PG_VERIFIER_BUNDLE": r"D:\private\verifier\bundle-onprem", "PG_VERIFIER_DEVICE": "cuda", "HOME": "/home/u"}
        recorded = runtime.recorded_overrides(environ)
        self.assertEqual(recorded, {"PG_ML_DEVICE": "cuda", "PG_ML_TIMEOUT_SECONDS": "60", "PG_ML_CHECKPOINT": "span-onprem-qwen",
                                    "PG_VERIFIER_BUNDLE": "bundle-onprem", "PG_VERIFIER_DEVICE": "cuda"})
        self.assertNotIn("private", json.dumps(recorded))

    def test_the_recorder_keeps_the_scorer_adapter(self) -> None:
        class PromptGuardAdapter:
            def __init__(self, value: int) -> None:
                self.detector = types.SimpleNamespace(describe=lambda: {"candidate_policy": "union", "runtime_settings": {"adapters": {}, "verifier": None}, "adapters": [{"name": "a", "version": "1"}]})

        module = types.SimpleNamespace(PromptGuardAdapter=PromptGuardAdapter)
        holder: list = []
        instrument.install_runtime_recorder(module, holder)
        module.PromptGuardAdapter(1)
        self.assertEqual(runtime.runtime_record(holder), {"candidate_policy": "union", "adapters": ["a"], "runtime_settings": {"adapters": {}, "verifier": None}})
        self.assertIsNone(runtime.runtime_record([]))


class ReportSection(unittest.TestCase):
    def test_lines(self) -> None:
        record = {"overrides": {"PG_ML_DEVICE": "cuda"}, "runtime": {"candidate_policy": "verifier", "adapters": ["credsweeper", "ml-span"],
                  "runtime_settings": {"adapters": {"ml-span": {"device": "cuda", "timeout_seconds": 60.0, "checkpoint": "span-onprem"}},
                                       "verifier": {"device": "cuda", "timeout_seconds": 60.0, "bundle": "verifier-onprem"}}}}
        lines = report.runtime_lines({"9-defaults-verifier": record})
        text = "\n".join(lines)
        self.assertIn("| 9-defaults-verifier | verifier | ml-span: cuda, 60.0초, span-onprem | cuda, 60.0초, verifier-onprem | PG_ML_DEVICE=cuda |", text)


if __name__ == "__main__":
    unittest.main()
