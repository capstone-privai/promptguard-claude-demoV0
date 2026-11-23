"""On-prem measurement overrides (feat/onprem-profile): PG_ML_DEVICE, PG_ML_CHECKPOINT, PG_VERIFIER_DEVICE and
PG_ML_TIMEOUT_SECONDS change ml-span, ml-v9 and the verifier without editing detector.json, and the product defaults
(cpu, 4 seconds) stay as they are. Fake models only (no torch, no weights).
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector  # noqa: E402
from pgdetector.adapters.span_models import MLSpanAdapter, MLV9Adapter  # noqa: E402
from pgdetector.verifier import VerifierStage  # noqa: E402

OVERRIDES = ("PG_ML_DEVICE", "PG_ML_CHECKPOINT", "PG_VERIFIER_DEVICE", "PG_ML_TIMEOUT_SECONDS", "PG_VERIFIER_BUNDLE", "PG_ML_SCOPE")
CONFIG = json.loads((ROOT / "src" / "detector" / "detector.json").read_text(encoding="utf-8"))
ENTRY = {entry["name"]: entry["options"] for entry in CONFIG["adapters"]}


class Seen:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def span(self, checkpoint, device="cpu"):
        self.calls.append({"checkpoint": Path(checkpoint), "device": device})
        return type("Model", (), {"scan_text": lambda self, text, threshold=None: []})()

    def verifier(self, bundle, device="cpu", recall_target=None, context_lines=3):
        self.calls.append({"bundle": Path(bundle), "device": device})
        return type("Model", (), {"threshold": 0.5, "model_version": "fake", "score": lambda self, *a: []})()


class OnpremOverrides(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "promptguard-model"
        (self.repo / "src").mkdir(parents=True)
        self.clean = mock.patch.dict(os.environ, {})
        self.clean.start()
        for name in OVERRIDES:
            os.environ.pop(name, None)

    def tearDown(self) -> None:
        self.clean.stop()
        self.tmp.cleanup()

    def span(self, cls=MLSpanAdapter, name="ml-span", env=None):
        seen = Seen()
        options = {**ENTRY[name], "repository": str(self.repo)}
        with mock.patch.dict(os.environ, env or {}):
            adapter = cls(name, options, ROOT, factory=seen.span)
        return adapter, seen.calls[0]

    def verifier(self, env=None):
        seen = Seen()
        with mock.patch.dict(os.environ, env or {}):
            stage = VerifierStage({**CONFIG["verifier"], "repository": str(self.repo)}, ROOT / "src" / "detector", factory=seen.verifier)
        return stage, seen.calls[0]

    def test_product_defaults_are_unchanged(self) -> None:
        for name in ("ml-span", "ml-v9"):
            self.assertEqual((ENTRY[name]["device"], ENTRY[name]["timeout_seconds"]), ("cpu", 4), name)
        self.assertEqual((CONFIG["verifier"]["device"], CONFIG["verifier"]["timeout_seconds"]), ("cpu", 4))
        adapter, call = self.span()
        self.assertEqual((call["device"], adapter.timeout), ("cpu", 4.0))
        stage, call = self.verifier()
        self.assertEqual((call["device"], stage.timeout), ("cpu", 4.0))

    def test_ml_device_for_ml_span_and_ml_v9(self) -> None:
        for cls, name in ((MLSpanAdapter, "ml-span"), (MLV9Adapter, "ml-v9")):
            _, call = self.span(cls, name, {"PG_ML_DEVICE": "cuda"})
            self.assertEqual(call["device"], "cuda", name)
        _, call = self.verifier({"PG_ML_DEVICE": "cuda"})
        self.assertEqual(call["device"], "cpu", "PG_ML_DEVICE is the span models'; the verifier has its own")

    def test_verifier_device(self) -> None:
        _, call = self.verifier({"PG_VERIFIER_DEVICE": "cuda"})
        self.assertEqual(call["device"], "cuda")
        _, call = self.span(env={"PG_VERIFIER_DEVICE": "cuda"})
        self.assertEqual(call["device"], "cpu")

    def test_ml_timeout_covers_ml_span_ml_v9_and_the_verifier(self) -> None:
        env = {"PG_ML_TIMEOUT_SECONDS": "60"}
        for cls, name in ((MLSpanAdapter, "ml-span"), (MLV9Adapter, "ml-v9")):
            self.assertEqual(self.span(cls, name, env)[0].timeout, 60.0, name)
            self.assertEqual(self.span(cls, name, {**env, "PG_ML_SCOPE": "full"})[0].timeout, 60.0, f"{name} scope full")
        self.assertEqual(self.verifier(env)[0].timeout, 60.0)

    def test_ml_checkpoint_picks_the_ml_span_bundle(self) -> None:
        _, call = self.span(env={"PG_ML_CHECKPOINT": "models/span-onprem-qwen"})
        self.assertEqual(call["checkpoint"], (self.repo / "models" / "span-onprem-qwen").resolve())
        absolute = Path(self.tmp.name) / "elsewhere" / "bundle"
        _, call = self.span(env={"PG_ML_CHECKPOINT": str(absolute)})
        self.assertEqual(call["checkpoint"], absolute)
        _, call = self.span(MLV9Adapter, "ml-v9", {"PG_ML_CHECKPOINT": "models/span-onprem-qwen"})
        self.assertEqual(call["checkpoint"].name, "span-detector-v9", "ml-v9 stays pinned to v9")

    def test_runtime_settings_name_the_bundle_never_its_path(self) -> None:
        seen = Seen()
        env = {"PG_ML_DEVICE": "cuda", "PG_ML_TIMEOUT_SECONDS": "60", "PG_ML_CHECKPOINT": str(Path(self.tmp.name) / "private" / "span-onprem"),
               "PG_VERIFIER_DEVICE": "cuda", "PG_VERIFIER_BUNDLE": str(Path(self.tmp.name) / "private" / "verifier-onprem")}
        with mock.patch.dict(os.environ, env):
            adapter = MLSpanAdapter("ml-span", {**ENTRY["ml-span"], "repository": str(self.repo)}, ROOT, factory=seen.span)
            stage = VerifierStage({**CONFIG["verifier"], "repository": str(self.repo)}, ROOT, factory=seen.verifier)
            detector = Detector([adapter], ConsensusPolicy.parse("any"), candidate_policy="verifier", verifier=stage)
        runtime = detector.describe()["runtime_settings"]
        self.assertEqual(runtime["adapters"]["ml-span"], {"device": "cuda", "timeout_seconds": 60.0, "checkpoint": "span-onprem"})
        self.assertEqual(runtime["verifier"], {"device": "cuda", "timeout_seconds": 60.0, "bundle": "verifier-onprem"})
        self.assertNotIn(self.tmp.name, json.dumps(runtime))


class ProfileFile(unittest.TestCase):
    PATH = ROOT / "src" / "detector" / "profiles" / "onprem.env"

    def test_values_and_note(self) -> None:
        text = self.PATH.read_text(encoding="utf-8")
        values = dict(re.findall(r"^(PG_[A-Z_]+)=(.*)$", text, re.M))
        self.assertEqual(values["PG_ML_DEVICE"], "cuda")
        self.assertEqual(values["PG_VERIFIER_DEVICE"], "cuda")
        self.assertEqual(values["PG_ML_TIMEOUT_SECONDS"], "60")
        self.assertIn("PG_ML_CHECKPOINT", values)
        self.assertIn("PG_VERIFIER_BUNDLE", values)
        self.assertIn("지표 1 오프라인 채점용", text)
        self.assertIn("브리지 5초", text)
        self.assertIn("훅 10초", text)


if __name__ == "__main__":
    unittest.main()
