"""ml-v9 / ml-qwen adapters, run against fake models (no torch, no weights).

The fakes copy the shapes of privai_model's MLSpanDetector.scan_text and
QwenSecretScanner.scan as of promptguard-model e17cb39. Values are synthetic.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import AdapterUnavailable, ConsensusPolicy, Detector, DetectorAdapter, RawFinding, load_detector  # noqa: E402
from pgdetector.adapters.span_models import MLV9Adapter, QwenAdapter  # noqa: E402

SECRET = "SyntheticModelKey_77Q"


class FakeV9:
    def __init__(self, checkpoint, device="cpu", spans=(), fail=False, delay=0.0):
        self.spans, self.fail, self.delay, self.calls = list(spans), fail, delay, 0

    def scan_text(self, text, threshold=None):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("ML span inference failed; caller must fail closed")
        out = []
        for value, score in self.spans:
            start = text.find(value)
            if start >= 0:
                out.append({"start": start, "end": start + len(value), "secret_type": "SECRET", "detector": "ml", "score": score})
        return out


@dataclass
class Finding:
    start: int
    end: int
    score: float


@dataclass
class Result:
    status: str
    findings: list = field(default_factory=list)
    error: str | None = None


class FakeTokenLength:
    def prompt_length(self, text):
        return len(text)  # one "token" per character keeps the limit easy to reason about


class FakeQwen:
    def __init__(self, bundle, values=(), error=None, limit=4096, **kwargs):
        self.values, self.error, self.max_input_tokens = list(values), error, limit
        self.detector = FakeTokenLength()
        self.calls, self.kwargs = [], kwargs

    def scan(self, text):
        self.calls.append(len(text))
        if self.error:
            return Result("error", [], self.error)
        if len(text) > self.max_input_tokens:
            return Result("error", [], "input_too_long")
        found = []
        for value in self.values:
            start = text.find(value)
            if start >= 0:
                found.append(Finding(start, start + len(value), 0.99))
        return Result("ok", found)


class Empty(DetectorAdapter):
    version = "test"

    def scan(self, text):
        return []


class SpanModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "promptguard-model"
        (self.repo / "src").mkdir(parents=True)
        self.options = {"repository": str(self.repo)}

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def v9(self, **fake):
        return MLV9Adapter("ml-v9", self.options, ROOT, factory=lambda checkpoint, device: FakeV9(checkpoint, device, **fake))

    def qwen(self, options=None, **fake):
        return QwenAdapter("ml-qwen", {**self.options, **(options or {})}, ROOT, factory=lambda bundle, **kw: FakeQwen(bundle, **fake, **kw))

    # v9
    def test_v9_returns_code_point_spans(self) -> None:
        text = f"로그 🔑 deploy key {SECRET} ok"
        rows = self.v9(spans=[(SECRET, 0.9999)]).scan(text)
        self.assertEqual([(text[r.start:r.end], r.family, r.confidence) for r in rows], [(SECRET, "ml_v9", "strong")])
        self.assertNotIn(SECRET, repr(rows[0].evidence))

    def test_v9_failure_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            self.v9(fail=True).scan(f"key {SECRET}")

    def test_v9_timeout_raises(self) -> None:
        adapter = MLV9Adapter("ml-v9", {**self.options, "timeout_seconds": 0.05}, ROOT, factory=lambda c, device: FakeV9(c, device, delay=0.5))
        with self.assertRaises(RuntimeError):
            adapter.scan(f"key {SECRET}")

    # Qwen
    def test_qwen_error_status_fails_closed(self) -> None:
        for error in ("invalid_json", "truncated", "inference_failed"):
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                self.qwen(error=error).scan(f"token {SECRET}")

    def test_qwen_long_text_is_chunked_with_correct_offsets(self) -> None:
        lines = [f"line {i:03d} ordinary log output\n" for i in range(60)]
        lines[47] = f"line 047 auth token {SECRET}\n"
        text = "".join(lines)
        adapter = self.qwen(values=[SECRET], limit=300)
        rows = adapter.scan(text)
        self.assertEqual([text[r.start:r.end] for r in rows], [SECRET])
        self.assertTrue(all(size <= 300 for size in adapter.model.calls))
        self.assertGreater(len(adapter.model.calls), 1)

    def test_qwen_overlap_does_not_duplicate(self) -> None:
        lines = [f"row {i:02d} token value\n" for i in range(30)]
        lines[10] = f"row 10 token {SECRET}\n"
        text = "".join(lines)
        rows = self.qwen({"overlap_lines": 3, "max_chunks": 30}, values=[SECRET], limit=120).scan(text)
        self.assertEqual(len(rows), 1)

    def test_qwen_too_many_chunks_or_long_line_fails_closed(self) -> None:
        many = "".join(f"token line {i:03d} padding padding\n" for i in range(200))
        with self.assertRaises(RuntimeError):
            self.qwen({"max_chunks": 2}, limit=200).scan(many)
        with self.assertRaises(RuntimeError):
            self.qwen(limit=50).scan("token " + "x" * 400)

    def test_qwen_cue_gate_skips_model(self) -> None:
        adapter = self.qwen({"gate": "cue"}, values=[SECRET])
        self.assertEqual(adapter.scan(f"hello world {SECRET}"), [])
        self.assertEqual(adapter.model.calls, [])
        self.assertEqual(len(adapter.scan(f"비밀번호는 {SECRET}")), 1)

    def test_qwen_passes_device_and_threshold(self) -> None:
        adapter = self.qwen({"device": "cpu", "threshold": 0.5})
        self.assertEqual(adapter.model.kwargs, {"device": "cpu", "local_files_only": False, "threshold": 0.5})

    # Availability and topology
    def test_missing_repository_or_weights_is_unavailable(self) -> None:
        with self.assertRaises(AdapterUnavailable):
            MLV9Adapter("ml-v9", {"repository": str(self.repo / "nope")}, ROOT)
        with self.assertRaises(AdapterUnavailable):
            MLV9Adapter("ml-v9", self.options, ROOT)
        with self.assertRaises(AdapterUnavailable):
            QwenAdapter("ml-qwen", self.options, ROOT)

    def test_union_masks_model_only_value_and_failure_blocks(self) -> None:
        text = f"debug: auth {SECRET}"
        detector = Detector([Empty("credsweeper", {}, ROOT), self.v9(spans=[(SECRET, 0.9999)])], ConsensusPolicy.parse("majority"),
                            candidate_only=["ml-v9"], candidate_policy="union")
        result = detector.scan(text, "unit")
        self.assertTrue(result["ok"])
        self.assertEqual(["ml-v9"], result["findings"][0]["detectors"])
        broken = Detector([Empty("credsweeper", {}, ROOT), self.v9(fail=True)], ConsensusPolicy.parse("majority"),
                          candidate_only=["ml-v9"], candidate_policy="union")
        self.assertIn("ADAPTER_FAILURE:ml-v9", broken.scan(text, "unit")["errors"])

    def test_env_enable_and_disable(self) -> None:
        config = Path(self.tmp.name) / "detector.json"
        config.write_text(json.dumps({"consensus": "any", "candidate_policy": "union", "adapters": [
            {"name": "shell-aware", "type": "shell-aware"},
            {"name": "ml-v9", "type": "ml-v9", "enabled": False, "required": False, "candidate_only": True,
             "options": {"repository": str(self.repo)}},
        ]}), encoding="utf-8")
        self.assertEqual([], load_detector(config).skipped, "disabled entry is not even tried")
        with mock.patch.dict(os.environ, {"PG_DETECTOR_ENABLE": "ml-v9"}):
            detector = load_detector(config)
        self.assertEqual(["ml-v9"], [row["name"] for row in detector.skipped], "enabled, then skipped: no weights here")
        with mock.patch.dict(os.environ, {"PG_DETECTOR_ENABLE": "ml-v9", "PG_DETECTOR_DISABLE": "ml-v9,shell-aware"}):
            with self.assertRaises(ValueError):
                load_detector(config)  # nothing left to vote: the policy refuses an empty ensemble

    def test_shipped_config_lists_models_disabled(self) -> None:
        config = json.loads((ROOT / "src" / "detector" / "detector.json").read_text(encoding="utf-8"))
        entries = {entry["name"]: entry for entry in config["adapters"]}
        for name in ("ml-v9", "ml-qwen"):
            self.assertFalse(entries[name]["enabled"])
            self.assertFalse(entries[name]["required"])
            self.assertTrue(entries[name]["candidate_only"])


if __name__ == "__main__":
    unittest.main()
