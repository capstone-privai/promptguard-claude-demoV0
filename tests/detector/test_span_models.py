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
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import AdapterUnavailable, ConsensusPolicy, Detector, DetectorAdapter, RawFinding, load_detector  # noqa: E402
from pgdetector.adapters.span_models import MLSpanAdapter, MLV9Adapter, QwenAdapter  # noqa: E402

SECRET = "SyntheticModelKey_77Q"


class FakeV9:
    def __init__(self, checkpoint, device="cpu", spans=(), fail=False, delay=0.0):
        self.spans, self.fail, self.delay, self.calls = list(spans), fail, delay, 0
        self.read = []  # the texts the model was given

    def scan_text(self, text, threshold=None):
        self.calls += 1
        self.read.append(text)
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

    def test_short_and_plain_word_spans_are_dropped(self) -> None:
        # ml-v9 flagged "of" and "by" in a live demo session.
        text = f"the token of the account is set by {SECRET} today"
        rows = self.v9(spans=[("of", 0.9999), ("by", 0.9999), ("today", 0.99), (SECRET, 0.9999)]).scan(text)
        self.assertEqual([text[r.start:r.end] for r in rows], [SECRET])
        loose = MLV9Adapter("ml-v9", {**self.options, "min_value_length": 2}, ROOT,
                            factory=lambda c, device: FakeV9(c, device, spans=[("ok", 0.99), ("of", 0.99)]))
        self.assertEqual([text2[r.start:r.end] for text2 in ["ok of"] for r in loose.scan(text2)], ["ok"])

    # v9 on long text: cue windows. The model reads text in time linear to its length (on CPU about 0.4 s per
    # 2 KB, 4 s per 20 KB, past the 4 s timeout), so long text is cut down to the lines near a credential cue.
    def v9_windows(self, **options):
        merged = {**self.options, "long_text": "cue_windows", "whole_text_chars": 2000, "window_lines": 2, "max_text_chars": 6000, "too_long": "skip", **options}
        return MLV9Adapter("ml-v9", merged, ROOT, factory=lambda c, device: FakeV9(c, device, spans=[(SECRET, 0.9999)]))

    @staticmethod
    def long_log(lines=300, secret_at=None, cue_at=None, secret_line=None):
        rows = [f"{i:04d} worker heartbeat ok, queue depth 3, latency 12ms\n" for i in range(lines)]
        if cue_at is not None:
            rows[cue_at] = f"{cue_at:04d} loaded the deploy password from vault\n"
        if secret_at is not None:
            rows[secret_at] = secret_line or f"{secret_at:04d} DB_PASSWORD={SECRET}\n"
        return "".join(rows)

    def test_v9_short_text_is_read_whole(self) -> None:
        adapter = self.v9_windows()
        text = f"the new one is {SECRET} so update the deploy"  # no cue word, short: still read
        self.assertEqual([text[r.start:r.end] for r in adapter.scan(text)], [SECRET])
        self.assertEqual(adapter.model.read, [text])

    def test_v9_long_text_reads_only_the_lines_around_a_cue(self) -> None:
        adapter = self.v9_windows()
        text = self.long_log(secret_at=200)
        self.assertGreater(len(text), 2000)
        rows = adapter.scan(text)
        self.assertEqual([text[r.start:r.end] for r in rows], [SECRET])
        self.assertEqual(len(adapter.model.read), 1)
        self.assertEqual(adapter.model.read[0].count("\n"), 5)  # the cue line and two either side

    def test_v9_window_covers_a_value_next_to_the_cue_line(self) -> None:
        adapter = self.v9_windows()
        text = self.long_log(cue_at=100, secret_at=102, secret_line=f"0102 {SECRET}\n")
        self.assertEqual([text[r.start:r.end] for r in adapter.scan(text)], [SECRET])
        far = self.long_log(cue_at=100, secret_at=110, secret_line=f"0110 {SECRET}\n")
        self.assertEqual(self.v9_windows().scan(far), [])

    def test_v9_long_text_without_a_cue_is_left_to_the_others(self) -> None:
        adapter = self.v9_windows()
        self.assertEqual(adapter.scan(self.long_log()), [])
        self.assertEqual(adapter.model.read, [])

    def test_v9_windows_over_the_limit_skip_or_fail(self) -> None:
        text = "".join(f"{i:04d} token rotated ok\n" for i in range(800))  # every line has a cue
        skip = self.v9_windows()
        self.assertEqual(skip.scan(text), [])
        self.assertEqual(skip.model.read, [])
        with self.assertRaises(RuntimeError):
            self.v9_windows(too_long="fail").scan(text)

    def test_v9_whole_mode_is_unchanged(self) -> None:
        adapter = self.v9(spans=[(SECRET, 0.9999)])
        text = self.long_log(secret_at=200)
        self.assertEqual([text[r.start:r.end] for r in adapter.scan(text)], [SECRET])
        self.assertEqual(adapter.model.read, [text])
        with self.assertRaises(ValueError):
            MLV9Adapter("ml-v9", {**self.options, "long_text": "sometimes"}, ROOT, factory=lambda c, device: FakeV9(c, device))

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

    def test_qwen_too_long_can_skip_instead_of_failing(self) -> None:
        many = "".join(f"token line {i:03d} padding padding\n" for i in range(200))
        adapter = self.qwen({"max_chunks": 2, "too_long": "skip"}, values=[SECRET], limit=200)
        self.assertEqual(adapter.scan(many), [])
        self.assertEqual(self.qwen({"too_long": "skip"}, limit=50).scan("token " + "x" * 400), [])
        with self.assertRaises(ValueError):
            self.qwen({"too_long": "maybe"})

    def test_max_text_chars_leaves_long_texts_to_the_others(self) -> None:
        adapter = self.qwen({"max_text_chars": 100}, values=[SECRET])
        self.assertEqual(adapter.scan(f"token {SECRET} " + "x" * 200), [])
        self.assertEqual(adapter.model.calls, [])
        self.assertEqual(len(adapter.scan(f"token {SECRET}")), 1)

    def test_timeout_override_from_environment(self) -> None:
        with mock.patch.dict(os.environ, {"PG_ML_TIMEOUT_SECONDS": "30"}):
            self.assertEqual(self.v9().timeout, 30.0)
        self.assertEqual(self.v9().timeout, None)

    def test_qwen_cue_gate_skips_model(self) -> None:
        adapter = self.qwen({"gate": "cue"}, values=[SECRET])
        self.assertEqual(adapter.scan(f"hello world {SECRET}"), [])
        self.assertEqual(adapter.model.calls, [])
        self.assertEqual(len(adapter.scan(f"비밀번호는 {SECRET}")), 1)

    def test_cue_gate_word_boundaries(self) -> None:
        from pgdetector.adapters.span_models import CUE
        for text in ("48 tests passed", "bypass the cache", "compass heading", "authoring notes", "tokenizer warmup done"):
            with self.subTest(text=text):
                self.assertIsNone(CUE.search(text))
        for text in ("password=", "DB_PASSWORD", "api_key:", "Authorization: Bearer", "getApiToken(", "auth token is", "비밀번호는", "client secrets"):
            with self.subTest(text=text):
                self.assertIsNotNone(CUE.search(text))

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
            with self.assertRaises(AdapterUnavailable):
                load_detector(config)  # asked for by name and it cannot run: do not start without it
        entries = json.loads(config.read_text(encoding="utf-8"))
        entries["adapters"][1]["enabled"] = True
        config.write_text(json.dumps(entries), encoding="utf-8")
        detector = load_detector(config)
        self.assertEqual(["ml-v9"], [row["name"] for row in detector.skipped], "on in the file, then skipped: no weights here")
        entries["adapters"][1]["enabled"] = False
        config.write_text(json.dumps(entries), encoding="utf-8")
        with mock.patch.dict(os.environ, {"PG_DETECTOR_ENABLE": "ml-v9", "PG_DETECTOR_DISABLE": "ml-v9,shell-aware"}):
            with self.assertRaises(ValueError):
                load_detector(config)  # nothing left to vote: the policy refuses an empty ensemble

    def test_shipped_config_lists_models_disabled(self) -> None:
        config = json.loads((ROOT / "src" / "detector" / "detector.json").read_text(encoding="utf-8"))
        entries = {entry["name"]: entry for entry in config["adapters"]}
        for name in ("ml-span", "ml-v9", "ml-qwen"):
            self.assertFalse(entries[name]["enabled"])
            self.assertFalse(entries[name]["required"])
            self.assertTrue(entries[name]["candidate_only"])
        self.assertEqual("models/span-detector-v9", entries["ml-v9"]["options"]["checkpoint"], "a result labelled v9 is v9")
        self.assertEqual("default", entries["ml-span"]["options"]["checkpoint"])
        self.assertEqual(entries["ml-span"]["options"].keys() - {"checkpoint", "fallback_checkpoint"},
                         entries["ml-v9"]["options"].keys() - {"checkpoint"}, "the two differ only in which bundle")

    # Which model runs, and saying so
    def bundle(self, name, file="span_bundle.json"):
        folder = self.repo / "models" / name
        folder.mkdir(parents=True)
        (folder / file).write_text(json.dumps({"revision": "abc32620dd4f6ab06f5f"}), encoding="utf-8")
        return folder

    def test_the_model_id_names_the_folder_that_was_loaded(self) -> None:
        self.bundle("span-detector-v10")
        self.bundle("qwen-span-v2", "qwen_bundle.json")
        v10 = MLV9Adapter("ml-v9", {**self.options, "checkpoint": "models/span-detector-v10"}, ROOT, factory=lambda c, device: FakeV9(c, device))
        self.assertEqual("span-detector-v10:abc32620dd4f", v10.version)
        self.assertEqual("qwen-span-v2:abc32620dd4f", self.qwen({"bundle": "models/qwen-span-v2"}).version)

    def loaded(self, options):
        seen = []
        MLV9Adapter("ml-v9", {**self.options, **options}, ROOT, factory=lambda c, device: seen.append(c) or FakeV9(c, device))
        return seen[0]

    def test_default_follows_the_bundle_the_model_repository_names(self) -> None:
        runtime = types.ModuleType("privai_model.ml_span.runtime")
        runtime.DEFAULT_BUNDLE = self.repo / "models" / "span-detector-v12"
        with mock.patch.dict(sys.modules, {"privai_model.ml_span.runtime": runtime}):
            self.assertEqual("span-detector-v12", self.loaded({"checkpoint": "default"}).name)

    def test_default_uses_the_fallback_until_the_repository_names_one(self) -> None:
        runtime = types.ModuleType("privai_model.ml_span.runtime")
        with mock.patch.dict(sys.modules, {"privai_model.ml_span.runtime": runtime}):
            self.assertEqual("span-detector-v10", self.loaded({"checkpoint": "default", "fallback_checkpoint": "models/span-detector-v10"}).name)

    def span(self, options=None):
        seen = []
        adapter = MLSpanAdapter("ml-span", {**self.options, **(options or {})}, ROOT, factory=lambda c, device: seen.append(c) or FakeV9(c, device, spans=[(SECRET, 0.9999)]))
        return adapter, seen[0]

    def test_ml_v9_is_v9_with_no_checkpoint_set(self) -> None:
        runtime = types.ModuleType("privai_model.ml_span.runtime")
        runtime.DEFAULT_BUNDLE = self.repo / "models" / "span-detector-v12"
        with mock.patch.dict(sys.modules, {"privai_model.ml_span.runtime": runtime}):
            self.assertEqual("span-detector-v9", self.loaded({}).name)

    def test_ml_span_follows_the_default_and_falls_back_to_v10(self) -> None:
        runtime = types.ModuleType("privai_model.ml_span.runtime")
        with mock.patch.dict(sys.modules, {"privai_model.ml_span.runtime": runtime}):
            self.assertEqual("span-detector-v10", self.span()[1].name)
            runtime.DEFAULT_BUNDLE = self.repo / "models" / "span-detector-v12"
            self.assertEqual("span-detector-v12", self.span()[1].name)

    def test_ml_span_findings_are_not_labelled_v9(self) -> None:
        with mock.patch.dict(sys.modules, {"privai_model.ml_span.runtime": types.ModuleType("privai_model.ml_span.runtime")}):
            row = self.span()[0].scan(f"key {SECRET}")[0]
        self.assertEqual(("ml_span", "ml_span-span"), (row.family, row.rule_id))

    def test_a_named_checkpoint_is_used_as_it_is(self) -> None:
        self.assertEqual("span-detector-v9", self.loaded({"checkpoint": "models/span-detector-v9"}).name)

    def test_qwen_default_follows_the_wrapper_constant(self) -> None:
        wrapper = types.ModuleType("privai_model.qwen_span.wrapper")
        wrapper.DEFAULT_BUNDLE = self.repo / "models" / "qwen-span-v9"
        with mock.patch.dict(sys.modules, {"privai_model.qwen_span.wrapper": wrapper}):
            adapter = self.qwen({"bundle": "default"})
        self.assertEqual("qwen-span-v9", adapter.version)

    # A call that timed out keeps running: it cannot be stopped, and the model is used by one thread at a time.
    def staged(self, *delays, timeout=0.2):
        fake = FakeV9("c", "cpu")
        queue = list(delays)
        real = fake.scan_text

        def scan_text(text, threshold=None):
            fake.delay = queue.pop(0) if queue else 0
            return real(text, threshold=threshold)

        fake.scan_text = scan_text
        return MLV9Adapter("ml-v9", {**self.options, "timeout_seconds": timeout}, ROOT, factory=lambda c, device: fake), fake

    def test_a_timed_out_call_does_not_fail_the_next_one(self) -> None:
        # The second call waits 0.1 s for the first and runs for 0.15 s: over 0.2 s in all, within it for its own work.
        adapter, _ = self.staged(0.3, 0.15)
        with self.assertRaises(RuntimeError):
            adapter.scan(f"key {SECRET}")
        self.assertEqual([], adapter.scan(f"key {SECRET}"))

    def test_a_call_that_gives_up_waiting_never_runs(self) -> None:
        adapter, fake = self.staged(0.8, 0, timeout=0.05)
        for _ in range(2):
            with self.assertRaises(RuntimeError):
                adapter.scan(f"key {SECRET}")
        time.sleep(0.9)
        self.assertEqual(1, fake.calls, "the call that gave up in the queue was cancelled")
        self.assertEqual([], adapter.scan(f"key {SECRET}"))


if __name__ == "__main__":
    unittest.main()
