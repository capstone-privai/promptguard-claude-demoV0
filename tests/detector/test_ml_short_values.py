"""PG_ML_SHORT_VALUES (strong|keep|drop): what happens to a model span shorter than min_value_length (6).

strong (the default) keeps a short span only when its score reaches the adapter's strong_threshold, and reports it
strong; keep never drops for length and lets the score decide strong or ambiguous; drop is the behaviour before the
setting (every short span dropped). Ordinary words (PROSE_WORDS) are dropped in all three, and a value of six characters
or more is not touched by any of them. Fake models only (no torch, no weights); values are synthetic and short on
purpose.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_span_models as existing  # noqa: E402
from pgdetector import AdapterUnavailable, ConsensusPolicy, Detector, load_detector, settings  # noqa: E402
from pgdetector.adapters.span_models import MLSpanAdapter, MLV9Adapter, QwenAdapter  # noqa: E402
from pgdetector.verifier import VerifierStage  # noqa: E402

SHORT = "mgb"
TEXT = f'password = "{SHORT}"\n'
ONE = "Q"
ONE_TEXT = f"pin: {ONE}\n"
LONG = "SyntheticModelKey_77Q"
MODES = ("strong", "keep", "drop")
NAME = "PG_ML_SHORT_VALUES"
STRIP = "\"'`.,;:()[]{}"
SURE, UNSURE = 0.995, 0.95  # either side of strong_threshold (0.99)


class RuntimeLike:
    """MLSpanDetector's length guard (promptguard-model 8409923 and 51f7407): the caller's min_value_length wins over
    the bundle's (span_bundle.json), None means the bundle's, and a span shorter than it never leaves the model."""

    def __init__(self, checkpoint, device="cpu", *, min_value_length=None, spans=()):
        meta = json.loads((Path(checkpoint) / "span_bundle.json").read_text(encoding="utf-8"))
        self.given = min_value_length
        self.min_value_length = meta.get("min_value_length") if min_value_length is None else min_value_length
        self.spans = list(spans)

    def scan_text(self, text, threshold=None):
        rows = []
        for value, score in self.spans:
            start = text.find(value)
            if start >= 0 and (self.min_value_length is None or len(value.strip().strip(STRIP)) >= self.min_value_length):
                rows.append({"start": start, "end": start + len(value), "secret_type": "SECRET", "detector": "ml", "score": score})
        return rows


class VerifierModel:
    """Stands in for CandidateVerifier: one score for every candidate, and a record of what it was given."""

    threshold = 0.5
    model_version = "fake-v0"

    def __init__(self, bundle, device="cpu", recall_target=None, context_lines=3, answer=0.9) -> None:
        self.answer, self.given = answer, []

    def score(self, text, source, candidates):
        self.given.extend(dict(candidate) for candidate in candidates)
        return [self.answer for _ in candidates]


def mode(value: str):
    return mock.patch.dict(os.environ, {NAME: value})


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "promptguard-model"
        (self.repo / "src").mkdir(parents=True)
        clean = mock.patch.dict(os.environ, {})
        clean.start()
        self.addCleanup(clean.stop)
        os.environ.pop(NAME, None)

    def adapter(self, spans, cls=MLSpanAdapter, name="ml-span", **options):
        return cls(name, {"repository": str(self.repo), **options}, ROOT, factory=lambda c, device: existing.FakeV9(c, device, spans=spans))

    def rows(self, adapter, text=TEXT):
        return [(text[row.start:row.end], row.confidence) for row in adapter.scan(text)]

    def under(self, value, spans, text=TEXT, **options):
        with mode(value):
            return self.rows(self.adapter(spans, **options), text)

    def detector(self, adapter, policy="union", answer=0.9):
        stage = None
        if policy == "verifier":
            stage = VerifierStage({"bundle": "unused", "timeout_seconds": None}, ROOT, factory=lambda bundle, **kw: VerifierModel(bundle, **kw, answer=answer))
        return Detector([existing.Empty("credsweeper", {}, ROOT), adapter], ConsensusPolicy.parse("majority"),
                        candidate_only=[adapter.name], candidate_policy=policy, verifier=stage)


class Defaults(Base):
    def test_strong_is_the_default(self) -> None:
        self.assertEqual(settings.DEFAULTS[NAME], "strong")
        self.assertEqual(self.adapter([]).short_values, "strong")
        with mode(" "):
            self.assertEqual(self.adapter([]).short_values, "strong", "an empty variable takes the default")

    def test_the_detector_json_option_and_the_environment_over_it(self) -> None:
        self.assertEqual(self.adapter([], short_values="drop").short_values, "drop")
        with mode("keep"):
            self.assertEqual(self.adapter([], short_values="drop").short_values, "keep")

    def test_an_unknown_value_is_refused(self) -> None:
        with mode("maybe"), self.assertRaises(ValueError):
            self.adapter([])
        with self.assertRaises(ValueError):
            self.adapter([], short_values="sometimes")


class ShortValues(Base):
    def test_a_sure_short_value_stays_strong_and_drop_loses_it(self) -> None:
        self.assertEqual(self.under("strong", [(SHORT, SURE)]), [(SHORT, "strong")])
        self.assertEqual(self.rows(self.adapter([(SHORT, SURE)])), [(SHORT, "strong")], "the default")
        self.assertEqual(self.under("keep", [(SHORT, SURE)]), [(SHORT, "strong")])
        self.assertEqual(self.under("drop", [(SHORT, SURE)]), [])

    def test_a_sure_short_value_is_masked_without_the_verifier(self) -> None:
        start = TEXT.index(SHORT)
        for policy in ("union", "verifier"):
            with self.subTest(policy=policy), mode("strong"):
                detector = self.detector(self.adapter([(SHORT, SURE)]), policy, answer=0.0)
                result = detector.scan(TEXT, "tool_output")
                self.assertTrue(result["ok"])
                self.assertEqual([(row["start"], row["end"]) for row in result["findings"]], [(start, start + len(SHORT))])
                self.assertEqual([candidate["strength"] for candidate in result["candidates"]], ["strong"])
                if policy == "verifier":
                    self.assertEqual(detector.verifier.model.given, [], "a strong candidate is not sent to the verifier")
        with mode("drop"):
            dropped = self.detector(self.adapter([(SHORT, SURE)]), "verifier").scan(TEXT, "tool_output")
        self.assertEqual((dropped["findings"], dropped["candidates"]), ([], []))

    def test_an_unsure_short_value_is_dropped_and_keep_leaves_it_ambiguous(self) -> None:
        self.assertEqual(self.under("strong", [(SHORT, UNSURE)]), [])
        self.assertEqual(self.under("keep", [(SHORT, UNSURE)]), [(SHORT, "ambiguous")])
        self.assertEqual(self.under("drop", [(SHORT, UNSURE)]), [])

    def test_an_unsure_short_value_reaches_the_verifier_under_keep_only(self) -> None:
        start = TEXT.index(SHORT)
        given = {}
        for value in MODES:
            with mode(value):
                detector = self.detector(self.adapter([(SHORT, UNSURE)]), "verifier", answer=0.9)
                result = detector.scan(TEXT, "tool_output")
            given[value] = ([(c["start"], c["end"], c["strength"]) for c in detector.verifier.model.given], [(row["start"], row["end"]) for row in result["findings"]])
        self.assertEqual(given["strong"], ([], []), "dropped in the adapter: the verifier is not asked")
        self.assertEqual(given["drop"], ([], []))
        self.assertEqual(given["keep"], ([(start, start + len(SHORT), "ambiguous")], [(start, start + len(SHORT))]))

    def test_one_character(self) -> None:
        self.assertEqual(self.under("strong", [(ONE, SURE)], ONE_TEXT), [(ONE, "strong")], "no shortest length: one character stays")
        self.assertEqual(self.under("strong", [(ONE, UNSURE)], ONE_TEXT), [])
        self.assertEqual(self.under("keep", [(ONE, UNSURE)], ONE_TEXT), [(ONE, "ambiguous")])
        self.assertEqual(self.under("drop", [(ONE, SURE)], ONE_TEXT), [])

    def test_the_score_is_compared_with_the_adapters_own_strong_threshold(self) -> None:
        self.assertEqual(self.under("strong", [(SHORT, 0.99)]), [(SHORT, "strong")], "at the threshold is strong, as for a long value")
        self.assertEqual(self.under("strong", [(SHORT, UNSURE)], strong_threshold=0.9), [(SHORT, "strong")])
        self.assertEqual(self.under("strong", [(SHORT, SURE)], strong_threshold=0.999), [])

    def test_the_length_is_counted_without_quotes_and_punctuation(self) -> None:
        text = 'pin = "ab",\npw = "s3x7Qz",\n'
        self.assertEqual(self.under("strong", [('"ab",', UNSURE)], text), [], "two characters, as min_value_length counts them")
        for value in MODES:
            with self.subTest(mode=value):
                self.assertEqual(self.under(value, [('"s3x7Qz",', UNSURE)], text), [('"s3x7Qz",', "ambiguous")], "six characters: not short")
                self.assertEqual(self.under(value, [('",', 0.999)], text), [], "nothing left after stripping: never a value")

    def test_ordinary_words_are_dropped_in_every_mode(self) -> None:
        text = "the token of the account is set by value here\n"
        spans = [("of", 0.999), ("by", 0.999), ("value", 0.999), ("account", 0.999)]
        for value in MODES:
            with self.subTest(mode=value):
                self.assertEqual(self.under(value, spans, text), [("account", "strong")])

    def test_six_characters_and_more_are_the_same_in_every_mode(self) -> None:
        text = f'key {LONG} and pw "s3x7Qz" or "t4y8Wb"\n'
        spans = [(LONG, 0.9999), ("s3x7Qz", UNSURE), ("t4y8Wb", SURE)]
        seen = {}
        for value in MODES:
            with mode(value):
                found = self.adapter(spans).scan(text)
            seen[value] = [(row.start, row.end, row.confidence, row.score, row.rule_id, row.family) for row in found]
        self.assertEqual(seen["strong"], seen["drop"])
        self.assertEqual(seen["keep"], seen["drop"])
        # What main (73282b9) returns for the same spans: the score alone decides, and nothing is dropped.
        self.assertEqual([(end - start, confidence, score) for start, end, confidence, score, *_ in seen["drop"]],
                         [(len(LONG), "strong", 0.9999), (6, "ambiguous", UNSURE), (6, "strong", SURE)])

    def test_min_value_length_says_what_short_is(self) -> None:
        # strong: a value of min_value_length or more is not short, so its score does not drop it.
        self.assertEqual(self.under("strong", [(SHORT, UNSURE)], min_value_length=3), [(SHORT, "ambiguous")])
        self.assertEqual(self.under("strong", [(SHORT, UNSURE)], min_value_length=4), [])
        self.assertEqual(self.under("drop", [(SHORT, SURE)], min_value_length=3), [(SHORT, "strong")])
        self.assertEqual(self.under("keep", [(SHORT, UNSURE)], min_value_length=12), [(SHORT, "ambiguous")], "keep does not read it")


class EveryModelAdapter(Base):
    def build(self, value, **options):
        with mode(value):
            return [self.adapter([(SHORT, 0.99)], **options), self.adapter([(SHORT, 0.99)], MLV9Adapter, "ml-v9", **options),
                    QwenAdapter("ml-qwen", {"repository": str(self.repo), **options}, ROOT, factory=lambda bundle, **kw: existing.FakeQwen(bundle, values=[SHORT], **kw))]

    def test_ml_span_ml_v9_and_ml_qwen_alike(self) -> None:
        # FakeQwen scores every finding 0.99; the same score is given to the other two.
        expected = {"strong": [(SHORT, "strong")], "keep": [(SHORT, "strong")], "drop": []}
        for value in MODES:
            for adapter in self.build(value):
                self.assertEqual(self.rows(adapter), expected[value], f"{adapter.name} under {value}")

    def test_alike_below_the_threshold(self) -> None:
        expected = {"strong": [], "keep": [(SHORT, "ambiguous")], "drop": []}
        for value in MODES:
            for adapter in self.build(value, strong_threshold=0.995):
                self.assertEqual(self.rows(adapter), expected[value], f"{adapter.name} under {value}")


class ModelSideFilter(Base):
    """The model repository's runtime drops short spans itself when its bundle says min_value_length 6 (v10)."""

    VALUES = ("Q", "x7", "k3y", "w9zt", "p4s5d")
    TEXT = "pin Q\nid x7\ncode k3y\nkey w9zt\npw p4s5d\n"
    MIXED = (SURE, UNSURE, SURE, UNSURE, SURE)

    def build(self, scores=None, **options):
        folder = self.repo / "models" / "span-detector-v10"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "span_bundle.json").write_text(json.dumps({"min_value_length": 6}), encoding="utf-8")
        seen = []
        spans = list(zip(self.VALUES, scores or [0.999] * len(self.VALUES)))

        def factory(checkpoint, device="cpu", *, min_value_length=None):
            seen.append(RuntimeLike(checkpoint, device, min_value_length=min_value_length, spans=spans))
            return seen[0]

        adapter = MLSpanAdapter("ml-span", {"repository": str(self.repo), "checkpoint": "models/span-detector-v10", **options}, ROOT, factory=factory)
        return adapter, seen[0]

    def test_strong_and_keep_let_short_spans_reach_the_adapter(self) -> None:
        for chosen in ("strong", "keep"):
            with self.subTest(mode=chosen), mode(chosen):
                adapter, model = self.build()
                self.assertEqual(model.given, 1, "the caller's value wins over the bundle's; 1 is the runtime's 'no length guard'")
                self.assertEqual(self.rows(adapter, self.TEXT), [(value, "strong") for value in self.VALUES])

    def test_strong_then_decides_by_the_score_in_the_adapter(self) -> None:
        adapter, _ = self.build(self.MIXED)
        self.assertEqual(self.rows(adapter, self.TEXT), [("Q", "strong"), ("k3y", "strong"), ("p4s5d", "strong")])

    def test_keep_passes_every_one_with_its_strength(self) -> None:
        with mode("keep"):
            adapter, _ = self.build(self.MIXED)
        self.assertEqual([confidence for _, confidence in self.rows(adapter, self.TEXT)], ["strong", "ambiguous", "strong", "ambiguous", "strong"])

    def test_drop_leaves_the_bundle_as_it_is(self) -> None:
        adapter, model = self.build(short_values="drop")
        self.assertIsNone(model.given, "drop passes nothing: the model is built as before")
        self.assertEqual(self.rows(adapter, self.TEXT), [])

    def test_a_runtime_without_the_argument_is_built_as_before(self) -> None:
        # promptguard-model before 9397bf7 (and every existing fake) takes (checkpoint, device) only.
        self.assertEqual(self.rows(self.adapter([(SHORT, SURE)])), [(SHORT, "strong")])


class ModelSettings(Base):
    """describe()["model_settings"]: the supervisor compares these between the Mod's and the Guard's workers."""

    def reported(self, *adapters):
        return Detector(list(adapters), ConsensusPolicy.parse("any"), candidate_policy="union").describe()["model_settings"][NAME]

    def test_the_mode_is_reported(self) -> None:
        self.assertEqual(self.reported(self.adapter([])), "strong")
        for value in MODES:
            with mode(value):
                self.assertEqual(self.reported(self.adapter([])), value)

    def test_no_model_reports_nothing_whatever_the_environment(self) -> None:
        with mode("drop"):
            self.assertIsNone(self.reported(existing.Empty("credsweeper", {}, ROOT)))

    def test_models_set_differently_are_named(self) -> None:
        one = self.adapter([])
        other = self.adapter([], MLV9Adapter, "ml-v9", short_values="drop")
        self.assertEqual(self.reported(one, other), "ml-span=strong,ml-v9=drop")


class ModelsOff(unittest.TestCase):
    """The default configuration (detector.json as shipped: every model adapter off) does not read the setting."""

    TEXTS = (TEXT, f"export DB_PASSWORD={'Synth-' + 'Val_92q' + 'Lm7xT'}\n", ONE_TEXT, "the build finished and all 48 tests passed\n")

    def test_the_same_result_in_every_mode(self) -> None:
        seen = {}
        for value in MODES:
            with mock.patch.dict(os.environ, {NAME: value}):
                for name in ("PG_DETECTOR_ENABLE", "PG_DETECTOR_DISABLE", "PG_DETECTOR_CONFIG", "PG_DETECTOR_CANDIDATE_POLICY"):
                    os.environ.pop(name, None)
                try:
                    detector = load_detector()
                except AdapterUnavailable as exc:  # pragma: no cover - a required rule detector is not installed here
                    self.skipTest(str(exc))
                self.assertFalse([adapter.name for adapter in detector.adapters if adapter.name.startswith("ml-")])
                self.assertIsNone(detector.describe()["model_settings"][NAME])
                results = [detector.scan(text, "tool_output") for text in self.TEXTS]
                seen[value] = [(result["ok"], result["findings"], result["candidates"]) for result in results]
        self.assertEqual(seen["strong"], seen["drop"])
        self.assertEqual(seen["keep"], seen["drop"])
        self.assertTrue(any(findings for _, findings, _ in seen["drop"]), "the rule detectors did find something to compare")


class DropRunsTheExistingTests(existing.SpanModelTests):
    """PG_ML_SHORT_VALUES=drop: every test of test_span_models.py, as it was written before this setting."""

    def setUp(self) -> None:
        super().setUp()
        drop = mock.patch.dict(os.environ, {NAME: "drop"})
        drop.start()
        self.addCleanup(drop.stop)


if __name__ == "__main__":
    unittest.main()
