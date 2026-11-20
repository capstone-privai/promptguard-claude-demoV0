"""candidate_policy "verifier": strong candidates are masked, ambiguous ones only when the back-end verifier accepts them.

The verifier model is a stub here (the real one, privai_model.verifier.runtime.CandidateVerifier, lives in the model
repository and needs torch). All values are synthetic; assertion messages never print them.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding, load_detector  # noqa: E402
from pgdetector.adapter import AdapterUnavailable  # noqa: E402
from pgdetector.core import utf16_len  # noqa: E402
from pgdetector.verifier import VerifierStage  # noqa: E402

SCHEMA = json.loads((ROOT / "src" / "shared" / "canonical-finding.schema.json").read_text(encoding="utf-8"))
STRONG = "SyntheticMajorityPass_42X"
WEAK = "SyntheticBuildValue_77Q"
TEXT = f"😀 password={STRONG}\nbuild_id={WEAK} done"


class Stub(DetectorAdapter):
    version = "test"

    def __init__(self, name: str, values=()) -> None:
        super().__init__(name, {}, ROOT)
        self.values = list(values)

    def scan(self, text: str) -> list[RawFinding]:
        return [RawFinding(text.index(v), text.index(v) + len(v), "PASSWORD", f"stub-{self.name}", "moderate") for v in self.values]


class LoadableStub(DetectorAdapter):
    """Constructible by load_detector(name, options, config_dir)."""

    version = "test"

    def scan(self, text: str) -> list[RawFinding]:
        return []


class FakeModel:
    """Stands in for CandidateVerifier: scores by span, records what it was given."""

    threshold = 0.5
    model_version = "fake-v0"

    def __init__(self, bundle, device="cpu", recall_target=None, context_lines=3, scores=None, error=None, delay=0.0) -> None:
        self.scores, self.error, self.delay, self.calls = dict(scores or {}), error, delay, []

    def score(self, text, source, candidates):
        self.calls.append((source, [dict(c) for c in candidates]))
        if self.delay:
            time.sleep(self.delay)
        if self.error:
            raise self.error
        return [self.scores.get(text[c["start"] - 1:c["end"] - 1], 0.0) for c in candidates]  # utf-16 shift: one emoji


def utf16_span(value: str) -> tuple[int, int]:
    start = TEXT.index(value)
    return utf16_len(TEXT[:start]), utf16_len(TEXT[:start + len(value)])


def stage(**model_kwargs) -> VerifierStage:
    options = {"bundle": "unused", "timeout_seconds": model_kwargs.pop("timeout", None)}
    return VerifierStage(options, ROOT, factory=lambda bundle, **kw: FakeModel(bundle, **kw, **model_kwargs))


def detector(verifier=None, policy="verifier") -> Detector:
    # STRONG: two of three adapters (the majority vote keeps it). WEAK: one adapter (ambiguous).
    adapters = [Stub("a", [STRONG, WEAK]), Stub("b", [STRONG]), Stub("c")]
    return Detector(adapters, ConsensusPolicy.parse("majority"), candidate_policy=policy, verifier=verifier)


def spans(result) -> list[tuple[int, int]]:
    return [(row["start"], row["end"]) for row in result["findings"]]


class VerifierPolicyTests(unittest.TestCase):
    def test_accepted_ambiguous_candidate_is_masked(self) -> None:
        result = detector(stage(scores={WEAK: 0.9})).scan(TEXT, "tool_output")
        self.assertTrue(result["ok"])
        self.assertEqual([utf16_span(STRONG), utf16_span(WEAK)], spans(result))
        weak = [c for c in result["candidates"] if c["strength"] == "ambiguous"]
        self.assertEqual([0.9], [c["verifier_score"] for c in weak])

    def test_rejected_ambiguous_candidate_is_not_masked(self) -> None:
        result = detector(stage(scores={WEAK: 0.1})).scan(TEXT, "tool_output")
        self.assertTrue(result["ok"])
        self.assertEqual([utf16_span(STRONG)], spans(result))
        self.assertEqual(2, result["candidate_count"], "candidates are reported either way")
        union = detector(None, "union").scan(TEXT, "tool_output")
        self.assertEqual([utf16_span(STRONG), utf16_span(WEAK)], spans(union))

    def test_verifier_sees_only_ambiguous_candidates_with_their_evidence(self) -> None:
        verifier = stage(scores={WEAK: 0.9})
        detector(verifier).scan(TEXT, "tool_output")
        (source, given), = verifier.model.calls
        self.assertEqual("tool_output", source)
        self.assertEqual([utf16_span(WEAK)], [(c["start"], c["end"]) for c in given])
        for key in ("type", "rule_id", "detectors", "evidence", "strength", "legacy_protected"):
            self.assertIn(key, given[0])
        self.assertEqual("ambiguous", given[0]["strength"])
        self.assertNotIn("value_hash", given[0])

    def test_findings_are_canonical(self) -> None:
        result = detector(stage(scores={WEAK: 0.9})).scan(TEXT, "tool_output")
        allowed, required = set(SCHEMA["properties"]), set(SCHEMA["required"])
        for row in result["findings"]:
            self.assertTrue(required <= set(row) <= allowed, sorted(row))
            self.assertEqual(64, len(row["value_hash"]))

    def test_verifier_failure_fails_closed(self) -> None:
        cases = {"error": stage(error=RuntimeError("synthetic")), "timeout": stage(delay=0.3, timeout=0.05),
                 "bad scores": stage(scores={WEAK: 7.0})}
        for name, verifier in cases.items():
            with self.subTest(case=name), mock.patch("sys.stderr"):
                result = detector(verifier).scan(TEXT, "tool_output")
                self.assertFalse(result["ok"])
                self.assertIn("ADAPTER_FAILURE:verifier", result["errors"])
                self.assertEqual([utf16_span(STRONG), utf16_span(WEAK)], spans(result))

    def test_no_ambiguous_candidates_skips_the_model(self) -> None:
        verifier = stage()
        adapters = [Stub("a", [STRONG]), Stub("b", [STRONG]), Stub("c")]
        result = Detector(adapters, ConsensusPolicy.parse("majority"), candidate_policy="verifier", verifier=verifier).scan(TEXT, "unit")
        self.assertEqual([utf16_span(STRONG)], spans(result))
        self.assertEqual([], verifier.model.calls)

    def test_policy_and_verifier_go_together(self) -> None:
        with self.assertRaises(ValueError):
            detector(None, "verifier")
        with self.assertRaises(ValueError):
            detector(stage(), "majority")
        self.assertEqual({"name": "verifier", "version": "unused:fake-v0", "threshold": 0.5}, detector(stage()).describe()["verifier"])

    def test_load_detector_needs_the_bundle_when_asked_for(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "model-repo" / "src").mkdir(parents=True)
            path = root / "detector.json"
            adapters = [{"name": "x", "type": "test_verifier:LoadableStub"}]
            verifier = {"repository": str(root / "model-repo"), "bundle": "runs/verifier/missing/model"}
            path.write_text(json.dumps({"consensus": "majority", "candidate_policy": "union", "verifier": verifier, "adapters": adapters}), encoding="utf-8")
            sys.path.insert(0, str(Path(__file__).parent))
            try:
                self.assertIsNone(load_detector(path).verifier, "union never loads the verifier")
                with mock.patch.dict(os.environ, {"PG_DETECTOR_CANDIDATE_POLICY": "verifier"}):
                    with self.assertRaises(AdapterUnavailable):
                        load_detector(path)
            finally:
                sys.path.remove(str(Path(__file__).parent))

    def test_shipped_config_keeps_the_verifier_off(self) -> None:
        config = json.loads((ROOT / "src" / "detector" / "detector.json").read_text(encoding="utf-8"))
        self.assertEqual("union", config["candidate_policy"])
        self.assertTrue(config["verifier"]["bundle"])


if __name__ == "__main__":
    unittest.main()
