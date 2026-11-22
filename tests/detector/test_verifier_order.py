"""#23's structure filters x #28's verifier (release/defaults-1120 on main 7becf6a): adapter findings -> structure
filters (PG_DETECTOR_FILTERS) -> union and vote -> (candidate_policy "verifier") ambiguous candidates only to the
verifier. A filtered candidate is never sent to the verifier. The verifier model is a stub; all values are synthetic
and assertion messages never print them.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding  # noqa: E402
from pgdetector.verifier import VerifierStage  # noqa: E402

KEPT = "SynthAmbiguous_7Qx9"    # a literal: kept by the filters, ambiguous (one adapter)
CODE = "get_token()"            # code: filtered with PG_DETECTOR_FILTERS=on
HTML = "</p>"                   # HTML: filtered with PG_DETECTOR_FILTERS=on
STRONG = "SynthStrong_4Kp2"     # two adapters agree: strong, never sent to the verifier
TEXT = f"password={KEPT}\ntoken={CODE}\nsecret={HTML}\napi_key={STRONG}\n"


class Stub(DetectorAdapter):
    version = "test"

    def __init__(self, name: str, values) -> None:
        super().__init__(name, {}, ROOT)
        self.values = list(values)

    def scan(self, text: str) -> list[RawFinding]:
        return [RawFinding(text.index(v), text.index(v) + len(v), "PASSWORD", "Password", "moderate") for v in self.values]


class FakeModel:
    threshold = 0.5
    model_version = "fake"

    def __init__(self, bundle, **_kw) -> None:
        self.calls = []

    def score(self, text, source, candidates):
        self.calls.append([text[c["start"]:c["end"]] for c in candidates])  # ASCII text: utf-16 offsets = indexes
        return [0.0 for _ in candidates]


def run(filters: str, policy: str = "verifier"):
    with mock.patch.dict(os.environ, {"PG_DETECTOR_FILTERS": filters, "PG_DETECTOR_FILTER_DUMMY": "off"}):
        verifier = VerifierStage({"bundle": "unused"}, ROOT, factory=lambda bundle, **kw: FakeModel(bundle, **kw)) if policy == "verifier" else None
        adapters = [Stub("credsweeper", [KEPT, CODE, HTML, STRONG]), Stub("gitleaks", [STRONG]), Stub("promptguard-rules", [])]
        detector = Detector(adapters, ConsensusPolicy.parse("majority"), candidate_policy=policy, verifier=verifier)
        return detector.scan(TEXT, "tool_output"), verifier


class FilterBeforeVerifier(unittest.TestCase):
    def test_filtered_candidates_never_reach_the_verifier(self) -> None:
        result, verifier = run("on")
        (sent,) = verifier.model.calls
        self.assertEqual(sent, [KEPT], "only the kept ambiguous candidate is sent")
        self.assertEqual(result["filtered"], {"code_fragment": 1, "html_fragment": 1})
        self.assertEqual(result["candidate_count"], 2, "filtered values are not candidates at all")

    def test_with_the_filters_off_every_ambiguous_candidate_is_sent(self) -> None:
        _, verifier = run("off")
        (sent,) = verifier.model.calls
        self.assertEqual(sorted(sent), sorted([KEPT, CODE, HTML]))

    def test_strong_candidates_skip_the_verifier_and_stay_masked(self) -> None:
        result, verifier = run("on")
        self.assertNotIn(STRONG, verifier.model.calls[0])
        masked = [TEXT[f["start"]:f["end"]] for f in result["findings"]]
        self.assertEqual(masked, [STRONG], "the verifier scored the ambiguous one 0.0, so only the strong one is masked")

    def test_union_is_still_the_default(self) -> None:
        config = json.loads((ROOT / "src" / "detector" / "detector.json").read_text(encoding="utf-8"))
        self.assertEqual(config["candidate_policy"], "union")
        result, verifier = run("on", "union")
        self.assertIsNone(verifier)
        self.assertEqual(sorted(TEXT[f["start"]:f["end"]] for f in result["findings"]), sorted([KEPT, STRONG]))


if __name__ == "__main__":
    unittest.main()
