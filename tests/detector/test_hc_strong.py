"""A high-confidence rule's candidate (src/detector/high-confidence-rules.json) is strong, whatever confidence the
adapter gave it, so candidate_policy "verifier" masks it whatever the verifier scores. Other moderate candidates still
follow the verifier, and the union and majority results are unchanged. Stub adapters and a stub verifier; synthetic
values only.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding  # noqa: E402
from pgdetector.verifier import VerifierStage  # noqa: E402

GOOGLE = "SynthGoogleKey_7Qx9mK2p"   # CredSweeper "Google API Key": on the list, moderate
CURL = "SynthCurlAuth_4Kp2vN8c"      # Gitleaks "curl-auth-header": on the list, moderate
PLAIN = "SynthPlainValue_9qZ3w"      # promptguard-rules secret-assignment: not on the list, moderate
TEXT = f"key={GOOGLE}\ncurl -H 'Authorization: {CURL}'\npassword={PLAIN}\n"
HIGH = {(r["adapter"], r["rule_id"]) for r in json.loads((ROOT / "src/detector/high-confidence-rules.json").read_text(encoding="utf-8"))["high_confidence_rules"]}


class Stub(DetectorAdapter):
    version = "test"

    def __init__(self, name: str, found) -> None:
        super().__init__(name, {}, ROOT)
        self.found = list(found)

    def scan(self, text: str) -> list[RawFinding]:
        return [RawFinding(text.index(v), text.index(v) + len(v), "API_KEY", rule, "moderate") for v, rule in self.found]


class ZeroModel:
    threshold = 0.5
    model_version = "zero"

    def __init__(self, bundle, **_kw) -> None:
        self.calls = []

    def score(self, text, source, candidates):
        self.calls.append([text[c["start"]:c["end"]] for c in candidates])  # ASCII: utf-16 offsets = indexes
        return [0.0 for _ in candidates]


def detector(policy: str):
    verifier = VerifierStage({"bundle": "unused"}, ROOT, factory=lambda bundle, **kw: ZeroModel(bundle, **kw)) if policy == "verifier" else None
    adapters = [Stub("credsweeper", [(GOOGLE, "Google API Key")]), Stub("gitleaks", [(CURL, "curl-auth-header")]),
                Stub("promptguard-rules", [(PLAIN, "secret-assignment")])]
    return Detector(adapters, ConsensusPolicy.parse("majority"), candidate_policy=policy, verifier=verifier), verifier


def masked(result) -> list[str]:
    return sorted(TEXT[f["start"]:f["end"]] for f in result["findings"])


class HighConfidenceStrong(unittest.TestCase):
    def test_the_list_holds_the_rules_under_test(self) -> None:
        self.assertIn(("credsweeper", "Google API Key"), HIGH)
        self.assertIn(("gitleaks", "curl-auth-header"), HIGH)
        self.assertNotIn(("promptguard-rules", "secret-assignment"), HIGH)

    def test_verifier_policy_masks_high_confidence_candidates_at_score_zero(self) -> None:
        d, verifier = detector("verifier")
        result = d.scan(TEXT, "tool_output")
        self.assertEqual(masked(result), sorted([GOOGLE, CURL]), "the list's candidates are masked; the plain one follows the verifier (0 points)")
        self.assertEqual(verifier.model.calls, [[PLAIN]], "only the plain moderate candidate goes to the verifier")
        strength = {TEXT[c["start"]:c["end"]]: c["strength"] for c in result["candidates"]}
        self.assertEqual(strength, {GOOGLE: "strong", CURL: "strong", PLAIN: "ambiguous"})
        self.assertTrue(result["ok"])

    def test_union_and_majority_results_are_unchanged(self) -> None:
        self.assertEqual(masked(detector("union")[0].scan(TEXT, "tool_output")), sorted([GOOGLE, CURL, PLAIN]))
        self.assertEqual(masked(detector("majority")[0].scan(TEXT, "tool_output")), [], "one adapter each: no majority, as before")

    def test_candidate_fields_are_unchanged(self) -> None:
        result = detector("union")[0].scan(TEXT, "tool_output")
        for candidate in result["candidates"]:
            for row in candidate["evidence"]:
                self.assertEqual(set(row) - {"score"}, {"adapter", "family", "strength", "details"})
                self.assertEqual(row["strength"], "moderate", "the adapter's own confidence is kept in the evidence")


if __name__ == "__main__":
    unittest.main()
