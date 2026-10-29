"""candidate_policy: "union" masks what any adapter finds, "majority" keeps the vote.

Only in-house adapters (promptguard-rules, shell-aware) and stubs are used, so
these tests run without CredSweeper or Gitleaks installed. All values are
synthetic; assertion messages never print them.
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

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding, load_detector  # noqa: E402
from pgdetector.adapters.patterns import PatternAdapter  # noqa: E402
from pgdetector.adapters.shell_aware import ShellAwareAdapter  # noqa: E402
from pgdetector.core import utf16_len  # noqa: E402


class Stub(DetectorAdapter):
    version = "test"

    def __init__(self, name: str, spans=(), fail: bool = False) -> None:
        super().__init__(name, {}, ROOT)
        self.spans, self.fail = list(spans), fail

    def scan(self, text: str) -> list[RawFinding]:
        if self.fail:
            raise RuntimeError("synthetic adapter failure")
        return [RawFinding(start, end, "PASSWORD", f"stub-{self.name}", "strong") for start, end in self.spans]


class LoadableStub(DetectorAdapter):
    """Constructible by load_detector(name, options, config_dir)."""

    version = "test"

    def scan(self, text: str) -> list[RawFinding]:
        return []


def cp_to_utf16(text: str, start: int, end: int) -> tuple[int, int]:
    return utf16_len(text[:start]), utf16_len(text[:end])


def mask(text: str, findings: list[dict]) -> str:
    """Native Mod style: replace UTF-16 spans (back to front) with [TYPE_n]."""
    units = text.encode("utf-16-le")
    for index, row in enumerate(sorted(findings, key=lambda r: r["start"], reverse=True), start=1):
        placeholder = f"[{row['type']}_{index}]".encode("utf-16-le")
        units = units[: row["start"] * 2] + placeholder + units[row["end"] * 2:]
    return units.decode("utf-16-le")


SECRET = "SyntheticUnionPass_42X"
TEXT = f"token=AAAA; sshpass -p '{SECRET}' ssh demo@host.invalid"


class CandidatePolicyTests(unittest.TestCase):
    def build(self, policy: str, *adapters: DetectorAdapter, candidate_only=()) -> Detector:
        return Detector(list(adapters), ConsensusPolicy.parse("majority"), candidate_only=candidate_only, candidate_policy=policy)

    def test_union_masks_single_adapter_span_majority_does_not(self) -> None:
        start = TEXT.index(SECRET)
        span = (start, start + len(SECRET))
        adapters = lambda: (Stub("a", [span]), Stub("b"), Stub("c"))  # noqa: E731
        union = self.build("union", *adapters()).scan(TEXT, "unit")
        majority = self.build("majority", *adapters()).scan(TEXT, "unit")
        self.assertEqual([cp_to_utf16(TEXT, *span)], [(r["start"], r["end"]) for r in union["findings"]])
        self.assertEqual([], majority["findings"])
        self.assertEqual(1, union["required_votes"])
        self.assertEqual(2, majority["required_votes"])

    def test_majority_ignores_candidate_only_but_union_uses_it(self) -> None:
        shell = ShellAwareAdapter("shell-aware", {}, ROOT)
        legacy = (Stub("a"), Stub("b"), Stub("c"))
        majority = self.build("majority", *legacy, shell, candidate_only=["shell-aware"])
        union = self.build("union", *legacy, shell, candidate_only=["shell-aware"])
        self.assertEqual(["a", "b", "c"], majority.protection_names)
        self.assertEqual(2, majority.required_votes)
        self.assertEqual([], majority.scan(TEXT, "unit")["findings"])
        found = union.scan(TEXT, "unit")["findings"]
        self.assertEqual(1, len(found))
        self.assertEqual(["shell-aware"], found[0]["detectors"])
        self.assertIn("value_hash", found[0], "Native Mod needs value_hash for stable placeholders")

    def test_overlapping_spans_are_merged_to_full_cover(self) -> None:
        start = TEXT.index(SECRET)
        a = Stub("a", [(start, start + 8)])
        b = Stub("b", [(start + 4, start + len(SECRET))])
        found = self.build("union", a, b).scan(TEXT, "unit")["findings"]
        self.assertEqual([cp_to_utf16(TEXT, start, start + len(SECRET))], [(r["start"], r["end"]) for r in found])
        self.assertEqual(["a", "b"], found[0]["detectors"])

    def test_adapter_failure_fails_closed_in_union(self) -> None:
        start = TEXT.index(SECRET)
        result = self.build("union", Stub("a", [(start, start + len(SECRET))]), Stub("broken", fail=True)).scan(TEXT, "unit")
        self.assertFalse(result["ok"])
        self.assertIn("ADAPTER_FAILURE:broken", result["errors"])

    def test_unknown_policy_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.build("any-of-them", Stub("a"))

    def test_config_and_env_select_policy(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "detector.json"
            adapters = [{"name": "x", "type": "test_candidate_policy:LoadableStub"}]
            sys.path.insert(0, str(Path(__file__).parent))
            try:
                path.write_text(json.dumps({"consensus": "majority", "adapters": adapters}), encoding="utf-8")
                self.assertEqual("majority", load_detector(path).candidate_policy, "missing key keeps legacy behaviour")
                path.write_text(json.dumps({"consensus": "majority", "candidate_policy": "union", "adapters": adapters}), encoding="utf-8")
                self.assertEqual("union", load_detector(path).candidate_policy)
                with mock.patch.dict(os.environ, {"PG_DETECTOR_CANDIDATE_POLICY": "majority"}):
                    self.assertEqual("majority", load_detector(path).candidate_policy)
            finally:
                sys.path.remove(str(Path(__file__).parent))

    def test_shipped_config_is_union_without_ml(self) -> None:
        config = json.loads((ROOT / "src" / "detector" / "detector.json").read_text(encoding="utf-8"))
        self.assertEqual("union", config["candidate_policy"])
        names = [entry["name"] for entry in config["adapters"]]
        self.assertEqual(["credsweeper", "gitleaks", "promptguard-rules", "shell-aware"], names)

    def test_masked_fixtures_do_not_retrigger_in_house_adapters(self) -> None:
        """Final Guard rescans masked text with the same union; placeholders must stay quiet."""
        detector = self.build("union", PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT), ShellAwareAdapter("shell-aware", {}, ROOT))
        texts = [path.read_text(encoding="utf-8") for path in sorted((ROOT / "fixtures" / "positive").iterdir()) if path.is_file()]
        cases = json.loads((ROOT / "tests" / "detector" / "shell_aware_cases.json").read_text(encoding="utf-8"))["cases"]
        texts += [case["text"] for case in cases]
        for index, text in enumerate(texts):
            with self.subTest(case=index):
                first = detector.scan(text, "unit")
                self.assertTrue(first["ok"])
                again = detector.scan(mask(text, first["findings"]), "unit")
                self.assertEqual([], [(r["detectors"], r["type"]) for r in again["findings"]], f"case {index} retriggers after masking")


if __name__ == "__main__":
    unittest.main()
