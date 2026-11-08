"""The CredSweeper adapter's handling of empty spans. Key material is random and never printed."""

from __future__ import annotations

import base64
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector  # noqa: E402
from pgdetector.adapters.credsweeper import CredSweeperAdapter  # noqa: E402

HEAD, TAIL = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----", "-----END PGP " + "PRIVATE KEY BLOCK-----"


def armor(*header: str) -> tuple[str, list[str]]:
    body = base64.b64encode(os.urandom(900)).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "\n".join([HEAD, *header, *lines, TAIL]) + "\n", lines


def candidate(line_num: int, start: int, end: int):
    return SimpleNamespace(rule_name="PEM Private Key", confidence=None, line_data_list=[
        SimpleNamespace(line_num=line_num, value_start=start, value_end=end, variable=""),
    ])


class FakeScanner:
    def __init__(self, candidates):
        self.credential_manager = SimpleNamespace(candidates=candidates, clear_credentials=lambda: None)

    def scan(self, _providers, _dedup):
        pass


class CredSweeperAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = CredSweeperAdapter("credsweeper", {"severity": "medium", "confidence": "moderate"}, ROOT / "src" / "detector")

    def detector(self, adapter) -> Detector:
        return Detector([adapter], ConsensusPolicy.parse("any"))

    def fake(self, *candidates) -> CredSweeperAdapter:
        adapter = CredSweeperAdapter.__new__(CredSweeperAdapter)
        adapter.name = "credsweeper"
        adapter.scanners = [FakeScanner(list(candidates))]
        adapter.lock = self.adapter.lock
        return adapter

    def test_pgp_armor_with_a_blank_line_is_scanned_and_every_body_line_masked(self) -> None:
        for header in (("",), ("Version: GnuPG v2", "")):
            text, lines = armor(*header)
            result = self.detector(self.adapter).scan(text, "unit")
            self.assertTrue(result["ok"], result["errors"])
            for line in lines:
                at = text.index(line)
                self.assertTrue(any(f["start"] < at + len(line) and at < f["end"] for f in result["findings"]))

    def test_an_empty_span_on_a_blank_line_is_dropped(self) -> None:
        self.assertEqual([], self.fake(candidate(2, 0, 0)).scan("first\n\nthird\n"))

    def test_an_empty_span_on_a_line_with_text_still_fails_closed(self) -> None:
        # Not the armor case: the value is somewhere CredSweeper did not say, so the scan must not pass.
        result = self.detector(self.fake(candidate(1, 3, 3))).scan("first\n\nthird\n", "unit")
        self.assertFalse(result["ok"])
        self.assertIn("INVALID_OFFSET_RANGE", result["errors"])

    def test_a_negative_offset_still_fails_closed(self) -> None:
        result = self.detector(self.fake(candidate(2, -1, -1))).scan("first\n\nthird\n", "unit")
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
