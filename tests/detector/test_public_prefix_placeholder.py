"""Text the Native Mod masked as prefix + [TYPE_N] is not a finding; anything else still is.

Only the in-house rules and stubs are used, so these run without CredSweeper or Gitleaks.
All values are synthetic and built at run time.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding  # noqa: E402
from pgdetector.adapters.patterns import PatternAdapter  # noqa: E402

PREFIX = "_".join(["sk", "live", ""])
PLACEHOLDER = f"{PREFIX}[STRIPE_SECRET_KEY_1]"
WHOLE = f"{PREFIX}SYNTHxFAKExVALUExONLYx0001"


class Stub(DetectorAdapter):
    version = "test"

    def __init__(self, value: str) -> None:
        super().__init__("stub", {}, ROOT)
        self.value = value

    def scan(self, text: str) -> list[RawFinding]:
        start = text.find(self.value)
        return [] if start < 0 else [RawFinding(start, start + len(self.value), "TOKEN", "stub", "strong", "stub", {})]


def detector(*adapters: DetectorAdapter) -> Detector:
    return Detector(list(adapters), ConsensusPolicy.parse("any"), candidate_policy="union")


class PublicPrefixPlaceholder(unittest.TestCase):
    def count(self, option: str | None, value: str, text: str | None = None) -> int:
        env = {} if option is None else {"PG_PLACEHOLDER_PUBLIC_PREFIX": option}
        with mock.patch.dict(os.environ, env):
            if option is None:
                os.environ.pop("PG_PLACEHOLDER_PUBLIC_PREFIX", None)
            return detector(Stub(value)).scan(text if text is not None else f"API_KEY={value}", "outbound")["finding_count"]

    def test_a_span_that_is_exactly_prefix_and_placeholder_is_dropped(self) -> None:
        self.assertEqual(self.count("on", PLACEHOLDER), 0)

    def test_the_whole_value_is_still_found(self) -> None:
        self.assertEqual(self.count("on", WHOLE), 1)

    def test_more_than_the_placeholder_is_still_found(self) -> None:
        self.assertEqual(self.count("on", f"{PLACEHOLDER}SYNTHxFAKE"), 1)
        self.assertEqual(self.count("on", f"x{PLACEHOLDER}"), 1)

    def test_a_prefix_with_another_rows_type_is_still_found(self) -> None:
        self.assertEqual(self.count("on", f"{PREFIX}[GITHUB_TOKEN_1]"), 1)

    def test_option_off_changes_nothing(self) -> None:
        self.assertEqual(self.count(None, PLACEHOLDER), 1)
        self.assertEqual(self.count("off", PLACEHOLDER), 1)

    def test_a_missing_table_changes_nothing(self) -> None:
        with mock.patch("pgdetector.ensemble.PUBLIC_PREFIX_TABLE", ROOT / "docs" / "no-such-table.md"):
            self.assertEqual(self.count("on", PLACEHOLDER), 1)

    def test_in_house_rules_leave_masked_text_alone(self) -> None:
        for form in ("API_KEY={v}", 'token: "{v}"', "password: {v}"):
            text = form.format(v=PLACEHOLDER)
            with self.subTest(form=form), mock.patch.dict(os.environ, {"PG_PLACEHOLDER_PUBLIC_PREFIX": "on"}):
                found = detector(PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT)).scan(text, "outbound")
                self.assertEqual(found["finding_count"], 0)
                self.assertEqual(found["candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()
