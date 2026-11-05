"""The gitleaks adapter against the real binary (skipped when gitleaks is not installed).

Point PG_GITLEAKS_BIN at the binary when it is not on PATH. Values are synthetic.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector.adapters.gitleaks import GitleaksAdapter  # noqa: E402

BINARY = os.environ.get("PG_GITLEAKS_BIN") or "gitleaks"
AVAILABLE = shutil.which(BINARY) is not None

# Assembled at run time so the source never holds a whole key-shaped literal.
PEM = "\n".join([
    "-----BEGIN " + "PRIVATE KEY-----",
    "MC4CAQAwBQYDK2VwBCIEIBV2nB5yZ8wQm3kL7pR4tX9cF2hJ6sD1aG0eW5uY3oNi",
    "-----END " + "PRIVATE KEY-----",
])
GITHUB = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
AWS = "AKIA" + "IOSFODNN7SYNTH01"
STRIPE = "sk_" + "live_" + "51HcR8sJx2kL9mQ4vR7xN5sP1tW6yZ3aBcD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB6cD7eF8gH9iJ0kL1mN2oP3qR4sT5uV6wX7yZ8aB9cD0eF1gH2iJ3kL4m"

TEXTS = [
    f"export GITHUB_TOKEN={GITHUB}\n",
    "nothing to see here\njust logs\n",
    f"aws_access_key_id = {AWS}",
    PEM,  # a key file with no trailing newline
    f'{{"stripe": "{STRIPE}"}}\n{GITHUB} again on line two',
    "",
    f"line one\r\nkey={GITHUB}\r\n",
]


def spans(text, findings):
    return sorted((f.type, text[f.start:f.end]) for f in findings)


@unittest.skipUnless(AVAILABLE, "gitleaks binary not found (set PG_GITLEAKS_BIN)")
class GitleaksAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = GitleaksAdapter("gitleaks", {"binary": BINARY}, ROOT / "src" / "detector")

    def test_a_key_file_without_a_trailing_newline_is_located(self) -> None:
        # gitleaks reports EndLine 1 for a three-line PEM at the very end of its input; the adapter raised
        # "could not be located" and the whole scan failed (blocked).
        findings = self.adapter.scan(PEM)
        self.assertTrue(findings)
        self.assertTrue(all(f.type == "PRIVATE_KEY" for f in findings))

    def test_a_batch_finds_what_each_text_finds_alone(self) -> None:
        alone = [spans(text, self.adapter.scan(text)) for text in TEXTS]
        together = [spans(text, found) for text, found in zip(TEXTS, self.adapter.scan_many(TEXTS))]
        self.assertEqual(together, alone)
        self.assertTrue(any(alone))

    def test_a_batch_runs_one_process(self) -> None:
        real = subprocess.run
        calls = []
        with mock.patch("pgdetector.adapters.gitleaks.subprocess.run", side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
            self.adapter.scan_many(TEXTS * 4)
        self.assertEqual(len(calls), 1)

    def test_a_match_never_spans_two_texts(self) -> None:
        # The header ends one text and the rest of the block starts the next: neither holds a key on its own.
        head, tail = PEM.split("\n", 1)
        results = self.adapter.scan_many([f"notes\n{head}", tail, "plain"])
        self.assertEqual(results, [self.adapter.scan(f"notes\n{head}"), self.adapter.scan(tail), []])

    def test_the_boundary_line_is_not_in_any_text(self) -> None:
        texts = ["a", "b"]
        boundary = self.adapter._boundary(texts)
        self.assertTrue(all(boundary not in text for text in texts))
        self.assertNotEqual(boundary, self.adapter._boundary(texts))


if __name__ == "__main__":
    unittest.main()
