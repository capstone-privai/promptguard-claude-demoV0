"""scripts/latency/size_sweep.py: texts (size, variety, planted secrets, seed), percentiles, and no text in the report."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "latency"))

import size_sweep  # noqa: E402


class Texts(unittest.TestCase):
    def test_size_variety_and_secrets(self) -> None:
        for size_kb in size_sweep.SIZES_KB:
            texts = size_sweep.make_texts(7, size_kb)
            self.assertEqual(len(texts), 20)
            self.assertTrue(all(len(text.encode("utf-8")) == size_kb * 1024 for text, _ in texts), size_kb)
            self.assertEqual(len({text for text, _ in texts}), 20, "20 different texts")
            planted = [count for _, count in texts]
            self.assertEqual(sum(1 for count in planted if count), 10)
            self.assertTrue(all(1 <= count <= 3 for count in planted if count))

    def test_secrets_survive_the_cut(self) -> None:
        for text, planted in size_sweep.make_texts(7, 1):
            found = sum(text.count(marker) for marker in ("API_KEY=", "db_password", "ghp_", "AKIA", "client_secret", "Bearer "))
            self.assertGreaterEqual(found, planted)

    def test_mixes_kinds(self) -> None:
        text = "".join(t for t, _ in size_sweep.make_texts(7, 16))
        for marker in ("def ", "public class", "export async function", " INFO ", "_HOST=", "replicas:", "\"tags\""):
            self.assertIn(marker, text)

    def test_seed_fixes_the_texts(self) -> None:
        self.assertEqual(size_sweep.make_texts(11, 2), size_sweep.make_texts(11, 2))
        self.assertNotEqual(size_sweep.make_texts(11, 2), size_sweep.make_texts(12, 2))


class Report(unittest.TestCase):
    def test_percentiles_and_timeouts(self) -> None:
        values = [float(v) for v in range(1, 201)]
        s = size_sweep.stats(values, timeout_ms=150)
        self.assertEqual((s["p50_ms"], s["p90_ms"], s["p95_ms"], s["p99_ms"], s["max_ms"], s["over_timeout"]), (100.0, 180.0, 190.0, 198.0, 200.0, 50))
        self.assertEqual(size_sweep.stats([1.0, 2.0], 5, failures=3)["over_timeout"], 3)

    def test_markdown_marks_the_goals_and_holds_no_text(self) -> None:
        scan = {str(k): size_sweep.stats([10.0 * k] * 4, 5000) for k in (1, 4)}
        result = {"date": "2026-11-23", "seed": 1, "timeout_ms": 5000.0, "scan_runs_per_size": 200, "bridge_runs_per_size": 50,
                  "machine": {"os": "x", "python": "3", "node": "v1", "gitleaks": "8", "credsweeper": "1", "logical_cpus": 8},
                  "configs": {"a": {"label": "기본값", "detector": {"adapters": [{"name": "credsweeper", "version": "1"}], "candidate_policy": "union",
                                                                   "consensus": "majority", "filter_settings": {}, "skipped": []},
                                    "scan": scan, "bridge": scan},
                              "b": {"label": "verifier", "unavailable": "번들 없음"}}}
        text = size_sweep.markdown(result)
        self.assertIn("| 4 | 40.0 | 40.0 | 40.0 | 40.0 | 40.0 | 0 | 달성 |", text)
        self.assertIn("0.4% |", text)
        self.assertIn("건너뜀: 번들 없음", text)
        sample = size_sweep.make_texts(1, 1)[0][0]
        self.assertNotIn(sample[:40], text + json.dumps(result))


if __name__ == "__main__":
    unittest.main()
