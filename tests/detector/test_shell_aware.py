from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding  # noqa: E402
from pgdetector.adapters.shell_aware import ShellAwareAdapter  # noqa: E402


class FixedAdapter(DetectorAdapter):
    version = "test"

    def __init__(self, name: str, spans: list[tuple[int, int]], _config: Path) -> None:
        super().__init__(name, {}, _config)
        self.spans = spans

    def scan(self, text: str) -> list[RawFinding]:
        return [RawFinding(start, end, "PASSWORD", "fixed", "strong") for start, end in self.spans]


class ShellAwareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ShellAwareAdapter("shell-aware", {}, ROOT)

    def assert_value_found(self, text: str, value: str, family: str | None = None) -> None:
        start = text.index(value)
        matches = [row for row in self.adapter.scan(text) if row.start <= start and row.end >= start + len(value)]
        self.assertTrue(matches, text)
        if family:
            self.assertTrue(any(row.family == family for row in matches), text)

    def test_long_options_quoted_unquoted_and_equals(self) -> None:
        for text, value in [
            ("somecmd --password 'SyntheticPass_123'", "SyntheticPass_123"),
            ("somecmd --token synthetic_token_123", "synthetic_token_123"),
            ("somecmd --api-key=synthetic_key_123", "synthetic_key_123"),
            ('somecmd --client-secret="SyntheticClient_123"', "SyntheticClient_123"),
            ("somecmd --access-token SyntheticAccess_123", "SyntheticAccess_123"),
        ]:
            with self.subTest(text=text):
                self.assert_value_found(text, value, "long_option")

    def test_command_aware_short_options(self) -> None:
        positives = [
            ("sshpass -p 'SyntheticPass_123' ssh user@host", "SyntheticPass_123"),
            ("mysql -uroot -p'SyntheticPass_123' demo", "SyntheticPass_123"),
            ("docker login -u demo -p 'SyntheticPass_123' example.invalid", "SyntheticPass_123"),
        ]
        for text, value in positives:
            with self.subTest(text=text):
                self.assert_value_found(text, value, "short_option")
        for text in (
            "mkdir -p build", "ssh -p 2222 localhost", "docker run -p 8080:80 nginx",
            "pytest -p plugin_name", "cp -p source target",
        ):
            with self.subTest(text=text):
                self.assertEqual([], self.adapter.scan(text))

    def test_stdin_here_string_and_heredoc(self) -> None:
        samples = [
            ("echo 'SyntheticPass_123' | sudo -S whoami", "SyntheticPass_123", "stdin_sink"),
            ("printf '%s\\n' 'SyntheticPass_123' | sudo -S whoami", "SyntheticPass_123", "stdin_sink"),
            ("echo 'SyntheticDockerPass_456' | docker login --username demo --password-stdin registry.invalid", "SyntheticDockerPass_456", "stdin_sink"),
            ("sudo -S <<< 'SyntheticPass_123'", "SyntheticPass_123", "here_string"),
            ("sudo -S sh <<'PGEOF'\nSyntheticPass_123\nPGEOF", "SyntheticPass_123", "heredoc"),
        ]
        for text, value, family in samples:
            with self.subTest(text=text):
                self.assert_value_found(text, value, family)
        self.assertEqual([], self.adapter.scan("echo 'hello' | cat"))
        self.assertEqual([], self.adapter.scan("cat <<EOF\nordinary text\nEOF"))

    def test_expect_context_and_semantic_function_arguments(self) -> None:
        self.assert_value_found("expect('Password:'); child.sendline('SyntheticPass_123')", "SyntheticPass_123", "expect_send")
        self.assert_value_found('expect "Password:"; send "SyntheticPass_123\\r"', "SyntheticPass_123", "expect_send")
        self.assertEqual([], self.adapter.scan("child.sendline('hello')"))
        for text in (
            "test_credentials('root', 'SyntheticPass_123')",
            "login('admin', 'SyntheticPass_123')",
            "authenticate(user, 'SyntheticPass_123')",
            "set_password(user, 'SyntheticPass_123')",
        ):
            with self.subTest(text=text):
                self.assert_value_found(text, "SyntheticPass_123", "function_argument")
        self.assertEqual([], self.adapter.scan("render('admin', 'SyntheticPass_123')"))

    def test_hard_negative_identifiers_are_not_candidates(self) -> None:
        for text in (
            "request_id=01HZ123456789ABCDEFGHJKMNPQ", "trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
            "commit=0123456789abcdef0123456789abcdef01234567",
            "digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "session_id=550e8400-e29b-41d4-a716-446655440000", "artifact_ref=Q7M9K2V4N8R6T3W5Y1Z0",
        ):
            with self.subTest(text=text):
                self.assertEqual([], self.adapter.scan(text))

    def test_union_preserves_legacy_and_provenance(self) -> None:
        text = "somecmd --password 'SyntheticPass_123'"
        start = text.index("SyntheticPass_123")
        legacy = FixedAdapter("legacy", [(start, start + len("SyntheticPass_123"))], ROOT)
        detector = Detector([legacy, self.adapter], ConsensusPolicy.parse("any"), candidate_only=["shell-aware"], candidate_policy="majority")
        ballots, errors = detector.collect([text])
        self.assertEqual([], errors)
        protected, _ = detector.decide(text, "unit", ballots[0])
        candidates, _ = detector.candidate_decide(text, "unit", ballots[0])
        self.assertEqual(1, len(protected))
        self.assertEqual(1, len(candidates))
        self.assertEqual(["legacy", "shell-aware"], candidates[0]["detectors"])
        self.assertEqual({"legacy", "shell-aware"}, {row["adapter"] for row in candidates[0]["evidence"]})

        response = detector.scan(text, "unit")
        self.assertEqual(1, len(response["findings"]))
        self.assertEqual(1, len(response["candidates"]))
        self.assertEqual(["legacy"], response["findings"][0]["detectors"])
        self.assertEqual(["legacy", "shell-aware"], response["candidates"][0]["detectors"])
        self.assertEqual("majority", response["candidate_policy"])
        self.assertNotIn("value_hash", response["candidates"][0])
        self.assertNotIn("SyntheticPass_123", repr(response["candidates"][0].get("evidence", [])))

    def test_old_candidate_coverage_is_subset_of_new_union(self) -> None:
        text = "token=LegacySynthetic123; sshpass -p 'SyntheticPass_123' ssh u@h"
        start = text.index("LegacySynthetic123")
        legacy = FixedAdapter("legacy", [(start, start + len("LegacySynthetic123"))], ROOT)
        detector = Detector([legacy, self.adapter], ConsensusPolicy.parse("any"), candidate_only=["shell-aware"])
        ballots, _ = detector.collect([text])
        old, _ = detector.decide(text, "unit", {"legacy": ballots[0]["legacy"]}, 1, candidate_scope=True)
        new, _ = detector.candidate_decide(text, "unit", ballots[0])
        self.assertTrue(all(any(candidate["start"] <= row["start"] and candidate["end"] >= row["end"] for candidate in new) for row in old))

    def test_adapter_emits_no_raw_logs(self) -> None:
        text = "somecmd --password 'SyntheticPass_DO_NOT_LOG'"
        captured_out, captured_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
            self.adapter.scan(text)
        self.assertNotIn("SyntheticPass_DO_NOT_LOG", captured_out.getvalue() + captured_err.getvalue())

    def test_union_policy_protects_shell_only_value(self) -> None:
        text = "sshpass -p 'SyntheticPass_123' ssh u@h"
        legacy = FixedAdapter("legacy", [], ROOT)
        detector = Detector([legacy, self.adapter], ConsensusPolicy.parse("any"), candidate_only=["shell-aware"], candidate_policy="union")
        response = detector.scan(text, "unit")
        self.assertEqual("union", response["candidate_policy"])
        self.assertEqual(1, len(response["findings"]))
        self.assertEqual(["shell-aware"], response["findings"][0]["detectors"])


if __name__ == "__main__":
    unittest.main()
