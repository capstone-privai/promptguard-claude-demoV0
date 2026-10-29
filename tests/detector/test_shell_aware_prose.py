"""Prose that names a credential option must not mask the next ordinary word (seen in a live demo session:
"of" and "by" masked as passwords). Values are synthetic."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector.adapters.shell_aware import ShellAwareAdapter  # noqa: E402


class ProseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ShellAwareAdapter("shell-aware", {}, ROOT)

    def found(self, text: str) -> list[str]:
        return [text[f.start:f.end] for f in self.adapter.scan(text)]

    def test_prose_words_after_an_option_are_not_values(self) -> None:
        for text in (
            "the --password option of mysql",
            "--api-key of the account",
            "flags such as --password, --token or --secret by convention",
            "credentials passed by --password are visible",
            "Never pass --password on the command line; use --password-stdin by piping",
            "Use --password by default",
            "with --secret of",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.found(text), [])

    def test_real_values_are_still_masked(self) -> None:
        cases = {
            "mysql --password SynthPw_41x -h db": ["SynthPw_41x"],
            "app --token 'of course secret' run": ["of course secret"],
            "app --password=of": ["of"],
            "login --password Of_Synth9": ["Of_Synth9"],
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.found(text), expected)


class DotenvCommandTests(unittest.TestCase):
    """A .env value that is a whole command (seen in the showcase .env: shell-aware missed it)."""

    def setUp(self) -> None:
        self.adapter = ShellAwareAdapter("shell-aware", {}, ROOT)

    def found(self, text: str) -> list[str]:
        return [text[f.start:f.end] for f in self.adapter.scan(text)]

    def test_assigned_command_is_read_as_the_command(self) -> None:
        self.assertEqual(self.found("DEPLOY_CMD=mysql -u deploy -pSynthDeploy_91x -h db orders"), ["SynthDeploy_91x"])
        self.assertEqual(self.found("LOGIN=sshpass -p SynthSsh_42z ssh deploy@db"), ["SynthSsh_42z"])

    def test_ordinary_assignments_still_skipped(self) -> None:
        self.assertEqual(self.found("FOO=bar mysql -u root -pSynthPw_77q db"), ["SynthPw_77q"])
        self.assertEqual(self.found("PAGER=less mysql -p db"), [])
        self.assertEqual(self.found("DB_HOST=demo-db.internal"), [])


if __name__ == "__main__":
    unittest.main()
