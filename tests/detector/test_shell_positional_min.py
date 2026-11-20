"""PG_SHELL_POSITIONAL_MIN: shell-aware's positional function_argument values shorter than it are not reported.

The CredData-trajectory test (668c2c1) had CreateOrUpdateEnvSecret(ctx, 1, "e", input) report "e", which the Native
Mod then re-masked across every output. Keyword arguments and command-flag rules keep min_value_length (1).
Values are synthetic; messages print only cases and lengths.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector.adapters.shell_aware import ShellAwareAdapter  # noqa: E402


def found(text: str, env: dict[str, str]) -> list[tuple[str, str]]:
    with mock.patch.dict(os.environ, env):
        if "PG_SHELL_POSITIONAL_MIN" not in env:
            os.environ.pop("PG_SHELL_POSITIONAL_MIN", None)
        adapter = ShellAwareAdapter("shell-aware", {"min_value_length": 1}, ROOT)
        return [(text[f.start:f.end], f.rule_id) for f in adapter.scan(text)]


MIN4 = {"PG_SHELL_POSITIONAL_MIN": "4"}
# 4 is the default since release/defaults-1120; 1 is the earlier behaviour.
MIN1 = {"PG_SHELL_POSITIONAL_MIN": "1"}


class PositionalMinimum(unittest.TestCase):
    def test_short_positional_literal_is_dropped_at_4(self) -> None:
        for text, value in (('CreateOrUpdateEnvSecret(ctx, 1, "e", input)', "e"), ("login('admin', 'mgb')", "mgb")):
            with self.subTest(length=len(value)):
                self.assertIn((value, "shell-function_argument"), found(text, MIN1), "1: found as before")
                self.assertEqual([f for f in found(text, MIN4) if f[1] == "shell-function_argument"], [])
                self.assertEqual(found(text, {}), found(text, MIN4), "4 by default")
                self.assertEqual(found(text, {"PG_SHELL_POSITIONAL_MIN": ""}), found(text, MIN4), "empty is the default")

    def test_positional_literal_of_4_or_more_is_kept(self) -> None:
        for text, value in (("login('admin', 'mgb4')", "mgb4"), ("set_password(user, 'SynthPass_16X')", "SynthPass_16X")):
            with self.subTest(length=len(value)):
                self.assertIn((value, "shell-function_argument"), found(text, MIN4))

    def test_keyword_arguments_and_command_flags_are_unchanged(self) -> None:
        for text in ('connect(host, password="e")', "db.login(user='x', passwd='ab')", "sshpass -p e ssh deploy@host",
                     "mysql -u root -pab db", "curl --password e https://example.test"):
            with self.subTest(case=text.split("(")[0].split(" ")[0]):
                self.assertEqual(found(text, MIN4), found(text, MIN1))

    def test_bad_values_fall_back_to_1(self) -> None:
        for value in ("zero", "-3", "0"):
            with self.subTest(setting=value):
                self.assertIn(("e", "shell-function_argument"), found('CreateOrUpdateEnvSecret(ctx, 1, "e", input)', {"PG_SHELL_POSITIONAL_MIN": value}))


if __name__ == "__main__":
    unittest.main()
