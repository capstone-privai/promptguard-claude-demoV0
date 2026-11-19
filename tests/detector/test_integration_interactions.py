"""Where the detector PRs meet (eval/integration-1118): #23's filters over #26's new rules, typed assignments and
escape-extended values. Only the in-house rules run, so the filters judge exactly what #26 found.
All values are synthetic and built at run time; messages print shapes and rule ids, never values.
"""

from __future__ import annotations

import base64
import os
import random
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector  # noqa: E402
from pgdetector.adapters.patterns import PatternAdapter  # noqa: E402

OFF = {"PG_DETECTOR_FILTERS": "off", "PG_DETECTOR_FILTER_DUMMY": "off", "PG_RULE_HEX_KEY": "off"}
ON = {"PG_DETECTOR_FILTERS": "on", "PG_DETECTOR_FILTER_DUMMY": "off", "PG_RULE_HEX_KEY": "on"}
ALL_ON = {"PG_DETECTOR_FILTERS": "on", "PG_DETECTOR_FILTER_DUMMY": "on", "PG_RULE_HEX_KEY": "on"}
HEX = "".join(random.Random(1118).choice("0123456789abcdef") for _ in range(40))
BASIC = base64.b64encode(b"synthuser:SynthPass9q").decode()


def scan(text: str, env: dict[str, str]) -> dict:
    with mock.patch.dict(os.environ, env):
        detector = Detector([PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT)], ConsensusPolicy.parse("any"), candidate_policy="union")
        return detector.scan(text, "outbound")


def covers(result: dict, text: str, value: str) -> bool:
    start = text.index(value)
    return any(f["start"] <= start and start + len(value) <= f["end"] for f in result["findings"])


class NewRulesUnderFilters(unittest.TestCase):
    """#26's basic-auth, sql-password and hex-key findings are not removed by #23's filters."""

    CASES = [
        ("basic-auth header", f"Authorization: Basic {BASIC}", BASIC),
        ("basic-auth quoted", f'headers = {{"Authorization": "Basic {BASIC}"}}', BASIC),
        ("sql-password identified by", "CREATE USER app_rw IDENTIFIED BY 'Synth.Sql9q';", "Synth.Sql9q"),
        ("sql-password with password", "ALTER ROLE app_ro WITH PASSWORD 'Q7z(S)x9';", "Q7z(S)x9"),
        ("sql-password set password", "SET PASSWORD FOR 'bob'@'%' = 'Syn<p>9q';", "Syn<p>9q"),
        ("hex-key Go String()", f'Key: String("{HEX}"),', HEX),
        ("hex-key assignment", f'api_key = "{HEX}"', HEX),
        ("hex-key bare key", f"key: '{HEX}'", HEX),
    ]

    def test_found_with_filters_on_and_with_the_dummy_filter(self) -> None:
        for name, text, value in self.CASES:
            for env in (ON, ALL_ON):
                with self.subTest(case=name, dummy=env["PG_DETECTOR_FILTER_DUMMY"]):
                    result = scan(text, env)
                    self.assertTrue(covers(result, text, value), f"{name}: filtered {result.get('filtered')}")

    def test_hex_key_only_with_its_switch(self) -> None:
        text = f'Key: String("{HEX}"),'
        self.assertFalse(covers(scan(text, {**ON, "PG_RULE_HEX_KEY": "off"}), text, HEX))
        self.assertTrue(covers(scan(text, ON), text, HEX))


class TypedAssignmentUnderFilters(unittest.TestCase):
    """#26 reads the value after a type annotation; #23's reference filter then judges that value."""

    def test_a_reference_is_filtered(self) -> None:
        for text in ("db_password: str = self.password", "API_TOKEN: Final = settings.API_TOKEN", "secret: str | None = config.secret"):
            with self.subTest(shape=text.split("=")[1].strip().split(".")[0]):
                on = scan(text, ON)
                self.assertEqual(on["finding_count"], 0)
                self.assertGreater(sum(on["filtered"].values()), 0, "removed by a filter, not missed by the rule")
                self.assertGreater(scan(text, OFF)["finding_count"], 0, "off: #26 alone reports it, so the filter is what removes it")

    def test_a_literal_is_found(self) -> None:
        for text, value in (('db_password: str = "Synth.Typed9q"', "Synth.Typed9q"), ("DB_PASSWORD: Final = 'Q7z!Typed2x'", "Q7z!Typed2x"),
                            ('api_token: Optional[str] = "SYNTHtypedTok9q"', "SYNTHtypedTok9q")):
            for env in (OFF, ON, ALL_ON):
                with self.subTest(filters=env["PG_DETECTOR_FILTERS"], dummy=env["PG_DETECTOR_FILTER_DUMMY"]):
                    self.assertTrue(covers(scan(text, env), text, value))


    def test_merge_order_lookup_default_before_parameter_default(self) -> None:
        # Step 2 (#23's lookup default) runs before step 3 (#26's typed parameter default), so the default literal of
        # a lookup is a candidate even as a parameter's default; a plain parameter default is not.
        text = 'def connect(password: str = os.getenv("DB_PASSWORD", "SynthDflt9q")):'
        plain = 'def connect(password: str = "SynthParam9q"):'
        for env in (OFF, ON, ALL_ON):
            with self.subTest(filters=env["PG_DETECTOR_FILTERS"], dummy=env["PG_DETECTOR_FILTER_DUMMY"]):
                self.assertTrue(covers(scan(text, env), text, "SynthDflt9q"))
                self.assertEqual(scan(plain, env)["finding_count"], 0)


class EscapedValuesUnderFilters(unittest.TestCase):
    """A value #26 extends over \\" \\' \\\\ is judged whole by #23's filters, not as code or HTML."""

    CASES = [
        ("call-like with an escaped argument", 'token = "get_token(\\"Q7x9zK\\")"', 'get_token(\\"Q7x9zK\\")'),
        ("index-like with an escaped key", "password = 'opts[\\'Q7x9zK\\']'", "opts[\\'Q7x9zK\\']"),
        ("HTML-like with an escaped quote", 'password = "<p>\\"Synth9q</p>"', '<p>\\"Synth9q</p>'),
        ("entity-like with a backslash", 'secret = "&lt;\\\\Synth9q&gt;"', "&lt;\\\\Synth9q&gt;"),
        ("apostrophe", "password = 'it\\'s-Synth9q'", "it\\'s-Synth9q"),
    ]

    def test_kept_whole(self) -> None:
        for name, text, value in self.CASES:
            for env in (OFF, ON, ALL_ON):
                with self.subTest(case=name, filters=env["PG_DETECTOR_FILTERS"], dummy=env["PG_DETECTOR_FILTER_DUMMY"]):
                    result = scan(text, env)
                    self.assertTrue(covers(result, text, value), f"{name}: filtered {result.get('filtered')}")
                    self.assertNotIn("code_fragment", result.get("filtered", {}))
                    self.assertNotIn("html_fragment", result.get("filtered", {}))


class PublicPrefixUnderFilters(unittest.TestCase):
    """main's public prefix (#21) x #23: with the filters on, an adapter's span over prefix + [TYPE_N] is removed
    as code (code_fragment), whatever the row's type. That text holds no raw value; a whole value is still found."""

    PREFIX = "_".join(["sk", "live", ""])

    def stub_scan(self, value: str, env: dict[str, str]) -> dict:
        from pgdetector import DetectorAdapter, RawFinding

        class Stub(DetectorAdapter):
            version = "test"

            def scan(self, text: str) -> list[RawFinding]:
                start = text.find(value)
                return [] if start < 0 else [RawFinding(start, start + len(value), "TOKEN", "stub", "strong", "stub", {})]

        with mock.patch.dict(os.environ, env):
            return Detector([Stub("stub", {}, ROOT)], ConsensusPolicy.parse("any"), candidate_policy="union").scan(f"API_KEY={value}", "outbound")

    def test_placeholder_text_is_removed_as_code(self) -> None:
        for placeholder in ("[STRIPE_SECRET_KEY_1]", "[GITHUB_TOKEN_1]"):
            for prefix_option in ("off", "on"):
                with self.subTest(placeholder=placeholder, public_prefix=prefix_option):
                    result = self.stub_scan(self.PREFIX + placeholder, {**ON, "PG_PLACEHOLDER_PUBLIC_PREFIX": prefix_option})
                    self.assertEqual((result["finding_count"], result["filtered"]), (0, {"code_fragment": 1}))

    def test_a_whole_value_is_still_found(self) -> None:
        for prefix_option in ("off", "on"):
            result = self.stub_scan(f"{self.PREFIX}SYNTHxFAKExVALUExONLYx0001", {**ALL_ON, "PG_PLACEHOLDER_PUBLIC_PREFIX": prefix_option})
            self.assertEqual(result["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()
