"""Detector filters (PG_DETECTOR_FILTERS, PG_DETECTOR_FILTER_DUMMY): values that cannot be secrets by structure.

One synthetic example per false-positive shape of promptguard-data's stage-0 fp_types.csv, the real-password
counter-examples that must pass, the high-confidence rules that are never filtered, and the secret-assignment
rule's own value checks. Messages print shapes and filter names, never values.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import ConsensusPolicy, Detector, DetectorAdapter, RawFinding  # noqa: E402
from pgdetector.adapters.patterns import PatternAdapter  # noqa: E402

# (fp_types.csv shape, synthetic value, filter that removes it with PG_DETECTOR_FILTERS=on, or None)
SHAPES = [
    ("short mixed value: HTML entities", "&lt;/p&gt;", "html_fragment"),
    ("short mixed value: HTML end tag", "</p>", "html_fragment"),
    ("short mixed value: HTML tags", "<pre><code>", "html_fragment"),
    ("short mixed value: entity", "&gt;", "html_fragment"),
    ("short mixed value: entity without semicolon", "&lt", "html_fragment"),
    ("short mixed value: numeric entity", "&#39;", "html_fragment"),
    ("code expression: call", "get_token()", "code_fragment"),
    ("code expression: open call", "function(", "code_fragment"),
    ("code expression: open index", "attributes[", "code_fragment"),
    ("code expression: method call", "os.getenv(", "code_fragment"),
    ("code expression: index", "options['password']", "code_fragment"),
    ("code expression: call with references", "get_config(name, self.region)", "code_fragment"),
    ("code expression: call with a string", 'os.getenv("API_KEY")', "code_fragment"),
    ("code expression: env name index", 'os.environ["DB_PASS"]', "code_fragment"),
    ("code expression: dotted key name", 'config.get("db.password")', "code_fragment"),
    ("code expression: key names", "settings.get('db-pass', 'API_KEY')", "code_fragment"),
    ("code expression: empty index", "items[]", "code_fragment"),
    ("CSS value: keyword", ":unset", "css_value"),
    ("CSS value: important", "!important", "css_value"),
    ("CSS value: length", "12px", "css_value"),
    ("CSS value: percent", "50%", "css_value"),
    ("CSS value: function", "rgba(0,0,0,0.5)", "css_value"),
    ("CSS value: custom property", "var(--main-color)", "css_value"),
    ("CSS value: calc", "calc(100% - 12px)", "css_value"),
    ("CSS value: url", "url(images/bg.png)", "css_value"),
    ("template: jinja", "{{ secrets.DEPLOY_KEY }}", "template"),
    ("template: jinja block", "{% raw %}", "template"),
    ("template: shell", "${DB_PASSWORD}", "template"),
    ("template: ruby", "#{api_token}", "template"),
    ("template: angle placeholder", "<db-password>", "template"),
    ("template: python format", "%(password)s", "template"),
    ("template: brace format", "{password}", "template"),
    ("template: PromptGuard placeholder", "[PASSWORD_1]", "template"),
    ("template: PromptGuard part marker", "[PASSWORD_1_PART]", "template"),
    # kept: shapes with no structural reason
    ("random-looking string (16+ chars)", "SYNTHx7Qk2mR9vL4wPz", None),
    ("short mixed value", "aB3$kL9q", None),
    ("word or identifier", "buildCacheDirectory", None),
    ("variable or attribute reference (other rules)", "self.password", None),
    ("digits only", "1700000000", None),
    ("hex digest", "9f86d081884c7d65a2f0", None),
    ("UUID", "123e4567-e89b-12d3-a456-426614174000", None),
    ("URL or path", "https://example.test/path", None),
    ("email address", "dev@example.test", None),
    ("JWT-like", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aCJ9.c3ludGhfc2ln", None),
    ("password hash", "$6$SYNTHsalt$SYNTHhashvalue", None),
]
# Explicit example and dummy values: only with PG_DETECTOR_FILTER_DUMMY=on.
# Placeholder shapes only. Weak default passwords (changeme) are real values to mask (labeling guide, decision 3).
DUMMIES = ["your_api_key_here", "your-password-here", "<password>", "<YOUR_TOKEN>", "<your-api-key>",
           "xxxxxxxx", "********", "REDACTED", "[redacted]", "placeholder", "replaceme", "replace_me", "insert_token_here"]
# Real passwords with look-alike characters: never filtered.
REAL = ["p@ss(w0rd", "Tr0ub&dor", "a<b>c!9", "password123", "Hello(World)1", "my&lt!pass9", "Secret[2024]x", "{SYNTH}9!q",
        "Summer2024.Pass", "x9#{q}Z", "Pa55word!", "letmein2026", "admin123", "qwerty!7",
        # found by review of #23: brackets that close but hold no code, and CSS look-alikes
        "Xk9(mZ!q#2)", "S3cr3t(!)", "Hunter(2)", "Summer[2024]", "Pass(12, 34)", "Key[0x1f]",
        "var(Xk9!q", "url(Xk9!q)", "calc(Xk9!)", "rgba(Xk9!)", "19951231s", "300ms", "12deg",
        # a quoted argument that is not a key name: a secret default, a secret key, a hex value
        'os.getenv("DB_PASS", "SYNTHx7Qk2m!pw")', "options['SYNTHx7Qk2m!pw']", 'String("9f8e7d6c5b4a39281706f5e4d3c2b1a0")',
        "cfg['deadbeefcafe']", 'get("abc123def")', "lookup('pass word')",
        # a lookup's default is a value, whatever its shape
        'os.getenv("DB_PASS", "changeme")', 'os.environ.get("ADMIN_PW", "admin")', 'config.get("db.password", "postgres")',
        # weak default passwords are values to mask, not placeholders (labeling guide, decision 3)
        "changeme", "CHANGEME", "change_me", "change-me", "changeit", "dummy"]


class Stub(DetectorAdapter):
    version = "test"

    def __init__(self, name: str, value: str, rule: str = "Password") -> None:
        super().__init__(name, {}, ROOT)
        self.value, self.rule = value, rule

    def scan(self, text: str) -> list[RawFinding]:
        start = text.find(self.value)
        return [] if start < 0 else [RawFinding(start, start + len(self.value), "PASSWORD", self.rule, "moderate")]


def scan(value: str, env: dict[str, str], adapter: str = "credsweeper", rule: str = "Password") -> dict:
    with mock.patch.dict(os.environ, env, clear=False):
        for name in ("PG_DETECTOR_FILTERS", "PG_DETECTOR_FILTER_DUMMY"):
            if name not in env:
                os.environ.pop(name, None)
        detector = Detector([Stub(adapter, value, rule)], ConsensusPolicy.parse("any"), candidate_policy="union")
        return detector.scan(f"password = {value}\n", "tool_result")


ON = {"PG_DETECTOR_FILTERS": "on"}
DUMMY = {"PG_DETECTOR_FILTER_DUMMY": "on"}


class Filters(unittest.TestCase):
    def test_each_shape(self) -> None:
        for shape, value, expected in SHAPES:
            with self.subTest(shape=shape):
                result = scan(value, ON)
                self.assertEqual(result["finding_count"], 0 if expected else 1)
                self.assertEqual(result.get("filtered", {}), {expected: 1} if expected else {})

    def test_off_changes_nothing(self) -> None:
        for shape, value, _ in SHAPES:
            with self.subTest(shape=shape):
                for env in ({}, {"PG_DETECTOR_FILTERS": "off"}):
                    result = scan(value, env)
                    self.assertEqual(result["finding_count"], 1)
                    self.assertNotIn("filtered", result)

    def test_dummy_values_only_with_their_own_switch(self) -> None:
        for value in DUMMIES:
            with self.subTest(length=len(value)):
                self.assertEqual(scan(value, ON)["finding_count"], 1, "dummy off")
                result = scan(value, {**ON, **DUMMY})
                self.assertEqual(result["finding_count"], 0)
                self.assertEqual(result["filtered"], {"dummy_value": 1})
                self.assertEqual(scan(value, DUMMY)["filtered"], {"dummy_value": 1}, "independent of PG_DETECTOR_FILTERS")

    def test_dummy_switch_does_not_turn_on_the_other_filters(self) -> None:
        self.assertEqual(scan("</p>", DUMMY)["finding_count"], 1)

    def test_real_passwords_with_look_alike_characters_pass(self) -> None:
        for value in REAL:
            with self.subTest(length=len(value)):
                result = scan(value, {**ON, **DUMMY})
                self.assertEqual(result["finding_count"], 1)
                self.assertEqual(result.get("filtered", {}), {})

    def test_high_confidence_rules_are_never_filtered(self) -> None:
        for adapter, rule in (("gitleaks", "private-key"), ("credsweeper", "Bearer Authorization"), ("promptguard-rules", "pem-private-key")):
            with self.subTest(rule=rule):
                self.assertEqual(scan("<pre><code>", {**ON, **DUMMY}, adapter, rule)["finding_count"], 1)
                self.assertEqual(scan("changeme", {**ON, **DUMMY}, adapter, rule)["finding_count"], 1)
        self.assertEqual(scan("<pre><code>", ON, "credsweeper", "private-key")["finding_count"], 0, "rule of another adapter")

    def test_counts_by_name_and_no_values_in_the_result(self) -> None:
        values = ["</p>", "&gt;", "get_token()"]
        with mock.patch.dict(os.environ, ON):
            detector = Detector([Stub("credsweeper", value) for value in values[:1]] + [Stub("gitleaks", values[1], "generic-api-key"), Stub("promptguard-rules", values[2], "secret-assignment")],
                                ConsensusPolicy.parse("any"), candidate_policy="union")
            result = detector.scan(" ".join(values), "tool_result")
        self.assertEqual(result["filtered"], {"html_fragment": 2, "code_fragment": 1})
        dumped = json.dumps(result)
        for value in values:
            self.assertNotIn(value, dumped)

    def test_filtered_ballots_are_what_collect_returns(self) -> None:
        with mock.patch.dict(os.environ, ON):
            detector = Detector([Stub("credsweeper", "</p>")], ConsensusPolicy.parse("any"), candidate_policy="union")
            ballots, errors = detector.collect(["password = </p>"])
        self.assertEqual(ballots[0]["credsweeper"], [])
        self.assertEqual(errors, [])


class Settings(unittest.TestCase):
    def test_describe_reports_the_setting_names_only(self) -> None:
        for env, expected in (({}, {"PG_DETECTOR_FILTERS": "off", "PG_DETECTOR_FILTER_DUMMY": "off"}),
                              ({**ON, **DUMMY}, {"PG_DETECTOR_FILTERS": "on", "PG_DETECTOR_FILTER_DUMMY": "on"})):
            with mock.patch.dict(os.environ, env):
                if not env:
                    os.environ.pop("PG_DETECTOR_FILTERS", None)
                    os.environ.pop("PG_DETECTOR_FILTER_DUMMY", None)
                detector = Detector([Stub("credsweeper", "x")], ConsensusPolicy.parse("any"), candidate_policy="union")
                self.assertEqual(detector.describe()["filter_settings"], expected)


class SecretAssignment(unittest.TestCase):
    """promptguard-rules secret-assignment: a value that is a reference, a call, code or a template is not a secret."""

    CODE = [
        "password = self.password",
        "db_password: config.db.password",
        "secret = settings.SECRET_KEY",
        "token = get_token()",
        "token = new_token_value()",
        "api_key = os.getenv(",
        "password = Credentials.load(",
        "api_token = request.headers[",
        "password={{vault_password}}",
        "secret_key = %(secret_key)s",
        # a template stays a template inside quotes
        'password = "{{vault_password}}"',
        "secret_key = '%(secret_key)s'",
        # a dotenv template is still a template
        "DB_PASSWORD={{vault_password}}",
    ]
    KEPT = [
        "password = p@ss(w0rd",
        "password = Tr0ub&dor",
        "password = Summer2024.Pass",
        "password = MyS3cret!(x)",
        "secret = SYNTHx7Qk2mR9vL4wPz",
        # a quoted value is a string literal, not a reference or code
        'master_key_password = "Admin.Master.Key"',
        "secret = 'alpha.bravo.charlie'",
        'token = "get_token()"',
        "api_key = 'settings.SECRET_KEY'",
        "password = Hunter(2)",
        "password = Xk9(mZ!q#2)",
        # a dotenv value (upper-case key, = with no spaces) is a literal even unquoted
        "DB_PASSWORD=alpha.bravo.charlie",
        "export API_TOKEN=Admin.Master.Key",
        # three dotted parts alone do not make a reference
        "password = alpha.bravo.charlie",
        # a secret default inside a call is a literal, not a key name
        'token = get_value("SYNTHx7Qk2m!pw")',
    ]

    def found(self, text: str, env: dict[str, str]) -> int:
        with mock.patch.dict(os.environ, env):
            if "PG_DETECTOR_FILTERS" not in env:
                os.environ.pop("PG_DETECTOR_FILTERS", None)
            return len([f for f in PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT).scan(text) if f.rule_id == "secret-assignment"])

    def test_code_values_are_skipped_when_on(self) -> None:
        for text in self.CODE:
            with self.subTest(case=self.CODE.index(text)):
                self.assertEqual(self.found(text, {}), 1, "off: found as today")
                self.assertEqual(self.found(text, ON), 0)

    def test_declined_values_are_counted_by_reason(self) -> None:
        with mock.patch.dict(os.environ, ON):
            detector = Detector([PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT)], ConsensusPolicy.parse("any"), candidate_policy="union")
            result = detector.scan("\n".join(self.CODE), "tool_result")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["filtered"], {"assignment_code": 5, "assignment_reference": 3, "assignment_template": 5})

    def test_real_values_are_still_found(self) -> None:
        for text in self.KEPT:
            with self.subTest(case=self.KEPT.index(text)):
                self.assertEqual(self.found(text, ON), 1)


class DefaultValues(unittest.TestCase):
    """secret-assignment reports a quoted default of an env or config lookup, with the filters off and on.

    This widens detection, apart from the filters: os.environ.get(..., "...") was not found at all before.
    """

    SECRET = "SYNTHx7Qk2m!pw"
    FORMS = [
        'password = os.getenv("DB_PASS", "{v}")',
        "password = os.environ.get('DB_PASS', '{v}')",
        'const password = process.env.DB_PASS || "{v}"',
        "const token = process.env.API_TOKEN ?? '{v}'",
        'password = config.get("db.password", "{v}")',
        'db_password=os.getenv("DB_PASS","{v}")',
    ]

    # A default is a value, whatever its shape: weak and short defaults are candidates too.
    WEAK = [
        ('password = os.getenv("DB_PASS", "changeme")', "changeme"),
        ('db_password = os.getenv("DB_PASSWORD", "postgres")', "postgres"),
        ('admin_password = os.environ.get("ADMIN_PW", "admin")', "admin"),
        ('const password = process.env.PW || "default"', "default"),
        ('password = config.get("db.password", "x9")', "x9"),
        ('password = os.getenv("DB_PASS", "DEFAULT_PASS")', "DEFAULT_PASS"),
    ]

    def values(self, text: str, env: dict[str, str]) -> list[str]:
        with mock.patch.dict(os.environ, env):
            for name in ("PG_DETECTOR_FILTERS", "PG_DETECTOR_FILTER_DUMMY"):
                if name not in env:
                    os.environ.pop(name, None)
            adapter = PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT)
            return [text[f.start:f.end] for f in adapter.scan(text) if f.rule_id == "secret-assignment"]

    def test_the_default_is_a_candidate(self) -> None:
        for form in self.FORMS:
            text = form.format(v=self.SECRET)
            for env in ({}, ON):
                with self.subTest(case=self.FORMS.index(form), filters=bool(env)):
                    self.assertIn(self.SECRET, self.values(text, env))

    def test_only_the_default_with_filters_on_or_off(self) -> None:
        text = self.FORMS[0].format(v=self.SECRET)
        for env in ({}, ON):
            with self.subTest(filters=bool(env)):
                self.assertEqual(self.values(text, env), [self.SECRET], "no separate os.getenv( span")

    def test_a_weak_or_short_default_is_a_candidate(self) -> None:
        for text, default in self.WEAK:
            for env in ({}, ON, {**ON, **DUMMY}):
                with self.subTest(case=self.WEAK.index((text, default)), env=sorted(env)):
                    self.assertEqual(self.values(text, env), [default])

    def test_exceptions_are_not_candidates(self) -> None:
        for default in ("", "None", "null", "undefined", "${DB_PASS}"):
            for env in ({}, ON):
                with self.subTest(default=default, filters=bool(env)):
                    self.assertNotIn(default, self.values(f'password = os.getenv("DB_PASS", "{default}")', env))

    def test_a_placeholder_default_only_with_the_dummy_filter_on(self) -> None:
        for default in ("<password>", "your_api_key_here", "xxxxxxxx"):
            with self.subTest(length=len(default)):
                text = f'password = os.getenv("DB_PASS", "{default}")'
                self.assertIn(default, self.values(text, ON))
                self.assertNotIn(default, self.values(text, {**ON, **DUMMY}))

    def test_the_key_argument_must_be_a_key_name(self) -> None:
        # Not a lookup when its first argument is not a key: no default candidate from it.
        self.assertNotIn("abcdefgh9", self.values('password = os.getenv("Xk9!q#2", "abcdefgh9")', ON))


if __name__ == "__main__":
    unittest.main()
