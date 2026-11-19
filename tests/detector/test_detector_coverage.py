"""Detector coverage: values every adapter missed in promptguard-data's 668c2c1 CredData-trajectory miss analysis.

New rules each have their own rule_id (basic-auth, sql-password, hex-key) so they can be counted. Every rule has
cases it must catch and counter-cases it must leave. Values are synthetic and built here (hex from a seeded RNG,
private keys freshly generated); assertion messages print only case names and lengths.
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

from pgdetector.adapters.patterns import PatternAdapter  # noqa: E402
from pgdetector.adapters.shell_aware import ShellAwareAdapter  # noqa: E402

RNG = random.Random(20261119)


def hexval(length: int) -> str:
    return "".join(RNG.choice("0123456789abcdef") for _ in range(length))


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def rules(text: str, env: dict[str, str] | None = None) -> list[tuple[str, str]]:
    with mock.patch.dict(os.environ, env or {}):
        if not env:
            os.environ.pop("PG_RULE_HEX_KEY", None)
        adapter = PatternAdapter("promptguard-rules", {"min_value_length": 8}, ROOT)
        return [(text[f.start:f.end], f.rule_id) for f in adapter.scan(text)]


def shell(text: str) -> list[tuple[str, str]]:
    adapter = ShellAwareAdapter("shell-aware", {"min_value_length": 1}, ROOT)
    return [(text[f.start:f.end], f.rule_id) for f in adapter.scan(text)]


class BasicAuth(unittest.TestCase):
    CRED = b64("deploy:SYNTHbasicPass9x")

    def test_caught(self) -> None:
        for text in (f"Authorization: Basic {self.CRED}", f'{{"headers": {{"Authorization": "Basic {self.CRED}"}}}}',
                     f"curl -H 'authorization: basic {self.CRED}' https://example.test"):
            with self.subTest(case=text[:14]):
                self.assertIn((self.CRED, "basic-auth"), rules(text))

    def test_counter_cases(self) -> None:
        for text in ('WWW-Authenticate: Basic realm="api"', f"Authorization: Basic {b64('SYNTHnocolonvalue')}",
                     "Use Basic authentication for the admin API", "Authorization: Basic"):
            with self.subTest(case=text[:18]):
                self.assertEqual([f for f in rules(text) if f[1] == "basic-auth"], [])


class SqlPassword(unittest.TestCase):
    CASES = [
        ("CREATE USER 'app'@'%' IDENTIFIED BY 'SYNTHsqlPass9';", "SYNTHsqlPass9"),
        ("ALTER USER 'app'@'localhost' IDENTIFIED WITH mysql_native_password BY 'SYNTHnative9';", "SYNTHnative9"),
        ("CREATE ROLE app WITH LOGIN PASSWORD 'SYNTHpgRole9';", "SYNTHpgRole9"),
        ("ALTER ROLE reporting WITH ENCRYPTED PASSWORD 'SYNTHenc9';", "SYNTHenc9"),
        ("CREATE USER svc PASSWORD = 'SYNTHsnow9';", "SYNTHsnow9"),
        ("SET PASSWORD FOR 'app'@'%' = 'SYNTHset9';", "SYNTHset9"),
        ("grant all on db.* to app identified by 'abc';", "abc"),  # 3 characters: SQL is context enough
        ("ALTER USER app IDENTIFIED BY 'it''s SYNTH 9';", "it''s SYNTH 9"),  # SQL doubles a quote to escape it
    ]

    def test_caught(self) -> None:
        for text, value in self.CASES:
            with self.subTest(case=self.CASES.index((text, value))):
                self.assertIn((value, "sql-password"), rules(text))

    def test_counter_cases(self) -> None:
        for text in ("SELECT password FROM users WHERE id = 1;", "ALTER TABLE users ADD COLUMN password VARCHAR(64);",
                     "CREATE USER app IDENTIFIED BY 'ab';", "UPDATE users SET password = ? WHERE id = ?;",
                     "-- Password: 'tag'"):
            with self.subTest(case=text[:20]):
                self.assertEqual([f for f in rules(text) if f[1] == "sql-password"], [])


class EscapedQuotes(unittest.TestCase):
    def test_in_house_rules_follow_escapes_to_the_closing_quote(self) -> None:
        for text, value in (('password = "SYNTH\\"quoted\\"Pass9"', 'SYNTH\\"quoted\\"Pass9'),
                            ("secret: 'it\\'s-SYNTH-9x'", "it\\'s-SYNTH-9x"),
                            ('api_token = "a\\\\b-SYNTHx9q"', "a\\\\b-SYNTHx9q")):
            with self.subTest(length=len(value)):
                self.assertIn((value, "secret-assignment"), rules(text))

    def test_without_escapes_the_value_ends_as_before(self) -> None:
        self.assertIn(("SYNTHplainPass9", "secret-assignment"), rules('password = "SYNTHplainPass9", user = "x"'))

    def test_shell_aware_follows_escapes(self) -> None:
        for text, value in (('login("admin", "SYNTH\\"Pass\\"9x")', 'SYNTH\\"Pass\\"9x'),
                            ("set_password(user, 'SYNTH\\'s-9x')", "SYNTH\\'s-9x"),
                            ('child.sendline("SYNTH\\"send\\"9")', 'SYNTH\\"send\\"9')):
            with self.subTest(length=len(value)):
                self.assertIn(value, [v for v, _ in shell(f"expect 'Password:'\n{text}" if "sendline" in text else text)])


class TypedAssignment(unittest.TestCase):
    def test_caught(self) -> None:
        for text, value in (('db_password: str = "SYNTHtyped9x!"', "SYNTHtyped9x!"),
                            ('DB_PASSWORD: Final = "SYNTHfinal9x!"', "SYNTHfinal9x!"),
                            ('api_token: Optional[str] = "SYNTHopt9xq!"', "SYNTHopt9xq!"),
                            ("secret: str | None = 'SYNTHunion9x!'", "SYNTHunion9x!")):
            with self.subTest(case=text.split(":")[0]):
                found = [f for f in rules(text) if f[1] == "secret-assignment"]
                self.assertEqual(found, [(value, "secret-assignment")], "the value, not the type name")

    def test_counter_cases(self) -> None:
        for text in ('def connect(host, password: str = "SYNTHdefault9")', "def f(self, password: str = None):",
                     "    password: str = \"SYNTHparam9x\",", "password: str", "db_password: Optional[str]"):
            with self.subTest(case=text.strip()[:16]):
                self.assertEqual([f for f in rules(text) if f[1] == "secret-assignment"], [])


class ShortNames(unittest.TestCase):
    def test_caught(self) -> None:
        for text, value in (('pw = "SYNTHpwShort9"', "SYNTHpwShort9"), ("db_pw=SYNTHdbPw9x", "SYNTHdbPw9x"),
                            ('pass_word = "SYNTHpassWord9"', "SYNTHpassWord9"), ("MYSQL_PWD=SYNTHmysql9x", "SYNTHmysql9x"),
                            ("passwd: SYNTHpasswd9", "SYNTHpasswd9")):
            with self.subTest(case=text.split("=")[0].split(":")[0].strip()):
                self.assertIn((value, "secret-assignment"), rules(text))

    def test_counter_cases(self) -> None:
        for text in ("pwd = os.getcwd()", 'pwd = "/home/x/project"', 'cwd = "/home/x"', "pass = None"):
            with self.subTest(case=text[:6]):
                self.assertEqual([f for f in rules(text) if f[1] == "secret-assignment"], [])


class HexKey(unittest.TestCase):
    ON = {"PG_RULE_HEX_KEY": "on"}

    def cases(self) -> list[tuple[str, str]]:
        values = [hexval(n) for n in (32, 40, 64, 32, 48, 32, 40)]
        return [
            (f'api_key = "{values[0]}"', values[0]),
            (f'"consumer_key": "{values[1]}"', values[1]),
            (f"accesskey='{values[2]}'", values[2]),
            (f'\tKey: String("{values[3]}"),', values[3]),
            (f'SecretKey = "{values[4]}"', values[4]),
            (f'key: "{values[5]}"', values[5]),
            (f'STRIPE_SIGNING_KEY = "{values[6]}"', values[6]),
        ]

    def test_caught_when_on(self) -> None:
        for text, value in self.cases():
            with self.subTest(case=text.strip().split()[0][:16]):
                self.assertIn((value, "hex-key"), rules(text, self.ON))

    def test_off_by_default(self) -> None:
        for text, _ in self.cases():
            for env in (None, {"PG_RULE_HEX_KEY": "off"}):
                with self.subTest(case=text.strip().split()[0][:16], env=bool(env)):
                    self.assertEqual([f for f in rules(text, env) if f[1] == "hex-key"], [])

    def test_counter_cases(self) -> None:
        value = hexval(40)
        for text in (f"commit {value}\nAuthor: dev <dev@example.test>", f'cache_key = "{hexval(32)}"', f'etag: "{hexval(32)}"',
                     f'sha256_key = "{hexval(64)}"', f'object_key = "{hexval(32)}"', f'primary_key = "{hexval(32)}"',
                     f'idempotency_key: "{hexval(32)}"', f'api_key = "{hexval(31)}"', f'api_key = "{hexval(65)}"',
                     f'foo_key = "{hexval(32)}"', 'api_key = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"', f"api_key = {hexval(32)}"):
            with self.subTest(case=text.split()[0][:16]):
                self.assertEqual([f for f in rules(text, self.ON) if f[1] == "hex-key"], [])


class PemPadding(unittest.TestCase):
    """CredSweeper's base64 PEM span ends before the = padding; the adapter now covers it."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from pgdetector.adapters.credsweeper import CredSweeperAdapter
        except ImportError as exc:  # pragma: no cover - CredSweeper is pinned in requirements
            raise unittest.SkipTest(f"credsweeper not installed: {exc}") from None
        cls.adapter = CredSweeperAdapter("credsweeper", {"severity": "medium", "confidence": "moderate",
                                                         "extra_rules": ["pgdetector/adapters/credsweeper-rules.yaml"]}, ROOT / "src" / "detector")
        key = ec.generate_private_key(ec.SECP256R1())  # generated here, used nowhere else
        cls.pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()).decode()

    def test_span_covers_the_padding(self) -> None:
        for extra in range(3):
            encoded = base64.b64encode((self.pem + "x" * extra).encode()).decode()
            pad = len(encoded) - len(encoded.rstrip("="))
            text = f'key_b64 = "{encoded}"\n'
            with self.subTest(padding=pad):
                spans = [(f.start, f.end) for f in self.adapter.scan(text) if "PEM" in f.rule_id or "Private Key" in f.rule_id]
                start = text.index(encoded)
                self.assertIn((start, start + len(encoded)), spans)


if __name__ == "__main__":
    unittest.main()
