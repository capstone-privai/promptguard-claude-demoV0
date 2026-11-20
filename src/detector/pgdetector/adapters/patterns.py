"""In-house rule set: a dependency-free voter next to the open-source scanners.

Prefix-anchored token formats are tried first; the generic ``key = value``
rule only fires where no specific rule already claimed the value.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from bisect import bisect_left
from pathlib import Path
from typing import Any, Mapping

from ..adapter import DetectorAdapter, RawFinding
from ..core import BENIGN_VARIABLES, pem_body_lines


# (rule_id, type, lower-case literals one of which every match contains, pattern
# with a ``value`` group). The literal check skips a full regex pass over large
# outputs that cannot match.
SPECIFIC_RULES = [
    ("jwt", "JWT", ("eyj",), re.compile(r"\b(?P<value>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")),
    ("github-token", "GITHUB_TOKEN", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"), re.compile(r"\b(?P<value>gh[pousr]_[A-Za-z0-9]{36,255})\b")),
    ("aws-access-key", "AWS_KEY", ("akia", "asia"), re.compile(r"\b(?P<value>(?:AKIA|ASIA)[A-Z0-9]{16})\b")),
    ("slack-token", "SLACK_TOKEN", ("xox", "pgdemo-slack-"), re.compile(r"\b(?P<value>xox[abposr]-[A-Za-z0-9-]{10,}|pgdemo-slack-[A-Za-z0-9-]{20,})")),
    ("stripe-key", "API_KEY", ("k_live_", "k_test_"), re.compile(r"\b(?P<value>[sr]k_(?:live|test)_[A-Za-z0-9_]{16,})")),
    ("bearer-token", "TOKEN", ("bearer",), re.compile(r"(?i)\bbearer[ \t]+(?P<value>[A-Za-z0-9._~+/=-]{16,})")),
    ("url-credential", "PASSWORD", ("://",), re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,30}://[^\s:/@]{1,128}:(?P<value>[^\s/@]{1,256})@")),
]
PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?P<body>.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)
# Key and value are matched separately so a non-secret key never swallows a
# nested assignment such as ``config: {password: ...}``.
ASSIGNMENT = re.compile(r"(?<![A-Za-z0-9_])(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,63})[\"']?[ \t]*(?::=|=>|[:=])[ \t]*[\"']?")
# A type annotation between the name and = (db_password: str = "...", DB_PASSWORD: Final = "..."): the value is
# after the =, not the type. ASSIGNMENT alone would take the type name for the value.
TYPED_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,63})[ \t]*:[ \t]*"
    r"(?P<annotation>[A-Za-z_][\w.]*(?:\[[^\]\n=]*\])?(?:[ \t]*\|[ \t]*[A-Za-z_][\w.]*(?:\[[^\]\n=]*\])?)*)"
    r"[ \t]*=(?![=>])[ \t]*[\"']?"
)
# The value of `name: <this>` with no = after it is a type, not a secret (db_password: Optional[str]).
TYPE_ONLY = re.compile(
    r"(?:Optional|List|Dict|Union|Final|ClassVar|Annotated|Literal|Sequence|Mapping|Tuple|Set|Type|Iterable)\[.*\]"
    r"|str|bytes|int|bool|float|Any|SecretStr|SecretBytes|Final"
)
# Every key key_type() accepts contains one of these. An assignment never spans
# lines, so only lines containing one are scanned.
SECRET_WORD = re.compile(r"(?i)pass|pw|secret|token|api")
VALUE = re.compile(r"[^\s\"'`,;]+")
# Values that only refer to or stand in for a secret.
PLACEHOLDER = re.compile(
    r"\[[A-Z][A-Z0-9_]*_\d+\]"                      # PromptGuard's own placeholders
    r"|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|<[^<>]*>|[*xX.]+"
    r"|(?:process\.env|os\.environ|import\.meta\.env)\b.*"
    r"|(?i:true|false|null|none|undefined|redacted)"
)
CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
KEY_PARTS = re.compile(r"[_.\-]+")
# ``token_url``, ``password_file`` ... name where a secret lives, not the secret.
NON_VALUE_SUFFIXES = {"url", "uri", "endpoint", "path", "file", "dir", "type", "name", "id", "length", "len", "count", "policy", "hint", "env"}
CLOSERS = {")": "(", "]": "[", "}": "{", ">": "<"}

# Basic authentication: the scheme, then base64 that decodes to user:pass. "Basic realm=" and prose are not values.
BASIC_AUTH = re.compile(r"(?i)\bbasic[ \t]+(?P<value>[A-Za-z0-9+/]{4,}={0,2})(?![A-Za-z0-9+/=])")
# A quoted SQL literal: ' or ", with the quote doubled ('') or a backslash escape inside.
SQL_LITERAL = r"(?P<quote>['\"])(?P<value>(?:(?P=quote)(?P=quote)|\\.|(?!(?P=quote))[^\\\n])*)(?P=quote)"
SQL_PASSWORD = [re.compile(rf"(?i){prefix}{SQL_LITERAL}") for prefix in (
    r"\bIDENTIFIED\s+(?:WITH\s+[`'\"]?[\w$]+[`'\"]?\s+)?BY\s+(?:PASSWORD\s+)?",   # MySQL CREATE/ALTER USER, GRANT
    r"\bWITH\b[^;\n'\"]*?\bPASSWORD\s+",                                            # PostgreSQL WITH [ENCRYPTED] PASSWORD
    r"\b(?:CREATE|ALTER)\s+(?:USER|ROLE)\b[^;\n]*?\bPASSWORD\s*=?\s*",               # ALTER ROLE x PASSWORD, PASSWORD = '...'
    r"\bSET\s+PASSWORD\b[^;\n]*?=\s*(?:PASSWORD\s*\(\s*)?",                         # MySQL SET PASSWORD ... = '...'
)]
SQL_MIN_LENGTH = 3  # SQL's own syntax is the context
# PG_RULE_HEX_KEY=on (default off): a 32-64 character hex value quoted next to a key name. Off by default because a
# git SHA or an md5 has the same shape; names that hold such digests are excluded.
HEX_KEY = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?[ \t]*(?::=|=>|[:=])[ \t]*"
    r"(?:[A-Za-z_][\w.]*\([ \t]*)?(?P<quote>[\"'`])(?P<value>[0-9a-fA-F]{32,64})(?P=quote)"
)
HEX_KEY_NAME = re.compile(r"key|(?:[a-z0-9]+[_.-])*(?:api|secret|access|consumer|private|signing|client|app|master|encryption)[_-]?key")
HEX_KEY_EXCLUDED = ("hash", "sha", "md5", "checksum", "digest", "etag", "commit", "rev", "cache", "primary", "foreign", "sort",
                    "partition", "idempotency", "object")


def basic_auth_value(value: str) -> bool:
    """base64 of user:pass: decodes strictly, to printable text with a ':' between two non-empty parts."""
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    user, colon, password = decoded.partition(":")
    return bool(colon and user and password) and decoded.isprintable()


def hex_key_name(key: str) -> bool:
    name = key.lower()
    return bool(HEX_KEY_NAME.fullmatch(name)) and not any(word in name for word in HEX_KEY_EXCLUDED)


def quoted_end(text: str, start: int, quote: str, limit: int) -> tuple[int, bool] | None:
    """The closing quote of a quoted value that starts at start, following backslash escapes, and whether it had one."""
    escaped = False
    at = start
    while at < limit:
        char = text[at]
        if char == "\\" and at + 1 < limit:
            escaped = True
            at += 2
            continue
        if char == quote:
            return at, escaped
        at += 1
    return None


def parameter_default(text: str, found: re.Match[str], value_end_at: int) -> bool:
    """def f(password: str = "x"): a typed name after ( or , or followed by , or ) is a parameter's default."""
    line_start = text.rfind("\n", 0, found.start("key")) + 1
    before = text[line_start:found.start("key")].rstrip()
    line_end = text.find("\n", value_end_at)
    after = text[value_end_at:len(text) if line_end < 0 else line_end].lstrip("\"' \t")
    return before.endswith(("(", ",")) or before.lstrip().startswith(("def ", "async def ")) or after.startswith((",", ")"))


def value_end(text: str, start: int, end: int) -> int:
    """Drop closing brackets that belong to the surrounding structure, e.g. ``{password: x}``."""
    while end > start and text[end - 1] in CLOSERS and CLOSERS[text[end - 1]] not in text[start:end - 1]:
        end -= 1
    return end


def key_type(key: str) -> str | None:
    if key.lower() in BENIGN_VARIABLES:
        return None
    parts = [part for part in KEY_PARTS.split(CAMEL.sub("_", key).lower()) if part]
    if not parts or parts[-1] in NON_VALUE_SUFFIXES:
        return None
    # pw is a password's short name (db_pw); pwd alone is the shell's working directory (pwd = os.getcwd()), so it
    # counts only joined to another word (MYSQL_PWD, db_pwd).
    if parts == ["pwd"]:
        return None
    if {"password", "passwd", "pwd", "pw", "pass", "passphrase"} & set(parts):
        return "PASSWORD"
    if "secret" in parts:
        return "SECRET"
    if "token" in parts:
        return "TOKEN"
    if "apikey" in parts or ("api" in parts and "key" in parts):
        return "API_KEY"
    return None


class Claimed:
    """Spans already taken by specific rules, with an O(log n) overlap test."""

    def __init__(self, findings: list[RawFinding]) -> None:
        spans = sorted((finding.start, finding.end) for finding in findings)
        self.starts = [start for start, _ in spans]
        # reach[i]: furthest end among the first i + 1 spans.
        self.reach = []
        for _, end in spans:
            self.reach.append(max(end, self.reach[-1]) if self.reach else end)

    def overlaps(self, start: int, end: int) -> bool:
        last = bisect_left(self.starts, end) - 1
        return last >= 0 and self.reach[last] > start


class PatternAdapter(DetectorAdapter):
    version = "0.1.0"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        self.min_value_length = int(options.get("min_value_length", 8))
        self.hex_key = os.environ.get("PG_RULE_HEX_KEY") == "on"

    def scan(self, text: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for block in PEM_BLOCK.finditer(text):
            findings.extend(
                RawFinding(start, end, "PRIVATE_KEY", "pem-private-key", "strong")
                for start, end in pem_body_lines(text, block.start("body"), block.end("body"))
            )
        lowered = text.lower()
        for rule_id, finding_type, literals, pattern in SPECIFIC_RULES:
            if not any(literal in lowered for literal in literals):
                continue
            for found in pattern.finditer(text):
                if self._plausible(found.group("value"), minimum=1):
                    findings.append(RawFinding(found.start("value"), found.end("value"), finding_type, rule_id, "strong"))
        findings.extend(self._extra_rules(text, lowered))
        claimed = Claimed(findings)
        for found in self._assignments(text):
            finding_type = key_type(found.group("key"))
            value = VALUE.match(text, found.end()) if finding_type else None
            if value is None:
                continue
            start, end = value.start(), value_end(text, *value.span())
            # A quoted value with a backslash escape (\" \' \\) runs to its real closing quote.
            opening = text[found.end() - 1] if found.end() > found.start() else ""
            if opening in "\"'" and text[found.end() - 1:found.end()] == opening and found.end() == start:
                line_end = text.find("\n", start)
                closing = quoted_end(text, start, opening, len(text) if line_end < 0 else line_end)
                if closing and closing[1]:
                    end = closing[0]
            typed = "annotation" in found.groupdict()
            if typed and parameter_default(text, found, end):
                continue
            if not typed and text[found.start("key"):found.end()].rstrip("\"' \t").endswith(":") and TYPE_ONLY.fullmatch(text[start:end]):
                continue  # name: Type, a declaration without a value
            if not self._plausible(text[start:end]):
                continue
            if claimed.overlaps(start, end):
                continue
            findings.append(RawFinding(start, end, finding_type, "secret-assignment", "moderate"))
        return findings

    def _extra_rules(self, text: str, lowered: str) -> list[RawFinding]:
        """basic-auth, sql-password and (PG_RULE_HEX_KEY=on) hex-key, each counted under its own rule id."""
        out: list[RawFinding] = []
        if "basic" in lowered:
            for found in BASIC_AUTH.finditer(text):
                if basic_auth_value(found.group("value")):
                    out.append(RawFinding(found.start("value"), found.end("value"), "PASSWORD", "basic-auth", "strong"))
        if "password" in lowered or "identified" in lowered:
            seen: set[tuple[int, int]] = set()
            for pattern in SQL_PASSWORD:
                for found in pattern.finditer(text):
                    span = found.span("value")
                    if span not in seen and self._plausible(found.group("value"), minimum=SQL_MIN_LENGTH):
                        seen.add(span)
                        out.append(RawFinding(*span, "PASSWORD", "sql-password", "strong"))
        if self.hex_key and "key" in lowered:
            for found in HEX_KEY.finditer(text):
                if hex_key_name(found.group("key")):
                    out.append(RawFinding(found.start("value"), found.end("value"), "API_KEY", "hex-key", "strong"))
        return out

    def _assignments(self, text: str):
        scanned_to = 0
        for word in SECRET_WORD.finditer(text):
            if word.start() < scanned_to:
                continue
            line_start = text.rfind("\n", 0, word.start()) + 1
            line_end = text.find("\n", word.end())
            scanned_to = len(text) if line_end < 0 else line_end
            typed = list(TYPED_ASSIGNMENT.finditer(text, line_start, scanned_to))
            typed_keys = {found.start("key") for found in typed}
            yield from typed
            yield from (found for found in ASSIGNMENT.finditer(text, line_start, scanned_to) if found.start("key") not in typed_keys)

    def _plausible(self, value: str, minimum: int | None = None) -> bool:
        return len(value) >= (self.min_value_length if minimum is None else minimum) and not PLACEHOLDER.fullmatch(value)
