"""In-house rule set: a dependency-free voter next to the open-source scanners.

Prefix-anchored token formats are tried first; the generic ``key = value``
rule only fires where no specific rule already claimed the value.
"""

from __future__ import annotations

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
# Every key key_type() accepts contains one of these. An assignment never spans
# lines, so only lines containing one are scanned.
SECRET_WORD = re.compile(r"(?i)pass|pwd|secret|token|api")
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
    if {"password", "passwd", "pwd", "pass", "passphrase"} & set(parts):
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
        claimed = Claimed(findings)
        for found in self._assignments(text):
            finding_type = key_type(found.group("key"))
            value = VALUE.match(text, found.end()) if finding_type else None
            if value is None:
                continue
            start, end = value.start(), value_end(text, *value.span())
            if not self._plausible(text[start:end]):
                continue
            if claimed.overlaps(start, end):
                continue
            findings.append(RawFinding(start, end, finding_type, "secret-assignment", "moderate"))
        return findings

    def _assignments(self, text: str):
        scanned_to = 0
        for word in SECRET_WORD.finditer(text):
            if word.start() < scanned_to:
                continue
            line_start = text.rfind("\n", 0, word.start()) + 1
            line_end = text.find("\n", word.end())
            scanned_to = len(text) if line_end < 0 else line_end
            yield from ASSIGNMENT.finditer(text, line_start, scanned_to)

    def _plausible(self, value: str, minimum: int | None = None) -> bool:
        return len(value) >= (self.min_value_length if minimum is None else minimum) and not PLACEHOLDER.fullmatch(value)
