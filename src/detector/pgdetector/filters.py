"""Filters for findings whose value cannot be a secret by its structure (PG_DETECTOR_FILTERS, PG_DETECTOR_FILTER_DUMMY).

The ensemble applies them to every adapter's findings before voting and merging (Detector.collect), in the one
pgdetector process the Native Mod and the Final Guard each run, so both judge a text the same way. Length alone is
never a reason: each filter names a structure, and a value with any character outside that structure passes.

From promptguard-data's stage-0 false-positive analysis (metric-detection/results/stage0_fp_20261115): the real-traffic
false positives were mostly the secret-assignment rule on references and code, and CredData's re-masks were HTML and
code fragments (&lt;, </p>, function(, attributes[, :unset) found once and re-masked at every repeat.

- html_fragment  HTML entities and tags of known HTML elements, with at most letters, spaces and / between them
- code_fragment  a call or index of an identifier: get_token(), function(, attributes[, options['x']
- css_value      CSS keywords, lengths and functions: :unset, !important, 12px, rgba(
- template       {{ }}, {% %}, ${ }, #{ }, <db-password>, %(name)s, {name}, and PromptGuard's own [TYPE_N]
- dummy_value    (PG_DETECTOR_FILTER_DUMMY=on, separately) an exact list of example values (changeme, <password>) and
                 the explicit forms your_*_here, <your-*>, xxx, ***; never a common real password such as password123

Findings of a high-confidence rule (src/detector/high-confidence-rules.json, shared with the Native Mod) are never
filtered. Only the count per filter name is reported; no value is kept.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Callable, Sequence

from .adapter import RawFinding

RULES_FILE = Path(__file__).resolve().parents[1] / "high-confidence-rules.json"

_HTML_ELEMENTS = (
    "a|abbr|article|aside|b|blockquote|body|br|button|caption|code|col|dd|div|dl|dt|em|footer|form|h[1-6]|head|header|"
    "hr|html|i|iframe|img|input|label|li|link|main|meta|nav|ol|option|p|pre|script|section|select|small|span|strong|"
    "style|sub|sup|svg|table|tbody|td|textarea|tfoot|th|thead|title|tr|u|ul"
)
_ENTITY = r"&(?:lt|gt|amp|quot|apos|nbsp|#\d{1,7}|#x[0-9a-fA-F]{1,6})(?![A-Za-z0-9]);?"
_TAG = rf"</?(?:{_HTML_ELEMENTS})(?:\s[^<>]*)?/?>"
_HTML_PIECE = re.compile(rf"{_ENTITY}|{_TAG}", re.I)
_HTML_REST = re.compile(r"[A-Za-z/\s]*")

_IDENT = r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*"
_CODE = re.compile(rf"{_IDENT}(?:\((?:[^()]*\))?|\[(?:[^\[\]]*\])?)")
_CSS = re.compile(
    r"(?i)(?::{1,2}(?:unset|inherit|initial|revert|revert-layer|hover|focus|active|before|after|root|not|nth-child)\b.*"
    r"|!important|-?\d*\.?\d+(?:px|em|rem|vh|vw|vmin|vmax|pt|pc|cm|mm|ch|ex|deg|s|ms)"
    r"|(?:rgba?|hsla?|var|calc|url|linear-gradient)\(.*)"
)
_TEMPLATE = re.compile(
    r"\{\{.*\}\}|\{%.*%\}|\$\{.*\}|#\{.*\}|%\([A-Za-z_]\w*\)[sdr]|\{[A-Za-z_][\w.]*\}"
    r"|<(?![Yy][Oo][Uu][Rr][-_ ])[A-Za-z][\w]*(?:[-_ ][\w]+)+>|\[[A-Z][A-Z0-9_]*_\d+(?:_PART)?\]"
)
_DUMMY_EXACT = {
    "changeme", "change_me", "change-me", "changeit", "replaceme", "replace_me", "replace-me", "placeholder",
    "dummy", "redacted", "[redacted]", "<redacted>", "<password>", "<secret>", "<token>", "<api_key>", "<apikey>",
    "<key>", "your_password", "yourpassword", "your_token", "your_secret", "your_api_key", "your-api-key",
}
_DUMMY_PATTERN = re.compile(
    r"(?i)your[-_][a-z0-9_-]*[-_]here|(?:insert|enter|put)[-_][a-z0-9_-]+[-_]here|<your[-_ ][^<>]+>|x{3,}|\*{3,}"
)


def _value(raw: str) -> str:
    return raw.strip().strip("\"'`")


def html_fragment(value: str) -> bool:
    pieces = list(_HTML_PIECE.finditer(value))
    if not pieces:
        return False
    rest = _HTML_PIECE.sub("", value)
    return bool(_HTML_REST.fullmatch(rest))


def code_fragment(value: str) -> bool:
    return bool(_CODE.fullmatch(value))


def css_value(value: str) -> bool:
    return bool(_CSS.fullmatch(value))


def template(value: str) -> bool:
    return bool(_TEMPLATE.fullmatch(value))


def dummy_value(value: str) -> bool:
    return value.lower() in _DUMMY_EXACT or bool(_DUMMY_PATTERN.fullmatch(value))


STRUCTURE: list[tuple[str, Callable[[str], bool]]] = [
    # css before code: rgba(0,0,0,0.5) is a CSS value, not a call to keep.
    ("html_fragment", html_fragment), ("css_value", css_value), ("template", template), ("code_fragment", code_fragment),
]


def high_confidence_rules(path: Path = RULES_FILE) -> set[tuple[str, str]]:
    config = json.loads(path.read_text(encoding="utf-8"))
    return {(rule["adapter"], rule["rule_id"]) for rule in config["high_confidence_rules"]}


class Filters:
    """The filters PG_DETECTOR_FILTERS and PG_DETECTOR_FILTER_DUMMY turn on (both default off)."""

    def __init__(self, structure: bool, dummy: bool, keep: set[tuple[str, str]]) -> None:
        self.checks = (STRUCTURE if structure else []) + ([("dummy_value", dummy_value)] if dummy else [])
        self.keep = keep

    @classmethod
    def from_env(cls) -> "Filters | None":
        structure = os.environ.get("PG_DETECTOR_FILTERS") == "on"
        dummy = os.environ.get("PG_DETECTOR_FILTER_DUMMY") == "on"
        if not (structure or dummy):
            return None
        return cls(structure, dummy, high_confidence_rules())

    def describe(self) -> dict[str, object]:
        return {"filters": [name for name, _ in self.checks]}

    def reason(self, adapter: str, finding: RawFinding, text: str) -> str | None:
        if (adapter, finding.rule_id) in self.keep or not (0 <= finding.start < finding.end <= len(text)):
            return None  # invalid offsets are left to accept(), which reports them
        value = _value(text[finding.start:finding.end])
        return next((name for name, check in self.checks if check(value)), None)

    def apply(self, adapter: str, findings: Sequence[RawFinding], text: str, counts: Counter) -> list[RawFinding]:
        kept = []
        for finding in findings:
            name = self.reason(adapter, finding, text)
            if name is None:
                kept.append(finding)
            else:
                counts[name] += 1
        return kept


# For the secret-assignment rule: a value that only refers to something, calls or indexes code, or is a template.
_RECEIVERS = {
    "self", "this", "cls", "config", "conf", "cfg", "settings", "options", "opts", "args", "kwargs", "params", "props",
    "ctx", "context", "env", "os", "process", "request", "req", "res", "response", "app", "data", "user", "credentials",
    "creds", "secrets", "vars", "inputs", "values", "obj", "form", "payload", "body", "auth", "session", "window",
}
_SECRET_WORDS = re.compile(r"(?i)(?:password|passwd|pwd|secret|token|api_?key|apikey|credentials?|auth\w*|key)$")
_DOTTED = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+")


def reference(value: str) -> bool:
    """self.password, config.db.password, settings.SECRET_KEY: an attribute chain, not a literal."""
    if not _DOTTED.fullmatch(value):
        return False
    parts = value.split(".")
    return parts[0] in _RECEIVERS or len(parts) >= 3 or bool(_SECRET_WORDS.search(parts[-1]))


def assignment_value_is_code(raw: str) -> str | None:
    """The reason secret-assignment declines a value (a filter count name), or None for a value it keeps."""
    value = _value(raw)
    if reference(value):
        return "assignment_reference"
    if template(value):
        return "assignment_template"
    if code_fragment(value):
        return "assignment_code"
    return None
