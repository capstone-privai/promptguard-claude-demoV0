"""Filters for findings whose value cannot be a secret by its structure (PG_DETECTOR_FILTERS, PG_DETECTOR_FILTER_DUMMY).

The ensemble applies them to every adapter's findings before voting and merging (Detector.collect), in the one
pgdetector process the Native Mod and the Final Guard each run, so both judge a text the same way. Length alone is
never a reason: each filter names a structure, and a value with any character outside that structure passes.

From promptguard-data's stage-0 false-positive analysis (metric-detection/results/stage0_fp_20261115): the real-traffic
false positives were mostly the secret-assignment rule on references and code, and CredData's re-masks were HTML and
code fragments (&lt;, </p>, function(, attributes[, :unset) found once and re-masked at every repeat.

- html_fragment  HTML entities and tags of known HTML elements, with at most letters, spaces and / between them
- code_fragment  an open call or index of an identifier (function(, attributes[), or a closed one holding only
                 identifiers, attribute references and string literals (get_token(), options['x'])
- css_value      CSS keywords, px/em/rem/vh/vw/% lengths, and closed CSS functions holding CSS values (var(--x))
- template       {{ }}, {% %}, ${ }, #{ }, <db-password>, %(name)s, {name}, and PromptGuard's own [TYPE_N], also
                 behind a public prefix of docs/PLACEHOLDER_PUBLIC_PREFIXES.md (sk_live_[TOKEN_1])
- dummy_value    (PG_DETECTOR_FILTER_DUMMY=on, separately) placeholder shapes only: an exact list (<password>,
                 replace_me, placeholder) and the forms your_*_here, <your-*>, xxx, ***; never a weak default or common
                 real password such as changeme or password123

Findings of a high-confidence rule (src/detector/high-confidence-rules.json, shared with the Native Mod) are never
filtered. Only the count per filter name is reported; no value is kept.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Callable, Sequence

from . import settings
from .adapter import RawFinding

PUBLIC_PREFIX_TABLE = Path(__file__).resolve().parents[3] / "docs" / "PLACEHOLDER_PUBLIC_PREFIXES.md"
PUBLIC_PREFIX_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([A-Z][A-Z0-9_]*)\s*\|", re.M)

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
# A key name: an environment variable name, or lower-case words without digits joined by . _ -. A hex string of 8
# or more characters is a value even when it is all letters (deadbeefcafe).
_KEY_NAME = r"(?:[A-Z_][A-Z0-9_]*|[a-z]+(?:[._-][a-z]+)*)"
_NOT_HEX = r"(?![0-9a-fA-F]{8,}[\"'])"
_STRING = rf"\"{_NOT_HEX}{_KEY_NAME}\"|'{_NOT_HEX}{_KEY_NAME}'"
# Inside a closed call or index only code may stand: nothing, identifiers and attribute references, quoted key names,
# and comma lists of them. Hunter(2) and Summer[2024] hold a number, which code and a password share, and a quoted
# argument that is not a key name (os.getenv("DB_PASS", "<secret>"), options['<secret>']) may be the secret itself.
_ARGS = rf"\s*(?:(?:{_IDENT}|{_STRING})(?:\s*,\s*(?:{_IDENT}|{_STRING}))*)?\s*"
_CODE = re.compile(rf"{_IDENT}(?:\(|\[|\({_ARGS}\)|\[{_ARGS}\])")
# A call or index that closes on its line, with any arguments: secret-assignment judges it whole.
CLOSED_CALL = re.compile(rf"{_IDENT}(?:\([^()\n]*\)|\[[^\[\]\n]*\])")
_CSS_NUMBER = r"-?(?:\d+(?:\.\d+)?|\.\d+)"
_CSS_LENGTH = rf"{_CSS_NUMBER}(?:px|em|rem|vh|vw|%)"
_CSS_TERM = rf"(?:{_CSS_LENGTH}|{_CSS_NUMBER}|var\(\s*--[A-Za-z0-9_-]+\s*\))"
_CSS_CHANNEL = rf"{_CSS_NUMBER}(?:%|deg)?"
# A CSS function counts only closed and holding a CSS value: var(Xk9!q and url(Xk9!q) pass. Lengths use only px,
# em, rem, vh, vw and %; 19951231s or 300ms read as times and pass.
_CSS = re.compile(
    r":{1,2}(?:unset|inherit|initial|revert|revert-layer|hover|focus|active|before|after|root|first-child|last-child)"
    rf"|!important|{_CSS_LENGTH}"
    r"|var\(\s*--[A-Za-z0-9_-]+\s*(?:,\s*[^()]*)?\)"
    rf"|(?:rgba?|hsla?)\(\s*{_CSS_CHANNEL}(?:\s*[,/ ]\s*{_CSS_CHANNEL}){{2,3}}\s*\)"
    rf"|calc\(\s*{_CSS_TERM}(?:\s*[-+*/]\s*{_CSS_TERM})*\s*\)"
    r"|url\(\s*(?:\"[^\"]*\"|'[^']*'|[A-Za-z0-9_./:#?=&%~-]+)\s*\)"
)
_TEMPLATE = re.compile(
    r"\{\{.*\}\}|\{%.*%\}|\$\{.*\}|#\{.*\}|%\([A-Za-z_]\w*\)[sdr]|\{[A-Za-z_][\w.]*\}"
    r"|<(?![Yy][Oo][Uu][Rr][-_ ])[A-Za-z][\w]*(?:[-_ ][\w]+)+>|\[[A-Z][A-Z0-9_]*_\d+(?:_PART)?\]"
)
_DUMMY_EXACT = {
    # Placeholder shapes only. Weak default passwords (changeme, change_me, changeit, dummy) are real values to
    # mask: promptguard-data's labeling guide, decision 3.
    "replaceme", "replace_me", "replace-me", "placeholder",
    "redacted", "[redacted]", "<redacted>", "<password>", "<secret>", "<token>", "<api_key>", "<apikey>",
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
    # A lookup's default is a value even when shaped like a key name (os.getenv("DB_PASS", "changeme")).
    lookup = _LOOKUP.fullmatch(value)
    if lookup and lookup_key(lookup.group("key")) and lookup_default_is_value(lookup.group("default")):
        return False
    return bool(_CODE.fullmatch(value))


def css_value(value: str) -> bool:
    return bool(_CSS.fullmatch(value))


def template(value: str) -> bool:
    return bool(_TEMPLATE.fullmatch(value))


def public_prefix_rows(path: Path = PUBLIC_PREFIX_TABLE) -> list[tuple[str, str]]:
    """(prefix, type) rows of docs/PLACEHOLDER_PUBLIC_PREFIXES.md; none when the table cannot be read."""
    try:
        return PUBLIC_PREFIX_ROW.findall(path.read_text(encoding="utf-8"))
    except OSError:
        return []


_public_placeholder: re.Pattern[str] | None = None


def public_placeholder(value: str) -> bool:
    """A public prefix of the table followed by a placeholder of any type (sk_live_[TOKEN_1]): what the Native Mod
    writes with PG_PLACEHOLDER_PUBLIC_PREFIX=on, or what a model writes around a placeholder. Read whatever that
    setting is. Before release/defaults-1120 the structure filter removed it as code_fragment (an open index); it is
    removed the same, now counted as template. Only the structure filter asks: template() itself, which
    secret-assignment also uses, is unchanged."""
    global _public_placeholder
    if _public_placeholder is None:
        prefixes = "|".join(re.escape(prefix) for prefix in sorted({p for p, _ in public_prefix_rows()}, key=len, reverse=True))
        _public_placeholder = re.compile(rf"(?:{prefixes})\[[A-Z][A-Z0-9_]*_\d+(?:_PART)?\]" if prefixes else r"(?!)")
    return bool(_public_placeholder.fullmatch(value))


def template_or_public_placeholder(value: str) -> bool:
    return template(value) or public_placeholder(value)


def dummy_value(value: str) -> bool:
    return value.lower() in _DUMMY_EXACT or bool(_DUMMY_PATTERN.fullmatch(value))


STRUCTURE: list[tuple[str, Callable[[str], bool]]] = [
    # css before code: rgba(0,0,0,0.5) is a CSS value, not a call to keep.
    ("html_fragment", html_fragment), ("css_value", css_value), ("template", template_or_public_placeholder),
    ("code_fragment", code_fragment),
]


SETTINGS = ("PG_DETECTOR_FILTERS", "PG_DETECTOR_FILTER_DUMMY")


def filter_settings() -> dict[str, str]:
    """The two settings as on or off, for describe(): the supervisor compares the Mod's and the Guard's workers."""
    return {name: "on" if settings.enabled(name) else "off" for name in SETTINGS}


def high_confidence_rules(path: Path = RULES_FILE) -> set[tuple[str, str]]:
    config = json.loads(path.read_text(encoding="utf-8"))
    return {(rule["adapter"], rule["rule_id"]) for rule in config["high_confidence_rules"]}


class Filters:
    """The filters PG_DETECTOR_FILTERS (default on) and PG_DETECTOR_FILTER_DUMMY (default off) turn on."""

    def __init__(self, structure: bool, dummy: bool, keep: set[tuple[str, str]]) -> None:
        self.checks = (STRUCTURE if structure else []) + ([("dummy_value", dummy_value)] if dummy else [])
        self.keep = keep

    @classmethod
    def from_env(cls) -> "Filters | None":
        structure = settings.enabled("PG_DETECTOR_FILTERS")
        dummy = settings.enabled("PG_DETECTOR_FILTER_DUMMY")
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
    """self.password, config.db.password, settings.SECRET_KEY: an attribute chain, not a literal.

    Only a known receiver first or a secret word last makes one; three dotted parts alone (alpha.bravo.charlie)
    may be a passphrase.
    """
    if not _DOTTED.fullmatch(value):
        return False
    parts = value.split(".")
    return parts[0] in _RECEIVERS or bool(_SECRET_WORDS.search(parts[-1]))



def key_name(value: str) -> bool:
    """An environment variable name or dotted lower-case words, not a value: DB_PASS, db.password."""
    return bool(re.fullmatch(_KEY_NAME, value)) and not re.fullmatch(r"[0-9a-fA-F]{8,}", value)


# An env or config lookup with a quoted default. Only the first argument is a key; the second is a value.
_LOOKUP = re.compile(
    rf"(?:os\.getenv|os\.environ\.get|config\.get)\(\s*(?P<key>\"[^\"\n]*\"|'[^'\n]*'|{_IDENT})\s*,\s*"
    r"(?:default\s*=\s*)?(?P<quote>[\"'])(?P<default>[^\"'\n]*)(?P=quote)\s*\)?"
)
_NO_VALUE = {"none", "null", "undefined"}


def lookup_key(key: str) -> bool:
    """A lookup's first argument: an identifier, or a quoted key name."""
    return key[:1] not in "\"'" or key_name(key[1:-1])


def lookup_default_is_value(default: str, dummy: bool = False) -> bool:
    """A lookup's default is a value whatever its shape (changeme, admin, DEFAULT_PASS), except an empty string,
    None/null/undefined, a template (${X}) and, with PG_DETECTOR_FILTER_DUMMY=on, a dummy_value placeholder."""
    value = default.strip()
    return bool(value) and value.lower() not in _NO_VALUE and not template(value) and not (dummy and dummy_value(value))


def assignment_value_is_code(raw: str, quoted: bool = False) -> str | None:
    """The reason secret-assignment declines a value (a filter count name), or None for a value it keeps.

    A quoted value is a string literal ("Admin.Master.Key", "get_token()"), never a reference or code; only a
    template ("{{ x }}", "%(name)s") is declined inside quotes.
    """
    value = _value(raw)
    if quoted:
        return "assignment_template" if template(value) else None
    if reference(value):
        return "assignment_reference"
    if template(value):
        return "assignment_template"
    if code_fragment(value):
        return "assignment_code"
    return None
