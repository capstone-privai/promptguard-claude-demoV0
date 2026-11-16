"""Value shapes and re-mask admission, as the Native Mod decides them (register.mjs valueShape, admitForRemask).

tests/fixtures/remask_shapes.json holds cases both must agree on. Nothing here prints or stores a value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "src" / "native-mod" / "remask-admission.json"

_TEMPLATE = [r"<[^<>]+>", r"\{\{[\s\S]*\}\}", r"\{%[\s\S]*%\}", r"\[[A-Z0-9_]+\]", r"\*{3,}", r"(?i:x{3,})", r"\.{3,}", r"#{3,}"]
_EXAMPLE = [
    r"(?i:(?:changeme|change_me|changeit|example|sample|dummy|placeholder|redacted|password|secret|token|test|testing|none|null|undefined|default)\d*)",
    r"(?i:your[-_ ]?.*[-_ ]here)",
]
_EXAMPLE_SEARCH = [r"(?i:(?:^|[-_])(?:example|dummy|placeholder|changeme|fake|sample)(?:[-_]|$))"]
_REPEAT = re.compile(r"(.)\1{5,}")
_REFERENCE = [r"\$\{[^}]+\}", r"\$[A-Za-z_]\w*", r"\$\([A-Za-z_]\w*\)", r"%[A-Za-z_]\w*%"]
_REFERENCE_START = re.compile(r"(?:process\.env|os\.environ|os\.getenv|System\.getenv|ENV|getenv)\b")
_DOTTED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+(?:\(\))?")
_UUID = re.compile(r"(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
_NUMERIC = re.compile(r"[+-]?[\d.,:\s_/-]+")
_HEX = re.compile(r"(?i:(?:sha(?:1|224|256|384|512)[:-])?(?:0x)?[0-9a-f]+)")
_WORD = r"(?:[a-z]+|[A-Z]+|[A-Z][a-z]+)"
_WORDS_ONLY = re.compile(rf"[-_. ]*{_WORD}(?:[-_. ]+{_WORD})*[-_. ]*")  # register.mjs WORDS_ONLY (#16)
_WORD_TOKEN = re.compile(_WORD)
_SPLIT = re.compile(r"[-_. ]+|(?<=[a-z])(?=[A-Z])")


def _full(patterns: Iterable[str], value: str) -> bool:
    return any(re.fullmatch(pattern, value) for pattern in patterns)


def wordy(value: str) -> bool:
    """Ordinary words, also joined into an identifier: no digit, no symbol but - _ . and spaces."""
    return all(_WORD_TOKEN.fullmatch(token) for token in _SPLIT.split(value) if token)


def value_shape(raw: str) -> str:
    value = raw.strip()
    if len(value) < 8:
        return "short"
    if _full(_TEMPLATE, value):
        return "template"
    if _full(_EXAMPLE, value) or any(re.search(p, value) for p in _EXAMPLE_SEARCH) or _REPEAT.fullmatch(value):
        return "example"
    if _full(_REFERENCE, value) or _REFERENCE_START.match(value) or (
            _DOTTED.fullmatch(value) and all(wordy(part) for part in re.sub(r"\(\)$", "", value).split("."))):
        return "reference"
    if _UUID.fullmatch(value):
        return "uuid"
    if _NUMERIC.fullmatch(value) and re.search(r"\d", value):
        return "numeric"
    if _HEX.fullmatch(value) and (re.search(r"\d", value) or len(value) >= 16):
        return "hex"
    if _WORDS_ONLY.fullmatch(value) or wordy(value):
        return "words"
    return "secret_like"


def high_confidence_rules(path: Path = CONFIG) -> set[tuple[str, str]]:
    config = json.loads(path.read_text(encoding="utf-8"))
    return {(rule["adapter"], rule["rule_id"]) for rule in config["high_confidence_rules"]}


def is_high_confidence(rules: set[tuple[str, str]], adapters: Iterable[str], rule_id: str) -> bool:
    """register.mjs highConfidence: one of the finding's adapters with one of its '+'-joined rule ids."""
    parts = str(rule_id or "").split("+")
    return any((adapter, part) in rules for adapter in adapters for part in parts)
