"""Span utilities shared by every detector adapter and the ensemble."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from typing import Any


MAX_SPAN = int(os.environ.get("PG_DETECTOR_MAX_SPAN", "8192"))
PROCESS_KEY = secrets.token_bytes(32)
# Placeholder kinds the Native Mod and Final Guard understand. Adapters must map
# their tool-specific rule names onto these.
CANONICAL_TYPES = {
    "PASSWORD", "API_KEY", "TOKEN", "PRIVATE_KEY", "AWS_KEY", "GITHUB_TOKEN",
    "SLACK_TOKEN", "JWT", "SECRET", "CREDENTIAL",
}
BENIGN_VARIABLES = {
    "host", "db_host", "port", "db_port", "expected_port", "database", "db_name",
    "service", "service_name", "region", "error_code", "version", "uuid", "hash",
    "url", "localhost", "file_path", "commit", "fixture_id", "color", "timestamp",
}
ASSIGNED_VARIABLE = re.compile(r'["\']?([A-Za-z][A-Za-z0-9_.-]*)["\']?\s*[=:]\s*["\']?$')
LINE = re.compile(r"[^\r\n]+")
PEM_BODY_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def utf16_len(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def type_for(rule_name: str, variable: str | None) -> str:
    rule = rule_name.lower()
    var = (variable or "").lower()
    if "private" in rule or "pem" in rule:
        return "PRIVATE_KEY"
    if "aws" in rule or "amazon" in rule:
        return "AWS_KEY"
    if "github" in rule:
        return "GITHUB_TOKEN"
    if "slack" in rule:
        return "SLACK_TOKEN"
    if "jwt" in rule or "json web token" in rule:
        return "JWT"
    if "url credential" in rule:
        return "PASSWORD"
    if "password" in rule or "passwd" in var or "password" in var or var in {"pwd", "pass"}:
        return "PASSWORD"
    if "secret" in var or var == "secret":
        return "SECRET"
    if "bearer" in rule or "token" in rule or "token" in var or "authorization" in var:
        return "TOKEN"
    if "api" in rule or "api" in var:
        return "API_KEY"
    if "secret" in rule:
        return "SECRET"
    if "credential" in rule:
        return "CREDENTIAL"
    return "CREDENTIAL"


def assigned_variable(text: str, line_start: int, value_start: int) -> str:
    """Name on the left of ``name = value`` / ``"name": value``, lower-cased."""
    found = ASSIGNED_VARIABLE.search(text[line_start:value_start])
    return found.group(1).lower() if found else ""


def line_table(text: str) -> tuple[list[str], list[int]]:
    raw_lines = text.splitlines(keepends=True)
    if not raw_lines:
        return [text], [0]
    lines: list[str] = []
    starts: list[int] = []
    cursor = 0
    for raw in raw_lines:
        starts.append(cursor)
        lines.append(raw.removesuffix("\r\n").removesuffix("\n").removesuffix("\r"))
        cursor += len(raw)
    return lines, starts


def pem_body_lines(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Base64 body lines of a PEM block, without armor or header lines.

    One span per body line is the canonical granularity for private keys, so
    every adapter reports PEM material the same way.
    """
    spans = []
    for line in LINE.finditer(text, start, end):
        stripped = line.group().strip()
        if PEM_BODY_LINE.fullmatch(stripped):
            offset = line.start() + line.group().index(stripped)
            spans.append((offset, offset + len(stripped)))
    return spans


def value_hash(value: str) -> str:
    return hmac.new(PROCESS_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()


def joined_rule_ids(*rule_ids: str) -> str:
    return "+".join(sorted({part for rule_id in rule_ids for part in rule_id.split("+")}))


def normalize(raw: list[dict[str, Any]], text: str, source: str) -> tuple[list[dict[str, Any]], list[str]]:
    valid: list[dict[str, Any]] = []
    errors: list[str] = []
    for item in raw:
        start = item.get("cp_start")
        end = item.get("cp_end")
        if not isinstance(start, int) or not isinstance(end, int):
            errors.append("INVALID_OFFSET_TYPE")
            continue
        if start < 0 or end > len(text) or start >= end:
            errors.append("INVALID_OFFSET_RANGE")
            continue
        if end - start > MAX_SPAN:
            errors.append("SPAN_TOO_LARGE")
            continue
        valid.append({**item, "cp_start": start, "cp_end": end})

    # "priority" is the reporting adapter's position in detector.json, so the
    # first-listed adapter wins type ties on identical spans.
    valid.sort(key=lambda x: (x["cp_start"], x["cp_end"], x.get("priority", 0), x["type"], x["rule_id"]))
    deduped: list[dict[str, Any]] = []
    seen: dict[tuple[int, int, str], dict[str, Any]] = {}
    for item in valid:
        key = (item["cp_start"], item["cp_end"], item["type"])
        if key in seen:
            # Keep every agreeing rule in rule_id so the audit shows who voted.
            kept = seen[key]
            kept["rule_id"] = joined_rule_ids(kept["rule_id"], item["rule_id"])
            kept["confidence"] = "strong" if "strong" in {kept["confidence"], item["confidence"]} else kept["confidence"]
            continue
        seen[key] = item
        deduped.append(item)

    merged: list[dict[str, Any]] = []
    for item in deduped:
        if not merged or item["cp_start"] >= merged[-1]["cp_end"]:
            merged.append(item)
            continue
        previous = merged[-1]
        union_start = min(previous["cp_start"], item["cp_start"])
        union_end = max(previous["cp_end"], item["cp_end"])
        if union_end - union_start > MAX_SPAN:
            errors.append("OVERLAP_TOO_LARGE")
            continue
        previous["cp_start"] = union_start
        previous["cp_end"] = union_end
        previous["type"] = previous["type"] if previous["type"] != "CREDENTIAL" else item["type"]
        previous["rule_id"] = joined_rule_ids(previous["rule_id"], item["rule_id"])
        previous["confidence"] = "strong" if "strong" in {previous["confidence"], item["confidence"]} else previous["confidence"]
        previous["value_hash"] = value_hash(text[union_start:union_end])

    output: list[dict[str, Any]] = []
    cp_cursor = utf16_cursor = 0
    for item in merged:
        # Merged spans are sorted and disjoint, so UTF-16 offsets can be
        # accumulated instead of re-encoding the whole prefix per finding.
        start = utf16_cursor + utf16_len(text[cp_cursor:item["cp_start"]])
        end = start + utf16_len(text[item["cp_start"]:item["cp_end"]])
        cp_cursor, utf16_cursor = item["cp_end"], end
        output.append({
            "type": item["type"],
            "rule_id": item["rule_id"],
            "confidence": item["confidence"],
            "value_hash": item["value_hash"],
            "start": start,
            "end": end,
            "source": source,
            "offset_unit": "utf16_code_units",
        })
    return output, sorted(set(errors))
