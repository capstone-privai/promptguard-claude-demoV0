"""Raw-free CredSweeper adapter for PromptGuard Demo V0."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

# Detector diagnostics can contain candidate text. Only explicit raw-free status is emitted.
logging.disable(logging.CRITICAL)

from credsweeper import CredSweeper, StringContentProvider, __version__ as CREDSWEEPER_VERSION


HOST = "127.0.0.1"
PORT = int(os.environ.get("PG_DETECTOR_PORT", "18771"))
MAX_BODY = int(os.environ.get("PG_DETECTOR_MAX_BODY", str(8 * 1024 * 1024)))
MAX_SPAN = int(os.environ.get("PG_DETECTOR_MAX_SPAN", "8192"))
PROCESS_KEY = secrets.token_bytes(32)
SCAN_LOCK = threading.Lock()
BENIGN_VARIABLES = {
    "host", "db_host", "port", "db_port", "expected_port", "database", "db_name",
    "service", "service_name", "region", "error_code", "version", "uuid", "hash",
    "url", "localhost", "file_path", "commit", "fixture_id", "color", "timestamp",
}


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


def confidence_value(candidate: Any) -> str:
    value = getattr(getattr(candidate, "confidence", None), "value", None)
    return str(value or "moderate")


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


def value_hash(value: str) -> str:
    return hmac.new(PROCESS_KEY, value.encode("utf-8"), hashlib.sha256).hexdigest()


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

    valid.sort(key=lambda x: (x["cp_start"], x["cp_end"], x["type"], x["rule_id"]))
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str]] = set()
    for item in valid:
        key = (item["cp_start"], item["cp_end"], item["type"])
        if key not in seen:
            seen.add(key)
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
        previous["rule_id"] = "+".join(sorted(set(previous["rule_id"].split("+") + item["rule_id"].split("+"))))
        previous["confidence"] = "strong" if "strong" in {previous["confidence"], item["confidence"]} else previous["confidence"]
        previous["value_hash"] = value_hash(text[union_start:union_end])

    output: list[dict[str, Any]] = []
    for item in merged:
        cp_start = item.pop("cp_start")
        cp_end = item.pop("cp_end")
        output.append({
            **item,
            "start": utf16_len(text[:cp_start]),
            "end": utf16_len(text[:cp_end]),
            "source": source,
            "offset_unit": "utf16_code_units",
        })
    return output, sorted(set(errors))


class Adapter:
    def __init__(self) -> None:
        # scan() is used directly and post_processing()/MlValidator are never invoked.
        common = dict(
            pool_count=1,
            severity="medium",
            confidence="moderate",
            use_filters=True,
            ml_threshold=0,
            log_level="ERROR",
        )
        self.scanners = [
            CredSweeper(**common),
            CredSweeper(rule_path=Path(__file__).with_name("rules-demo.yaml"), **common),
        ]

    def scan(self, text: str, source: str) -> dict[str, Any]:
        started = time.perf_counter()
        mode = os.environ.get("PG_DETECTOR_MODE", "normal")
        if mode == "crash":
            os._exit(86)
        if mode == "timeout":
            time.sleep(30)
        if mode == "import_failure":
            raise RuntimeError("synthetic import failure")
        if mode == "malformed_json":
            return {"malformed": True}

        lines, starts = line_table(text)
        candidates = []
        with SCAN_LOCK:
            for scanner in self.scanners:
                scanner.credential_manager.clear_credentials()
                provider = StringContentProvider(lines, file_path="memory.txt", file_type=".txt", info=source)
                scanner.scan([provider], None)
                candidates.extend(list(scanner.credential_manager.candidates))

        raw_findings: list[dict[str, Any]] = []
        for candidate in candidates:
            for line_data in candidate.line_data_list:
                variable = str(getattr(line_data, "variable", "") or "").strip().lower()
                line_index = max(0, int(line_data.line_num) - 1)
                if line_index >= len(starts):
                    raw_findings.append({"cp_start": -1, "cp_end": -1, "type": "CREDENTIAL", "rule_id": candidate.rule_name, "confidence": confidence_value(candidate), "value_hash": ""})
                    continue
                cp_start = starts[line_index] + int(line_data.value_start)
                cp_end = starts[line_index] + int(line_data.value_end)
                prefix = text[starts[line_index]:cp_start]
                inferred = re.search(r'["\']?([A-Za-z][A-Za-z0-9_.-]*)["\']?\s*[=:]\s*["\']?$', prefix)
                inferred_variable = inferred.group(1).lower() if inferred else ""
                if variable in BENIGN_VARIABLES or inferred_variable in BENIGN_VARIABLES:
                    continue
                finding_type = type_for(candidate.rule_name, variable or inferred_variable)
                # CredSweeper's broad fallback "Credential" rules are useful for
                # discovery but too noisy for an enforcement boundary. Demo V0
                # only enforces value-oriented, classifiable candidate families.
                if finding_type == "CREDENTIAL":
                    continue
                value = text[cp_start:cp_end] if 0 <= cp_start <= cp_end <= len(text) else ""
                raw_findings.append({
                    "cp_start": cp_start,
                    "cp_end": cp_end,
                    "type": finding_type,
                    "rule_id": str(candidate.rule_name),
                    "confidence": confidence_value(candidate),
                    "value_hash": value_hash(value),
                })

        if mode == "invalid_span":
            raw_findings.append({"cp_start": -2, "cp_end": len(text) + 8, "type": "TOKEN", "rule_id": "synthetic-invalid", "confidence": "strong", "value_hash": "invalid"})
        if mode == "overlap_invalid" and text:
            raw_findings.extend([
                {"cp_start": 0, "cp_end": min(len(text), MAX_SPAN), "type": "TOKEN", "rule_id": "synthetic-overlap-a", "confidence": "strong", "value_hash": "a"},
                {"cp_start": 1, "cp_end": min(len(text), MAX_SPAN + 1), "type": "TOKEN", "rule_id": "synthetic-overlap-b", "confidence": "strong", "value_hash": "b"},
            ])

        findings, errors = normalize(raw_findings, text, source)
        if mode == "unicode_mismatch":
            for finding in findings:
                finding["offset_unit"] = "code_points"
        elapsed = (time.perf_counter() - started) * 1000
        return {
            "ok": not errors,
            "findings": findings,
            "errors": errors,
            "finding_count": len(findings),
            "latency_ms": round(elapsed, 3),
            "detector": "CredSweeper",
            "detector_version": CREDSWEEPER_VERSION,
            "ml": False,
        }


ADAPTER: Adapter | None = None


class Handler(BaseHTTPRequestHandler):
    server_version = "PromptGuardCredSweeperAdapter/0.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def send_json(self, status: int, value: Any) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_json(404, {"ok": False, "error": "NOT_FOUND"})
            return
        self.send_json(200, {"ok": True, "detector": "CredSweeper", "version": CREDSWEEPER_VERSION, "ml": False})

    def do_POST(self) -> None:
        if self.path not in {"/scan", "/scan-batch"}:
            self.send_json(404, {"ok": False, "error": "NOT_FOUND"})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            if length <= 0 or length > MAX_BODY:
                self.send_json(413, {"ok": False, "error": "BODY_SIZE"})
                return
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if ADAPTER is None:
                raise RuntimeError("adapter unavailable")
            if self.path == "/scan":
                text = payload.get("text")
                source = payload.get("source", "unknown")
                if not isinstance(text, str) or not isinstance(source, str):
                    self.send_json(400, {"ok": False, "error": "INVALID_INPUT"})
                    return
                self.send_json(200, ADAPTER.scan(text, source))
                return
            items = payload.get("items")
            if not isinstance(items, list) or len(items) > 4096:
                self.send_json(400, {"ok": False, "error": "INVALID_BATCH"})
                return
            output = []
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                    self.send_json(400, {"ok": False, "error": "INVALID_ITEM"})
                    return
                result = ADAPTER.scan(item["text"], str(item.get("source", "unknown")))
                output.append({"id": item.get("id"), **result})
            self.send_json(200, {"ok": all(item.get("ok") for item in output), "items": output})
        except Exception:
            self.send_json(500, {"ok": False, "error": "DETECTOR_EXCEPTION"})


def main() -> None:
    global ADAPTER
    ADAPTER = Adapter()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(json.dumps({"ready": True, "host": HOST, "port": PORT, "version": CREDSWEEPER_VERSION, "ml": False}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
