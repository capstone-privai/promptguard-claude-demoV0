"""Gitleaks (open source, Go binary) as one ensemble voter.

Texts are piped to ``gitleaks stdin`` and the JSON report is mapped back to
code point spans. Gitleaks' column numbers are byte-based and off by one in
places, so a finding is located by searching its ``Match`` on the reported
lines and its ``Secret`` inside that match.

A batch runs one process: starting gitleaks costs about 0.2 s on Windows (0.3 s
per call in all), against a few milliseconds of scanning, so the texts go in one
stdin stream between boundary lines and each finding is mapped back by its line.
Nothing is written to disk.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..adapter import AdapterUnavailable, DetectorAdapter, RawFinding
from ..core import assigned_variable, pem_body_lines, type_for


NEWLINE = re.compile(r"\n")
# Prefix-anchored rules; everything else (generic-api-key, ...) is entropy-based.
STRONG_RULES = re.compile(r"private-key|github|jwt|aws|slack|stripe|gitlab|npm|openai|anthropic")


class GitleaksAdapter(DetectorAdapter):
    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        binary = os.environ.get("PG_GITLEAKS_BIN") or options.get("binary") or "gitleaks"
        resolved = shutil.which(binary)
        if not resolved:
            raise AdapterUnavailable(f"gitleaks binary {binary!r} not found")
        self.timeout = float(options.get("timeout_seconds", 10))
        self.command = [
            resolved, "stdin", "--no-banner", "--no-color", "--log-level", "error",
            "--report-format", "json", "--report-path", "-", "--exit-code", "0",
            # Decoded findings point at text that is not in the input.
            "--max-decode-depth", "0",
            # Scanned text is untrusted; it must not be able to opt itself out.
            "--ignore-gitleaks-allow",
        ]
        if options.get("config"):
            self.command += ["--config", str(config_dir / options["config"])]
        # Pin rule selection to the options above: no GITLEAKS_CONFIG* from the
        # environment and no .gitleaks.toml/.gitleaksignore from the cwd.
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GITLEAKS_")}
        self.cwd = Path(__file__).resolve().parent
        try:
            completed = subprocess.run([resolved, "version"], capture_output=True, text=True, timeout=self.timeout, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterUnavailable(f"gitleaks {binary!r} is not runnable") from exc
        self.version = completed.stdout.strip() or "unknown"

    def scan(self, text: str) -> list[RawFinding]:
        return self.scan_many([text])[0]

    def scan_many(self, texts: Sequence[str]) -> list[list[RawFinding]]:
        results: list[list[RawFinding]] = [[] for _ in texts]
        todo = [(index, text) for index, text in enumerate(texts) if text.strip()]
        if not todo:
            return results
        # Each text ends with a newline and then a boundary line, so no text is the last line of the input (where
        # gitleaks reports a multi-line match as one line) and a match cannot run from one text into the next
        # without crossing a boundary, which drops it.
        boundary = self._boundary(texts)
        parts: list[str] = []
        ranges: list[tuple[int, int, int]] = []  # (text index, first line, line count), lines 0-based
        line = 0
        for index, text in todo:
            body = text if text.endswith("\n") else text + "\n"
            count = body.count("\n")
            ranges.append((index, line, count))
            parts += [body, boundary, "\n"]
            line += count + 1
        report = self._run("".join(parts))
        leaks: dict[int, list[dict[str, Any]]] = {}
        for leak in report:
            first, last = int(leak["StartLine"]) - 1, int(leak["EndLine"]) - 1
            owner = next((r for r in ranges if r[1] <= first < r[1] + r[2]), None)
            if owner is None:
                continue  # on a boundary line
            index, start, count = owner
            if last >= start + count:
                continue  # runs into the next text: not a finding of either
            leaks.setdefault(index, []).append({**leak, "StartLine": first - start + 1, "EndLine": last - start + 1})
        for index, text in todo:
            results[index] = self._locate(leaks.get(index, []), text)
        return results

    def _run(self, stream: str) -> list[dict[str, Any]]:
        completed = subprocess.run(
            self.command, input=stream.encode("utf-8"), capture_output=True,
            timeout=self.timeout, cwd=self.cwd, env=self.env, check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"gitleaks exited with {completed.returncode}")
        return json.loads(completed.stdout or b"[]")

    @staticmethod
    def _boundary(texts: Sequence[str]) -> str:
        # Letters only and no credential keyword, so no rule fires on it; fresh per batch and absent from every text.
        while True:
            nonce = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))
            line = f"pg boundary {nonce}"
            if not any(line in text for text in texts):
                return line

    def _locate(self, report: list[dict[str, Any]], text: str) -> list[RawFinding]:
        line_starts = [0] + [newline.end() for newline in NEWLINE.finditer(text)]
        cursors: dict[tuple[int, str], int] = {}
        findings: list[RawFinding] = []
        for leak in sorted(report, key=lambda leak: (leak["StartLine"], leak["StartColumn"])):
            rule_id = str(leak["RuleID"])
            secret = leak.get("Secret") or ""
            match = leak.get("Match") or secret
            first, last = int(leak["StartLine"]) - 1, int(leak["EndLine"]) - 1
            if not secret or not 0 <= first <= last < len(line_starts):
                raise ValueError(f"gitleaks finding {rule_id} has no usable location")
            window_end = line_starts[last + 1] if last + 1 < len(line_starts) else len(text)
            # The same match can repeat on one line; take occurrences in report order.
            key = (first, match)
            at = text.find(match, cursors.get(key, line_starts[first]), window_end)
            if at < 0:
                # gitleaks can report a multi-line match as ending on its first line (seen on a PEM block at the end of
                # its input); look past the reported lines before giving up.
                at = text.find(match, cursors.get(key, line_starts[first]))
            secret_at = text.find(secret, at, at + len(match)) if at >= 0 else -1
            if secret_at < 0:
                raise ValueError(f"gitleaks finding {rule_id} could not be located")
            cursors[key] = at + len(match)
            secret_end = secret_at + len(secret)

            finding_type = type_for(rule_id, assigned_variable(text, line_starts[first], secret_at))
            confidence = "strong" if STRONG_RULES.search(rule_id) else "moderate"
            spans = [(secret_at, secret_end)]
            if finding_type == "PRIVATE_KEY":
                # Gitleaks reports the whole armored block; report body lines like the other voters.
                spans = pem_body_lines(text, secret_at, secret_end) or spans
            findings.extend(RawFinding(start, end, finding_type, rule_id, confidence) for start, end in spans)
        return findings
