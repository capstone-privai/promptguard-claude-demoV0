"""Gitleaks (open source, Go binary) as one ensemble voter.

Each text is piped to ``gitleaks stdin`` and the JSON report is mapped back to
code point spans. Gitleaks' column numbers are byte-based and off by one in
places, so a finding is located by searching its ``Match`` on the reported
lines and its ``Secret`` inside that match.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
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
        self.max_parallel = max(1, int(options.get("max_parallel", 4)))
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
        if not text.strip():
            return []
        completed = subprocess.run(
            self.command, input=text.encode("utf-8"), capture_output=True,
            timeout=self.timeout, cwd=self.cwd, env=self.env, check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"gitleaks exited with {completed.returncode}")
        return self._locate(json.loads(completed.stdout or b"[]"), text)

    def scan_many(self, texts: Sequence[str]) -> list[list[RawFinding]]:
        # One process per text; run them side by side to hide spawn latency.
        if len(texts) <= 1:
            return [self.scan(text) for text in texts]
        with ThreadPoolExecutor(max_workers=min(self.max_parallel, len(texts))) as pool:
            return list(pool.map(self.scan, texts))

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
