"""Gitleaks (open source, Go binary) as one ensemble voter.

Texts are piped to ``gitleaks stdin`` and the JSON report is mapped back to
code point spans. Gitleaks' column numbers are byte-based and off by one in
places, so a finding is located by searching its ``Match`` on the reported
lines and its ``Secret`` inside that match.

A batch runs one process: starting gitleaks costs about 0.3 s (it reads its
config and compiles its rules before it reads stdin), against a few milliseconds
of scanning, so the texts go in one stdin stream between boundary lines and each
finding is mapped back by its line. Nothing is written to disk.

PG_GITLEAKS_PRESPAWN (default on) keeps one process, started with the same
command, cwd and env, waiting on stdin, so a call only pays the scan; after each
call the next one is started in the background. A waiting process that has died,
or fails on the write, is replaced once on the spot (the off behaviour); a second
failure raises, which the ensemble reports as ADAPTER_FAILURE (fail-closed). A
call that finds the waiting process taken by another call starts its own rather
than wait. The timeout counts from the write. The waiting process is killed when
the adapter is closed or collected and at interpreter exit; if the detector
process is killed outright, its end of the stdin pipe closes and gitleaks exits
on the empty input.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import weakref
from pathlib import Path
from typing import Any, Mapping, Sequence

from .. import settings
from ..adapter import AdapterUnavailable, DetectorAdapter, RawFinding
from ..core import assigned_variable, pem_body_lines, type_for


NEWLINE = re.compile(r"\n")
# Prefix-anchored rules; everything else (generic-api-key, ...) is entropy-based.
STRONG_RULES = re.compile(r"private-key|github|jwt|aws|slack|stripe|gitlab|npm|openai|anthropic")

# Adapters holding a waiting process; closed at interpreter exit (a normal exit or an uncaught exception).
_OPEN: "weakref.WeakSet[GitleaksAdapter]" = weakref.WeakSet()


@atexit.register
def _close_all() -> None:
    for adapter in list(_OPEN):
        adapter.close()


class _Stale(Exception):
    """The waiting process could not take the stream: it had died, or the write failed."""


def _discard(process: subprocess.Popen) -> None:
    try:
        process.kill()
    except OSError:
        pass
    for pipe in (process.stdin, process.stdout, process.stderr):
        try:
            if pipe:
                pipe.close()
        except OSError:
            pass
    try:
        process.wait(5)
    except subprocess.SubprocessError:
        pass


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
        self.prespawn = settings.enabled("PG_GITLEAKS_PRESPAWN")
        self._lock = threading.Lock()
        self._idle: subprocess.Popen | None = None
        self._refilling = False
        self._closed = False
        if self.prespawn:
            _OPEN.add(self)
            self._refill()

    def runtime_settings(self) -> Mapping[str, Any]:
        return {"prespawn": "on" if self.prespawn else "off"}

    def close(self) -> None:
        """Kill the waiting process; no new one is started after this."""
        with self._lock:
            self._closed = True
            process, self._idle = self._idle, None
        if process is not None:
            _discard(process)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

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
        data = stream.encode("utf-8")
        if not self.prespawn:
            return self._finish(self._spawn(), data)
        waiting = self._take()
        try:
            if waiting is not None:
                try:
                    return self._finish(waiting, data, waiting=True)
                except _Stale:
                    pass  # start one now and try once more, as without a waiting process
            return self._finish(self._spawn(), data)
        finally:
            threading.Thread(target=self._refill, name="gitleaks-prespawn", daemon=True).start()

    def _spawn(self) -> subprocess.Popen:
        return subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=self.cwd, env=self.env)

    def _take(self) -> subprocess.Popen | None:
        """The waiting process, handed to one caller only; None when there is none or another call has it."""
        with self._lock:
            process, self._idle = self._idle, None
        return process

    def _refill(self) -> None:
        with self._lock:
            if self._closed or self._idle is not None or self._refilling:
                return
            self._refilling = True
        process = None
        keep = False
        try:
            process = self._spawn()
        except Exception:
            pass  # the next call starts its own
        finally:
            with self._lock:
                self._refilling = False
                keep = process is not None and not self._closed and self._idle is None
                if keep:
                    self._idle = process
        if process is not None and not keep:
            _discard(process)

    def _finish(self, process: subprocess.Popen, data: bytes, *, waiting: bool = False) -> list[dict[str, Any]]:
        """Write the stream, close stdin, read the report: what subprocess.run did, with the timeout from the write.

        For a waiting process, having died or failing on the write raises _Stale so the caller retries once.
        """
        if waiting and process.poll() is not None:
            _discard(process)
            raise _Stale
        with process:
            try:
                stdout, _ = process.communicate(data, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise
            except OSError:
                process.kill()
                if waiting:
                    raise _Stale
                raise
            except BaseException:
                process.kill()
                raise
        if process.returncode != 0:
            if waiting:
                raise _Stale  # it died while waiting or on the write
            raise RuntimeError(f"gitleaks exited with {process.returncode}")
        return json.loads(stdout or b"[]")

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
