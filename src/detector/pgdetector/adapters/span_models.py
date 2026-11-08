"""Adapters for the team ML span detectors in capstone-privai/promptguard-model.

Two independent modules, each switched on or off in detector.json (or with
PG_DETECTOR_ENABLE / PG_DETECTOR_DISABLE):

- ``ml-v9``   wraps ``privai_model.ml_span.runtime.MLSpanDetector`` (mmBERT token
  classification). The name is historical: it runs whichever bundle is configured.
- ``ml-qwen`` wraps ``privai_model.qwen_span.wrapper.QwenSecretScanner``
  (Qwen2.5-Coder LoRA).

Which bundle: ``"checkpoint"`` / ``"bundle"`` set to ``"default"`` uses the
``DEFAULT_BUNDLE`` the model repository's module names, and
``fallback_checkpoint`` / ``fallback_bundle`` while it names none. A new model is
then picked up with ``git pull`` and ``git lfs pull`` there and a PromptGuard
restart, as long as the entry points keep their shape. The newest folder is not
used: a version number does not mean the team adopted that model.

Fail-closed: a model error, an unscannable chunk or a timeout raises, which the
ensemble reports as ``ADAPTER_FAILURE:<name>`` and the Native Mod / Final Guard
treat as a blocked scan. Nothing here logs or returns candidate text.
"""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Callable, Mapping

from ..adapter import AdapterUnavailable, DetectorAdapter, RawFinding
from .shell_aware import PROSE_WORDS

DEFAULT_REPOSITORY = "../../../promptguard-model"
DEFAULT_SPAN_BUNDLE = "models/span-detector-v10"
DEFAULT_QWEN_BUNDLE = "models/qwen-span-v3"
# Words that suggest a credential is nearby. Used only when an adapter sets
# "gate": "cue" to skip slow models on text with no such word.
# Whole words only (snake_case and camelCase parts count): "passed" or "bypass"
# must not wake a model that costs seconds per input.
CUE = re.compile(
    r"(?i)(?<![a-z])(?:pass(?:word|wd|phrase)?|pwd|secrets?|tokens?|api[_-]?keys?|auth(?:orization|orize|enticat(?:e|ion|ed)|token)?|credentials?"
    r"|bearer|private[ _-]?key|access[_-]?key)(?![a-z])"
    r"|(?<=[a-z])(?:Password|Passwd|Secret|Token|ApiKey|Auth)"
    r"|비밀번호|비번|토큰|인증|시크릿"
)


def _resolve(base: Path, value: str | None, default: str) -> Path:
    path = Path(value or default)
    return path if path.is_absolute() else (base / path).resolve()


def _real_weights(path: Path) -> bool:
    """False for a missing file or a Git LFS pointer that was never pulled."""
    return path.is_file() and path.stat().st_size >= 1024


class _ModelRepoAdapter(DetectorAdapter):
    """Shared plumbing: locate the model repo, import lazily, gate, serialize, time out."""

    family = "ml"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        self.repository = _resolve(config_dir, options.get("repository"), DEFAULT_REPOSITORY)
        source = self.repository / "src"
        if not source.is_dir():
            raise AdapterUnavailable(f"model repository not found ({self.repository.name}/src)")
        if str(source) not in sys.path:
            sys.path.insert(0, str(source))
        gate = str(options.get("gate", "always"))
        if gate not in {"always", "cue"}:
            raise ValueError("gate must be 'always' or 'cue'")
        self.gate = gate
        # PG_ML_TIMEOUT_SECONDS overrides every model adapter's timeout, for a run where they share the CPU
        # (v9 and Qwen together) and a call takes longer than it does alone.
        timeout = os.environ.get("PG_ML_TIMEOUT_SECONDS") or options.get("timeout_seconds")
        self.timeout = float(timeout) if timeout is not None else None
        # Texts longer than max_text_chars are left to the other detectors, the same way the cue gate leaves texts
        # without a cue. too_long says what happens when a text still does not fit the model (Qwen: a line over
        # the input limit, or more chunks than max_chunks): "fail" (default) raises and the request is blocked,
        # "skip" leaves that text to the other detectors.
        limit = options.get("max_text_chars")
        self.max_text_chars = int(limit) if limit is not None else None
        too_long = str(options.get("too_long", "fail"))
        if too_long not in {"fail", "skip"}:
            raise ValueError("too_long must be 'fail' or 'skip'")
        self.too_long = too_long
        # long_text: "whole" (default) gives the model the whole text. "cue_windows" gives it a text of up to
        # whole_text_chars whole, and of a longer one only the lines within window_lines of a line with a credential
        # cue (CUE). The model reads in time linear to its input: ml-v9 on CPU took about 0.4 s for 2 KB and 4 to
        # 9 s for 20 KB, past its 4 s timeout, so every large tool output failed and was blocked. In this mode
        # max_text_chars bounds what the model reads (the windows together), and too_long decides past it.
        long_text = str(options.get("long_text", "whole"))
        if long_text not in {"whole", "cue_windows"}:
            raise ValueError("long_text must be 'whole' or 'cue_windows'")
        self.long_text = long_text
        self.whole_text_chars = int(options.get("whole_text_chars", 2000))
        self.window_lines = max(0, int(options.get("window_lines", 2)))
        self.strong_threshold = float(options.get("strong_threshold", 0.99))
        # A model span shorter than this, or one that is an ordinary English word ("of", "by": ml-v9 flagged both
        # in a live demo session), is not a credential value and is dropped before it can mask anything.
        self.min_value_length = max(1, int(options.get("min_value_length", 6)))
        # One model instance is not safe to share across the worker's request
        # threads; a single executor thread serializes calls and lets a timeout
        # return control while the model call finishes in the background.
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"pg-{name}")
        self._lock = threading.Lock()

    def _bundle_path(self, options: Mapping[str, Any], key: str, module: str, fallback: str) -> Path:
        """The configured bundle folder; "default" asks the model repository which bundle it names."""
        value = options.get(key)
        if value == "default":
            try:
                named = getattr(importlib.import_module(module), "DEFAULT_BUNDLE", None)
            except (ImportError, OSError):
                named = None  # the caller reports missing weights or dependencies as usual
            value = str(named) if named else options.get(f"fallback_{key}")
        return _resolve(self.repository, value, fallback)

    def _call(self, func: Callable[[], Any]) -> Any:
        if self.timeout is None:
            return self._executor.submit(func).result()
        started = threading.Event()

        def run() -> Any:
            started.set()
            return func()

        future = self._executor.submit(run)
        # A call that timed out cannot be stopped and holds the model until it ends. The wait behind it is not this
        # call's own time, so the timeout covers only the model's work and the wait gets the same length again. A
        # call that gives up waiting is cancelled, so it does not hold up the calls after it.
        if not started.wait(self.timeout) and future.cancel():
            raise RuntimeError(f"{self.name} timed out")
        try:
            return future.result(timeout=self.timeout)
        except FutureTimeout:
            raise RuntimeError(f"{self.name} timed out") from None

    def scan(self, text: str) -> list[RawFinding]:
        if not text.strip():
            return []
        if self.gate == "cue" and not CUE.search(text):
            return []
        if self.long_text == "cue_windows":
            regions = self._cue_windows(text)
        elif self.max_text_chars is not None and len(text) > self.max_text_chars:
            return []
        else:
            regions = [(0, text)]
        if not regions:
            return []
        spans = self._call(lambda: self._region_spans(regions))
        findings = []
        for start, end, score in spans:
            if not (0 <= start < end <= len(text)):
                raise RuntimeError(f"{self.name} returned an invalid span")
            if not self._plausible(text[start:end]):
                continue
            findings.append(RawFinding(
                start, end, "SECRET", f"{self.family}-span",
                "strong" if score >= self.strong_threshold else "ambiguous",
                self.family, {"model": self.model_id}, round(float(score), 6),
            ))
        return findings

    def _cue_windows(self, text: str) -> list[tuple[int, str]]:
        """(offset, text) pieces for the model to read in cue_windows mode; [] leaves the text to the others."""
        if len(text) <= self.whole_text_chars:
            return [(0, text)]
        lines, offset = [], 0
        for line in text.splitlines(keepends=True):
            lines.append((offset, line))
            offset += len(line)
        cued = [index for index, (_, line) in enumerate(lines) if CUE.search(line)]
        ranges: list[list[int]] = []
        for index in cued:
            start, end = max(0, index - self.window_lines), min(len(lines), index + self.window_lines + 1)
            if ranges and start <= ranges[-1][1]:
                ranges[-1][1] = max(ranges[-1][1], end)
            else:
                ranges.append([start, end])
        regions = [(lines[start][0], "".join(line for _, line in lines[start:end])) for start, end in ranges]
        if self.max_text_chars is not None and sum(len(piece) for _, piece in regions) > self.max_text_chars:
            if self.too_long == "skip":
                return []
            raise RuntimeError(f"{self.name}: cue windows exceed max_text_chars")
        return regions

    def _region_spans(self, regions: list[tuple[int, str]]) -> list[tuple[int, int, float]]:
        out = []
        for base, piece in regions:
            out.extend((base + start, base + end, score) for start, end, score in self._spans(piece))
        return out

    def _plausible(self, value: str) -> bool:
        word = value.strip().strip("\"'`.,;:()[]{}")
        return len(word) >= self.min_value_length and word.lower() not in PROSE_WORDS

    def _spans(self, text: str) -> list[tuple[int, int, float]]:  # pragma: no cover - abstract
        raise NotImplementedError


class MLV9Adapter(_ModelRepoAdapter):
    """mmBERT span detector (see the module docstring for which bundle). Long text is windowed by the model."""

    family = "ml_v9"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path, *, factory: Callable[..., Any] | None = None) -> None:
        super().__init__(name, options, config_dir)
        checkpoint = self._bundle_path(options, "checkpoint", "privai_model.ml_span.runtime", DEFAULT_SPAN_BUNDLE)
        if factory is None:
            if not _real_weights(checkpoint / "model.safetensors"):
                raise AdapterUnavailable(f"{checkpoint.name} weights missing (run git lfs pull in the model repository)")
            try:
                from privai_model.ml_span.runtime import MLSpanDetector as factory  # type: ignore[no-redef]
            except (ImportError, OSError) as exc:
                raise AdapterUnavailable("span model dependencies are not installed (torch, transformers)") from exc
        threshold = options.get("threshold")
        self.threshold = float(threshold) if threshold is not None else None
        try:
            self.model = factory(checkpoint, device=str(options.get("device", "cpu")))
        except Exception as exc:
            raise AdapterUnavailable(f"{checkpoint.name} model initialization failed") from exc
        self.model_id = _bundle_id(checkpoint / "span_bundle.json", checkpoint.name)
        self.version = self.model_id

    def _spans(self, text: str) -> list[tuple[int, int, float]]:
        rows = self.model.scan_text(text, threshold=self.threshold)  # raises RuntimeError on failure
        return [(int(row["start"]), int(row["end"]), float(row["score"])) for row in rows]


class QwenAdapter(_ModelRepoAdapter):
    """Qwen2.5-Coder LoRA span detector via QwenSecretScanner.

    The scanner refuses inputs over its token limit, so long text is split on
    line boundaries into chunks that fit, with ``overlap_lines`` lines repeated
    between chunks. More than ``max_chunks`` chunks, or a line too long to fit,
    fails closed.
    """

    family = "ml_qwen"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path, *, factory: Callable[..., Any] | None = None) -> None:
        super().__init__(name, options, config_dir)
        bundle = self._bundle_path(options, "bundle", "privai_model.qwen_span.wrapper", DEFAULT_QWEN_BUNDLE)
        if factory is None:
            if not _real_weights(bundle / "adapter_model.safetensors"):
                raise AdapterUnavailable("Qwen adapter weights missing (run git lfs pull in the model repository)")
            try:
                from privai_model.qwen_span.wrapper import QwenSecretScanner as factory  # type: ignore[no-redef]
            except (ImportError, OSError) as exc:
                raise AdapterUnavailable("Qwen dependencies are not installed (torch, transformers, peft)") from exc
        kwargs: dict[str, Any] = {"device": str(options.get("device", "auto")), "local_files_only": bool(options.get("local_files_only", False))}
        if options.get("threshold") is not None:
            kwargs["threshold"] = float(options["threshold"])
        try:
            self.model = factory(bundle, **kwargs)
        except Exception as exc:
            raise AdapterUnavailable("Qwen model initialization failed") from exc
        self.max_chunks = max(1, int(options.get("max_chunks", 8)))
        self.overlap_lines = max(0, int(options.get("overlap_lines", 1)))
        self.limit = int(getattr(self.model, "max_input_tokens", 4096))
        self.model_id = _bundle_id(bundle / "qwen_bundle.json", bundle.name)
        self.version = self.model_id

    def _fits(self, text: str) -> bool:
        return self.model.detector.prompt_length(text) <= self.limit

    def _chunks(self, text: str) -> list[tuple[int, str]] | None:
        """The text cut at line ends into pieces that fit the model, or None when it cannot be (too_long: skip)."""
        if self._fits(text):
            return [(0, text)]
        lines, offset = [], 0
        for line in text.splitlines(keepends=True):
            lines.append((offset, line))
            offset += len(line)
        chunks: list[tuple[int, str]] = []
        index = 0
        while index < len(lines):
            start = index
            end = index + 1
            if not self._fits(lines[start][1]):
                if self.too_long == "skip":
                    return None
                raise RuntimeError(f"{self.name}: a single line exceeds the model input limit")
            while end < len(lines) and self._fits("".join(line for _, line in lines[start:end + 1])):
                end += 1
            chunks.append((lines[start][0], "".join(line for _, line in lines[start:end])))
            if len(chunks) > self.max_chunks:
                if self.too_long == "skip":
                    return None
                raise RuntimeError(f"{self.name}: input needs more than {self.max_chunks} chunks")
            if end >= len(lines):
                break
            index = max(start + 1, end - self.overlap_lines)
        return chunks

    def _spans(self, text: str) -> list[tuple[int, int, float]]:
        found: dict[tuple[int, int], float] = {}
        for base, chunk in self._chunks(text) or []:
            result = self.model.scan(chunk)
            if result.status != "ok":
                raise RuntimeError(f"{self.name}: scan failed ({result.error})")
            for finding in result.findings:
                key = (base + int(finding.start), base + int(finding.end))
                found[key] = max(found.get(key, 0.0), float(finding.score))
        return [(start, end, score) for (start, end), score in sorted(found.items())]


def _bundle_id(path: Path, fallback: str) -> str:
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback
    revision = str(meta.get("revision") or "")[:12]
    return f"{fallback}:{revision}" if revision else fallback
