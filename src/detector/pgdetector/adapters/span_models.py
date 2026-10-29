"""Adapters for the team ML span detectors in capstone-privai/promptguard-model.

Two independent modules, each switched on or off in detector.json (or with
PG_DETECTOR_ENABLE / PG_DETECTOR_DISABLE):

- ``ml-v9``   wraps ``privai_model.ml_span.runtime.MLSpanDetector`` (mmBERT token
  classification, models/span-detector-v9).
- ``ml-qwen`` wraps ``privai_model.qwen_span.wrapper.QwenSecretScanner``
  (Qwen2.5-Coder LoRA, models/qwen-span-v2).

Both only call the model repository's public entry points, so a new model
version is picked up with ``git pull`` in that repository and a PromptGuard
restart, as long as those entry points keep their shape.

Fail-closed: a model error, an unscannable chunk or a timeout raises, which the
ensemble reports as ``ADAPTER_FAILURE:<name>`` and the Native Mod / Final Guard
treat as a blocked scan. Nothing here logs or returns candidate text.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Callable, Mapping

from ..adapter import AdapterUnavailable, DetectorAdapter, RawFinding
from .shell_aware import PROSE_WORDS

DEFAULT_REPOSITORY = "../../../promptguard-model"
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
        timeout = options.get("timeout_seconds")
        self.timeout = float(timeout) if timeout is not None else None
        self.strong_threshold = float(options.get("strong_threshold", 0.99))
        # A model span shorter than this, or one that is an ordinary English word ("of", "by": ml-v9 flagged both
        # in a live demo session), is not a credential value and is dropped before it can mask anything.
        self.min_value_length = max(1, int(options.get("min_value_length", 6)))
        # One model instance is not safe to share across the worker's request
        # threads; a single executor thread serializes calls and lets a timeout
        # return control while the model call finishes in the background.
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"pg-{name}")
        self._lock = threading.Lock()

    def _call(self, func: Callable[[], Any]) -> Any:
        future = self._executor.submit(func)
        try:
            return future.result(timeout=self.timeout)
        except FutureTimeout:
            raise RuntimeError(f"{self.name} timed out") from None

    def scan(self, text: str) -> list[RawFinding]:
        if not text.strip():
            return []
        if self.gate == "cue" and not CUE.search(text):
            return []
        spans = self._call(lambda: self._spans(text))
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

    def _plausible(self, value: str) -> bool:
        word = value.strip().strip("\"'`.,;:()[]{}")
        return len(word) >= self.min_value_length and word.lower() not in PROSE_WORDS

    def _spans(self, text: str) -> list[tuple[int, int, float]]:  # pragma: no cover - abstract
        raise NotImplementedError


class MLV9Adapter(_ModelRepoAdapter):
    """mmBERT span detector (models/span-detector-v9). Long text is windowed by the model."""

    family = "ml_v9"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path, *, factory: Callable[..., Any] | None = None) -> None:
        super().__init__(name, options, config_dir)
        checkpoint = _resolve(self.repository, options.get("checkpoint"), "models/span-detector-v9")
        if factory is None:
            if not _real_weights(checkpoint / "model.safetensors"):
                raise AdapterUnavailable("v9 weights missing (run git lfs pull in the model repository)")
            try:
                from privai_model.ml_span.runtime import MLSpanDetector as factory  # type: ignore[no-redef]
            except (ImportError, OSError) as exc:
                raise AdapterUnavailable("v9 dependencies are not installed (torch, transformers)") from exc
        threshold = options.get("threshold")
        self.threshold = float(threshold) if threshold is not None else None
        try:
            self.model = factory(checkpoint, device=str(options.get("device", "cpu")))
        except Exception as exc:
            raise AdapterUnavailable("v9 model initialization failed") from exc
        self.model_id = _bundle_id(checkpoint / "span_bundle.json", "span-detector-v9")
        self.version = self.model_id

    def _spans(self, text: str) -> list[tuple[int, int, float]]:
        rows = self.model.scan_text(text, threshold=self.threshold)  # raises RuntimeError on failure
        return [(int(row["start"]), int(row["end"]), float(row["score"])) for row in rows]


class QwenAdapter(_ModelRepoAdapter):
    """Qwen2.5-Coder LoRA span detector (models/qwen-span-v2) via QwenSecretScanner.

    The scanner refuses inputs over its token limit, so long text is split on
    line boundaries into chunks that fit, with ``overlap_lines`` lines repeated
    between chunks. More than ``max_chunks`` chunks, or a line too long to fit,
    fails closed.
    """

    family = "ml_qwen"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path, *, factory: Callable[..., Any] | None = None) -> None:
        super().__init__(name, options, config_dir)
        bundle = _resolve(self.repository, options.get("bundle"), "models/qwen-span-v2")
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
        self.model_id = _bundle_id(bundle / "qwen_bundle.json", "qwen-span-v2")
        self.version = self.model_id

    def _fits(self, text: str) -> bool:
        return self.model.detector.prompt_length(text) <= self.limit

    def _chunks(self, text: str) -> list[tuple[int, str]]:
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
                raise RuntimeError(f"{self.name}: a single line exceeds the model input limit")
            while end < len(lines) and self._fits("".join(line for _, line in lines[start:end + 1])):
                end += 1
            chunks.append((lines[start][0], "".join(line for _, line in lines[start:end])))
            if len(chunks) > self.max_chunks:
                raise RuntimeError(f"{self.name}: input needs more than {self.max_chunks} chunks")
            if end >= len(lines):
                break
            index = max(start + 1, end - self.overlap_lines)
        return chunks

    def _spans(self, text: str) -> list[tuple[int, int, float]]:
        found: dict[tuple[int, int], float] = {}
        for base, chunk in self._chunks(text):
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
