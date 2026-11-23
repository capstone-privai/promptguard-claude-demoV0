"""Back-end verifier: re-judges the detector's ambiguous candidates with the team's verifier model.

candidate_policy "verifier" protects what the model repository's verifier plan (promptguard-model,
docs/ml_span/VERIFIER_PLAN.md) calls strong + verifier:

- each candidate is strong or ambiguous exactly as under "majority" (strong: inside a span the majority vote kept, or
  some adapter gave strong evidence);
- strong candidates are masked, and so are the ambiguous ones the verifier scores at or above its threshold;
- the other ambiguous candidates are not masked.

The model is ``privai_model.verifier.runtime.CandidateVerifier`` from the model repository: any verifier bundle it
writes (the local mmBERT candidate classifier, or the server Qwen LoRA verifier). The bundle fixes the threshold
(recall 0.99 on validation unless ``recall_target`` says otherwise), and the model sees the same candidate input it
was trained on.

Fail-closed: a verifier error, a wrong number of scores or a timeout masks every candidate of the text and reports
``ADAPTER_FAILURE:verifier``, which the Native Mod and Final Guard treat as a blocked scan. Nothing here logs or
returns candidate text; candidates get a ``verifier_score``.
"""

from __future__ import annotations

import math
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .adapter import AdapterUnavailable
from .adapters.span_models import DEFAULT_REPOSITORY, _resolve, path_digest, weights_present

WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin", "adapter_model.safetensors")


class VerifierStage:
    name = "verifier"

    def __init__(self, options: Mapping[str, Any], config_dir: Path, *, factory: Callable[..., Any] | None = None) -> None:
        self.repository = _resolve(config_dir, options.get("repository"), DEFAULT_REPOSITORY)
        source = self.repository / "src"
        if factory is None:
            if not source.is_dir():
                raise AdapterUnavailable(f"model repository not found ({self.repository.name}/src)")
            if str(source) not in sys.path:
                sys.path.insert(0, str(source))
        configured = os.environ.get("PG_VERIFIER_BUNDLE") or options.get("bundle")
        if not configured:
            raise AdapterUnavailable("no verifier bundle configured (detector.json verifier.bundle or PG_VERIFIER_BUNDLE)")
        bundle = _resolve(self.repository, str(configured), str(configured))
        if factory is None:
            # A bundle in shards (model.safetensors.index.json and the shards it names) has weights too.
            if not (bundle / "bundle.json").is_file() or not any(weights_present(bundle, name) for name in WEIGHT_FILES):
                raise AdapterUnavailable(f"verifier bundle {bundle.name} is missing or has no weights")
            try:
                from privai_model.verifier.runtime import CandidateVerifier as factory  # type: ignore[no-redef]
            except (ImportError, OSError) as exc:
                raise AdapterUnavailable("verifier dependencies are not installed (torch, transformers)") from exc
        target = options.get("recall_target")
        # PG_VERIFIER_DEVICE overrides detector.json's device (a GPU server for measurement); the default stays cpu.
        self.device = str(os.environ.get("PG_VERIFIER_DEVICE") or options.get("device", "cpu"))
        try:
            self.model = factory(bundle, device=self.device,
                                 recall_target=float(target) if target is not None else None,
                                 context_lines=int(options.get("context_lines", 3)))
        except Exception as exc:
            raise AdapterUnavailable(f"verifier {bundle.name} initialization failed") from exc
        self.threshold = float(self.model.threshold)
        if not 0.0 <= self.threshold <= 1.0:
            raise AdapterUnavailable("verifier threshold is not a probability")
        self.bundle = bundle
        self.bundle_digest = path_digest(bundle)
        self.version = f"{bundle.name}:{self.model.model_version}"
        timeout = os.environ.get("PG_ML_TIMEOUT_SECONDS") or options.get("timeout_seconds")
        self.timeout = float(timeout) if timeout is not None else None
        # The model is not safe to share across request threads: one executor thread serializes calls, and a call
        # that times out returns control while the model finishes in the background (as span_models does).
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pg-verifier")

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "threshold": self.threshold}

    def runtime_settings(self) -> dict[str, Any]:
        """What this stage runs with, for measurement records: the bundle's folder name, never its path."""
        return {"device": self.device, "timeout_seconds": self.timeout, "bundle": self.bundle.name}

    def _call(self, func: Callable[[], Any]) -> Any:
        if self.timeout is None:
            return self._executor.submit(func).result()
        started = threading.Event()

        def run() -> Any:
            started.set()
            return func()

        future = self._executor.submit(run)
        # Waiting behind a call that timed out is not this call's own time: the wait gets the same length again, and
        # a call that gives up waiting is cancelled so it does not hold up the calls after it.
        if not started.wait(self.timeout) and future.cancel():
            raise RuntimeError("verifier timed out")
        try:
            return future.result(timeout=self.timeout)
        except FutureTimeout:
            raise RuntimeError("verifier timed out") from None

    def score(self, text: str, source: str, candidates: Sequence[Mapping[str, Any]]) -> list[float]:
        """P(MASK) per candidate, in order. Raises on any malformed result so the caller fails closed."""
        if not candidates:
            return []
        rows = [dict(candidate) for candidate in candidates]
        scores = self._call(lambda: self.model.score(text, source, rows))
        if len(scores) != len(rows):
            raise RuntimeError("verifier returned a wrong number of scores")
        values = [float(score) for score in scores]
        if not all(math.isfinite(value) and 0.0 <= value <= 1.0 for value in values):
            raise RuntimeError("verifier returned a score outside [0, 1]")
        return values
