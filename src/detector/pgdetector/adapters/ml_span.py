"""Adapter for capstone-privai/promptguard-model's independent span detector."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Mapping

from ..adapter import AdapterUnavailable, DetectorAdapter, RawFinding


class MLSpanAdapter(DetectorAdapter):
    version = "unknown"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        repository = Path(options.get("repository", "../../../promptguard-model"))
        repository = repository if repository.is_absolute() else (config_dir / repository).resolve()
        checkpoint = Path(options.get("checkpoint", "models/span-detector-v9"))
        checkpoint = checkpoint if checkpoint.is_absolute() else repository / checkpoint
        source = repository / "src"
        weights = checkpoint / "model.safetensors"
        if not source.is_dir() or not checkpoint.is_dir() or not weights.is_file() or weights.stat().st_size < 1024:
            raise AdapterUnavailable("ML span repository/checkpoint is not available (Git LFS weights required)")
        if str(source) not in sys.path:
            sys.path.insert(0, str(source))
        try:
            from privai_model.ml_span.runtime import MLSpanDetector
        except (ImportError, OSError) as exc:
            raise AdapterUnavailable("ML span dependencies are not installed") from exc
        device = str(options.get("device", "cpu"))
        try:
            self.model = MLSpanDetector(checkpoint, device=device)
            metadata = json.loads((checkpoint / "span_bundle.json").read_text(encoding="utf-8"))
        except Exception as exc:
            raise AdapterUnavailable("ML span model initialization failed") from exc
        self.threshold = options.get("threshold")
        self.strong_threshold = float(options.get("strong_threshold", 0.9999))
        self.version = f"{metadata.get('schema_version', 'ml-span')}:{metadata.get('revision', 'unknown')[:12]}"

    def scan(self, text: str) -> list[RawFinding]:
        predictions = self.model.scan_text(text, threshold=self.threshold)
        findings = []
        for prediction in predictions:
            score = float(prediction["score"])
            findings.append(RawFinding(
                int(prediction["start"]), int(prediction["end"]), "SECRET", "ml-secret-span",
                "strong" if score >= self.strong_threshold else "ambiguous",
                "ml_span", {"model": "span-detector-v9"}, score,
            ))
        return findings
