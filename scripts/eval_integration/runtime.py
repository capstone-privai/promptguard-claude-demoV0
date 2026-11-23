"""Measurement-only model settings (feat/onprem-profile): the env file (src/detector/profiles/onprem.env) run.py
hands to every scorer run, and what each run records of them. Device, timeout and the bundle folder's name are kept;
a path is cut to its last folder name, so nothing about where the files live is written.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping, Sequence

# Overrides a run records, and those whose value is a path (only its last folder name is kept).
RECORDED = ("PG_ML_DEVICE", "PG_VERIFIER_DEVICE", "PG_ML_TIMEOUT_SECONDS", "PG_ML_CHECKPOINT", "PG_VERIFIER_BUNDLE",
            "PG_ML_SCOPE", "PG_DETECTOR_ENABLE", "PG_DETECTOR_DISABLE", "PG_DETECTOR_TIMEOUT_MS")
PATHS = ("PG_ML_CHECKPOINT", "PG_VERIFIER_BUNDLE")
LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
UNFILLED = re.compile(r"<[^<>]+>")


def read_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines (# comments and blank lines skipped). A value still holding a <placeholder> is refused, so a
    run never starts on the example's unfilled bundle path (the model would be skipped as unavailable)."""
    values: dict[str, str] = {}
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = LINE.match(line)
        if not match:
            raise ValueError(f"{path}:{number}: not KEY=VALUE")
        name, value = match.group(1), match.group(2).strip("\"'")
        if UNFILLED.search(value):
            raise ValueError(f"{path}:{number}: fill in {name} (it still holds a <placeholder>)")
        values[name] = value
    return values


def folder_name(value: str) -> str:
    return re.split(r"[\\/]", value.rstrip("\\/"))[-1]


def recorded_overrides(environ: Mapping[str, str]) -> dict[str, str]:
    return {name: folder_name(environ[name]) if name in PATHS else environ[name] for name in RECORDED if environ.get(name)}


def runtime_record(adapters: Sequence[Any]) -> dict[str, Any] | None:
    """From the scorer's PromptGuard adapter (instrument.install_runtime_recorder): the candidate policy, the adapters
    that ran, and each model's device, timeout and bundle name (pgdetector Detector.describe()["runtime_settings"])."""
    if not adapters:
        return None
    described = adapters[-1].detector.describe()
    return {"candidate_policy": described.get("candidate_policy"), "adapters": [row["name"] for row in described.get("adapters", [])],
            "runtime_settings": described.get("runtime_settings")}
