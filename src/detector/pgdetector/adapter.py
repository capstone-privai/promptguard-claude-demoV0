"""The single interface every detection module is wrapped in."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class RawFinding:
    """One adapter's claim that ``text[start:end]`` is a credential.

    Offsets are Python code point indices into the scanned text; the ensemble
    converts accepted spans to UTF-16 units after voting.
    """

    start: int
    end: int
    type: str
    rule_id: str
    confidence: str = "moderate"
    family: str | None = None
    evidence: Mapping[str, str] = field(default_factory=dict)
    score: float | None = None


class AdapterUnavailable(RuntimeError):
    """Raised while constructing an adapter whose backing tool is missing."""


class DetectorAdapter(ABC):
    """Uniform face of one detection module.

    The ensemble only ever sees ``name``, ``version`` and the scan methods, so an
    adapter wrapping an open-source scanner and one implementing in-house rules
    are interchangeable voters. ``name`` comes from detector.json, which lets the
    same adapter class appear twice with different options.
    """

    version = "unknown"

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        self.name = name

    @abstractmethod
    def scan(self, text: str) -> list[RawFinding]:
        """Return this module's findings for ``text``; raise if it cannot decide."""

    def scan_many(self, texts: Sequence[str]) -> list[list[RawFinding]]:
        """Scan a batch. Override when the backing tool has a cheaper batch path."""
        return [self.scan(text) for text in texts]
