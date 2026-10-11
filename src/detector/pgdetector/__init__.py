"""PromptGuard detector ensemble: pluggable adapters + a consensus vote."""

from .adapter import AdapterUnavailable, DetectorAdapter, RawFinding
from .consensus import ConsensusPolicy, vote
from .ensemble import Detector, load_detector

__all__ = [
    "AdapterUnavailable", "ConsensusPolicy", "Detector", "DetectorAdapter",
    "RawFinding", "load_detector", "vote",
]
