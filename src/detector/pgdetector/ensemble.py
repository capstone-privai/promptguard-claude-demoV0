"""Runs every configured adapter and keeps the spans the consensus policy accepts."""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Mapping, Sequence

from .adapter import AdapterUnavailable, DetectorAdapter, RawFinding
from .adapters import ADAPTER_TYPES
from .consensus import ConsensusPolicy, vote
from . import settings
from .core import CANONICAL_TYPES, MAX_SPAN, normalize, value_hash
from .filters import Filters, filter_settings, public_prefix_rows
from .verifier import VerifierStage


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "detector.json"
Ballots = dict[str, list[RawFinding]]
CANDIDATE_POLICIES = ("union", "majority", "verifier")
# The canonical finding fields a protected candidate keeps (src/shared/canonical-finding.schema.json).
FINDING_FIELDS = ("type", "rule_id", "detectors", "confidence", "value_hash", "start", "end", "source", "offset_unit")
PUBLIC_PREFIX_TABLE = Path(__file__).resolve().parents[3] / "docs" / "PLACEHOLDER_PUBLIC_PREFIXES.md"


def public_placeholder_pattern() -> re.Pattern[str] | None:
    """What the Native Mod writes with PG_PLACEHOLDER_PUBLIC_PREFIX=on: a prefix from the table and its [TYPE_N].

    Rules see `API_KEY=sk_live_[STRIPE_SECRET_KEY_1]` as an assignment of a secret, so the Final Guard would block
    masked text and the Mod would mask it again. None (option off, or no table) leaves every span as it was.
    """
    if not settings.enabled("PG_PLACEHOLDER_PUBLIC_PREFIX"):
        return None
    rows = public_prefix_rows(PUBLIC_PREFIX_TABLE)
    return re.compile("|".join(rf"{re.escape(prefix)}\[{kind}_\d+\]" for prefix, kind in rows)) if rows else None


class Detector:
    def __init__(self, adapters: Sequence[DetectorAdapter], policy: ConsensusPolicy, skipped: Sequence[Mapping[str, str]] = (), candidate_only: Sequence[str] = (), candidate_policy: str = "majority", verifier: Any = None) -> None:
        names = [adapter.name for adapter in adapters]
        if len(set(names)) != len(names):
            raise ValueError(f"adapter names must be unique: {names}")
        if candidate_policy not in CANDIDATE_POLICIES:
            raise ValueError(f"candidate_policy must be one of {CANDIDATE_POLICIES}, got {candidate_policy!r}")
        if (candidate_policy == "verifier") != (verifier is not None):
            raise ValueError('a verifier is used with candidate_policy "verifier" and only with it')
        # "verifier": candidates get their strength from the majority vote, as under "majority"; then strong ones and
        # the ambiguous ones the verifier accepts are protected (see verifier.py).
        self.verifier = verifier
        self.adapters = list(adapters)
        self.policy = policy
        self.candidate_policy = candidate_policy
        self.candidate_only = set(candidate_only)
        if not self.candidate_only <= set(names):
            raise ValueError("candidate-only adapters must be active adapters")
        # The majority vote never counts candidate-only adapters, so "majority"
        # stays identical to the pre-union detector.
        self.majority_names = [name for name in names if name not in self.candidate_only]
        self.majority_required_votes = policy.required_votes(len(self.majority_names))
        if candidate_policy == "union":
            # Recall-first protection: one adapter is enough for a span to be
            # masked by the Native Mod and blocked by the Final Guard.
            self.protection_names = list(names)
            self.required_votes = 1
        else:
            self.protection_names = list(self.majority_names)
            self.required_votes = self.majority_required_votes
        self.skipped = [dict(item) for item in skipped]
        self.priority = {name: index for index, name in enumerate(names)}
        self.public_placeholder = public_placeholder_pattern()
        # PG_DETECTOR_FILTERS / PG_DETECTOR_FILTER_DUMMY (filters.py): None when both are off (FILTERS is on by default).
        self.filters = Filters.from_env()
        # The filter counts of the texts the current thread's last collect() saw, read by scan_many.
        self._filtered = threading.local()

    @property
    def names(self) -> list[str]:
        return [adapter.name for adapter in self.adapters]

    def describe(self) -> dict[str, Any]:
        return {
            "detector": "ensemble",
            "candidate_policy": self.candidate_policy,
            "consensus": str(self.policy),
            "required_votes": self.required_votes,
            "majority_required_votes": self.majority_required_votes,
            "adapters": [{"name": adapter.name, "version": adapter.version} for adapter in self.adapters],
            "protection_adapters": self.protection_names,
            "majority_adapters": self.majority_names,
            "candidate_adapters": self.names,
            "candidate_only_adapters": sorted(self.candidate_only),
            "verifier": self.verifier.describe() if self.verifier is not None else None,
            "skipped": self.skipped,
            **(self.filters.describe() if self.filters else {}),
            "filter_settings": filter_settings(),
        }

    def collect(self, texts: Sequence[str]) -> tuple[list[Ballots], list[str]]:
        """Every adapter's findings for every text, plus adapter failure codes."""

        def run(adapter: DetectorAdapter) -> tuple[list[list[RawFinding]], str | None, list[Mapping[str, int]] | None]:
            try:
                ballots = adapter.scan_many(texts)
                if len(ballots) != len(texts):
                    raise RuntimeError("ballot count mismatch")
                # Read in the thread that scanned: what the adapter itself declined, per text (counts only).
                return ballots, None, adapter.declined()
            except Exception as exc:
                # Exception text may quote the scanned input, so only the type is logged.
                print(f"PromptGuard detector: adapter {adapter.name!r} failed ({type(exc).__name__})", file=sys.stderr, flush=True)
                return [[] for _ in texts], f"ADAPTER_FAILURE:{adapter.name}", None

        if len(self.adapters) == 1:
            results = [run(self.adapters[0])]
        else:
            with ThreadPoolExecutor(max_workers=len(self.adapters), thread_name_prefix="pg-adapter") as pool:
                results = list(pool.map(run, self.adapters))
        errors = sorted({error for _, error, _ in results if error})
        per_text = [
            {adapter.name: ballots[index] for adapter, (ballots, _, _) in zip(self.adapters, results)}
            for index in range(len(texts))
        ]
        # Before any vote or merge, so every adapter's findings are filtered alike and callers that record
        # collect() (promptguard-data's scorer) see what the ensemble used.
        counts: list[Counter] = [Counter() for _ in texts]
        if self.filters:
            for _, _, declined in results:
                for index, declined_here in enumerate(declined or []):
                    counts[index].update(declined_here)
            for index, text in enumerate(texts):
                per_text[index] = {name: self.filters.apply(name, found, text, counts[index]) for name, found in per_text[index].items()}
        self._filtered.counts = counts
        return per_text, errors

    def accept(self, text: str, ballots: Mapping[str, Sequence[RawFinding]], required_votes: int | None = None, *, candidate_scope: bool = False, include_evidence: bool = False) -> tuple[list[dict[str, Any]], list[str]]:
        """Spans that won the vote, in normalize()'s raw input format."""
        errors = []
        valid: Ballots = {}
        allowed = set(self.names if candidate_scope else self.protection_names)
        for name, findings in ballots.items():
            if name not in allowed:
                continue
            valid[name] = []
            for finding in findings:
                if 0 <= finding.start < finding.end <= len(text):
                    if not (self.public_placeholder and self.public_placeholder.fullmatch(text, finding.start, finding.end)):
                        valid[name].append(finding)
                else:
                    errors.append("INVALID_OFFSET_RANGE")
        required = self.required_votes if required_votes is None else required_votes
        raw = [{
            "cp_start": finding.start,
            "cp_end": finding.end,
            "type": finding.type if finding.type in CANONICAL_TYPES else "CREDENTIAL",
            "rule_id": finding.rule_id,
            "detectors": [name],
            "confidence": finding.confidence,
            "value_hash": value_hash(text[finding.start:finding.end]),
            "priority": self.priority.get(name, len(self.priority)),
            **({"evidence": [{
                "adapter": name,
                "family": finding.family or finding.rule_id,
                "strength": finding.confidence,
                "details": dict(finding.evidence),
                **({"score": finding.score} if finding.score is not None else {}),
            }]} if include_evidence else {}),
        } for name, finding in vote(valid, required)]
        return raw, errors

    def decide(self, text: str, source: str, ballots: Mapping[str, Sequence[RawFinding]], required_votes: int | None = None, *, candidate_scope: bool = False, include_evidence: bool = False) -> tuple[list[dict[str, Any]], list[str]]:
        raw, errors = self.accept(text, ballots, required_votes, candidate_scope=candidate_scope, include_evidence=include_evidence)
        findings, normalize_errors = normalize(raw, text, source)
        return findings, sorted(set(errors + normalize_errors))

    def candidate_decide(self, text: str, source: str, ballots: Mapping[str, Sequence[RawFinding]]) -> tuple[list[dict[str, Any]], list[str]]:
        candidates, errors = self.decide(text, source, ballots, 1, candidate_scope=True, include_evidence=True)
        return candidates, errors

    def scan_many(self, items: Sequence[tuple[str, str]]) -> list[dict[str, Any]]:
        started = time.perf_counter()
        mode = os.environ.get("PG_DETECTOR_MODE", "normal")
        if mode == "crash":
            os._exit(86)
        if mode == "timeout":
            time.sleep(30)
        if mode == "import_failure":
            raise RuntimeError("synthetic import failure")
        if mode == "malformed_json":
            return [{"malformed": True} for _ in items]

        texts = [text for text, _ in items]
        per_text, adapter_errors = self.collect(texts)
        filtered = getattr(self._filtered, "counts", None) or [Counter() for _ in texts]
        decided = []
        for (text, source), ballots in zip(items, per_text):
            raw, errors = self.accept(text, ballots)
            raw.extend(_injected_findings(mode, text))
            findings, normalize_errors = normalize(raw, text, source)
            candidates, candidate_errors = self.candidate_decide(text, source, ballots)
            hashes = [candidate.get("value_hash") for candidate in candidates]
            _decorate_candidates(candidates, findings)
            verifier_errors: list[str] = []
            if self.verifier is not None:
                findings, verifier_errors = self.verified_findings(text, source, candidates, hashes)
            if mode == "unicode_mismatch":
                for finding in findings:
                    finding["offset_unit"] = "code_points"
            decided.append((findings, candidates, sorted(set(adapter_errors + errors + normalize_errors + candidate_errors + verifier_errors)), filtered[len(decided)]))

        # Adapters scan the batch together, so latency is the batch wall time.
        elapsed = round((time.perf_counter() - started) * 1000, 3)
        return [{
            "ok": not errors,
            "findings": findings,
            "candidates": candidates,
            "errors": errors,
            "finding_count": len(findings),
            "candidate_count": len(candidates),
            "latency_ms": elapsed,
            "detector": "ensemble",
            "consensus": str(self.policy),
            "required_votes": self.required_votes,
            "adapters": self.names,
            "candidate_policy": self.candidate_policy,
            # Counts per filter name only, never values; absent when the filters are off.
            **({"filtered": dict(sorted(counts.items()))} if self.filters else {}),
        } for findings, candidates, errors, counts in decided]

    def scan(self, text: str, source: str) -> dict[str, Any]:
        return self.scan_many([(text, source)])[0]

    def verified_findings(self, text: str, source: str, candidates: list[dict[str, Any]], hashes: Sequence[str | None]) -> tuple[list[dict[str, Any]], list[str]]:
        """candidate_policy "verifier": strong candidates plus the ambiguous ones the verifier accepts, as findings.

        Fails closed: when the verifier cannot score, every ambiguous candidate is protected and the scan reports
        ADAPTER_FAILURE:verifier. Each scored candidate gets ``verifier_score`` (a number, never text).
        """
        ambiguous = [index for index, candidate in enumerate(candidates) if candidate["strength"] == "ambiguous"]
        errors: list[str] = []
        try:
            scores = self.verifier.score(text, source, [candidates[index] for index in ambiguous])
        except Exception as exc:
            # Exception text may quote the scanned input, so only the type is logged.
            print(f"PromptGuard detector: verifier failed ({type(exc).__name__})", file=sys.stderr, flush=True)
            scores, errors = [1.0] * len(ambiguous), ["ADAPTER_FAILURE:verifier"]
        else:
            for index, score in zip(ambiguous, scores):
                candidates[index]["verifier_score"] = round(score, 6)
        accepted = {index for index, score in zip(ambiguous, scores) if score >= self.verifier.threshold}
        protected = [index for index, candidate in enumerate(candidates) if candidate["strength"] == "strong" or index in accepted]
        findings = [{field: hashes[index] if field == "value_hash" else candidates[index][field] for field in FINDING_FIELDS}
                    for index in protected]
        return findings, errors


def _injected_findings(mode: str, text: str) -> list[dict[str, Any]]:
    if mode == "invalid_span":
        return [{"cp_start": -2, "cp_end": len(text) + 8, "type": "TOKEN", "rule_id": "synthetic-invalid", "confidence": "strong", "value_hash": "invalid"}]
    if mode == "overlap_invalid" and text:
        return [
            {"cp_start": 0, "cp_end": min(len(text), MAX_SPAN), "type": "TOKEN", "rule_id": "synthetic-overlap-a", "confidence": "strong", "value_hash": "a"},
            {"cp_start": 1, "cp_end": min(len(text), MAX_SPAN + 1), "type": "TOKEN", "rule_id": "synthetic-overlap-b", "confidence": "strong", "value_hash": "b"},
        ]
    return []


def _decorate_candidates(candidates: list[dict[str, Any]], protected: list[dict[str, Any]]) -> None:
    """Mark legacy protection and evidence strength without retaining raw values."""
    protected_spans = [(item["start"], item["end"]) for item in protected]
    for candidate in candidates:
        legacy = any(candidate["start"] < end and candidate["end"] > start for start, end in protected_spans)
        evidence = candidate.get("evidence", [])
        candidate["legacy_protected"] = legacy
        candidate["strength"] = "strong" if legacy or any(row.get("strength") == "strong" for row in evidence) else "ambiguous"
        candidate.pop("value_hash", None)


def _name_set(value: str | None) -> set[str]:
    return {part.strip() for part in (value or "").split(",") if part.strip()}


def adapter_class(kind: str) -> type[DetectorAdapter]:
    """Built-in adapter by short name, or any ``package.module:Class`` on sys.path."""
    target = ADAPTER_TYPES.get(kind, kind)
    module_name, _, class_name = target.partition(":")
    if not class_name:
        raise ValueError(f"unknown adapter type {kind!r}; use one of {sorted(ADAPTER_TYPES)} or 'module:Class'")
    cls = getattr(importlib.import_module(module_name), class_name)
    if not (isinstance(cls, type) and issubclass(cls, DetectorAdapter)):
        raise TypeError(f"{target} is not a DetectorAdapter")
    return cls


def load_detector(config_path: str | Path | None = None, consensus: Any = None) -> Detector:
    """Build the ensemble from detector.json.

    ``PG_DETECTOR_CONFIG`` and ``PG_DETECTOR_CONSENSUS`` override the config file
    and its consensus policy, and ``PG_DETECTOR_CANDIDATE_POLICY`` overrides
    ``candidate_policy`` ("union" masks what any adapter finds; "majority" keeps
    the original vote and ignores candidate-only adapters for protection;
    "verifier" masks strong candidates and the ambiguous ones the back-end
    verifier accepts, with the model named by the config's "verifier" entry or
    ``PG_VERIFIER_BUNDLE``).
    ``PG_DETECTOR_ENABLE`` / ``PG_DETECTOR_DISABLE`` (comma-separated adapter
    names) switch entries on or off without editing the file; DISABLE wins. An
    adapter whose tool is missing aborts startup unless its entry sets
    ``"required": false``, in which case it is skipped and does not count as a
    voter. An adapter named in ``PG_DETECTOR_ENABLE`` always aborts startup when
    it cannot run.
    """
    path = Path(config_path or os.environ.get("PG_DETECTOR_CONFIG") or DEFAULT_CONFIG).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    policy = ConsensusPolicy.parse(consensus or os.environ.get("PG_DETECTOR_CONSENSUS") or config.get("consensus", "any"))
    adapters: list[DetectorAdapter] = []
    candidate_only: list[str] = []
    skipped: list[dict[str, str]] = []
    force_on = _name_set(os.environ.get("PG_DETECTOR_ENABLE"))
    force_off = _name_set(os.environ.get("PG_DETECTOR_DISABLE"))
    for entry in config.get("adapters", []):
        enabled = entry.get("enabled", True)
        if entry["name"] in force_on:
            enabled = True
        if entry["name"] in force_off:
            enabled = False
        if not enabled:
            continue
        name = entry["name"]
        try:
            adapters.append(adapter_class(entry.get("type", name))(name, entry.get("options", {}), path.parent))
            if entry.get("candidate_only", False):
                candidate_only.append(name)
        except AdapterUnavailable as exc:
            # Asked for by name (--enable): starting without it would look like it is running.
            if entry.get("required", True) or name in force_on:
                raise
            skipped.append({"name": name, "reason": str(exc)})
            print(f"PromptGuard detector: optional adapter {name!r} skipped ({exc})", file=sys.stderr, flush=True)
    candidate_policy = os.environ.get("PG_DETECTOR_CANDIDATE_POLICY") or config.get("candidate_policy", "majority")
    # "verifier" loads the "verifier" entry (verifier.py). Asked for, it must run: a missing bundle stops startup.
    verifier = VerifierStage(config.get("verifier", {}), path.parent) if candidate_policy == "verifier" else None
    return Detector(adapters, policy, skipped, candidate_only, candidate_policy, verifier)
