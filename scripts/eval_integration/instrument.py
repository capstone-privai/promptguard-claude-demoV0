"""Scorer instrumentation for scripts/eval_integration (moved from #23's detector_filters/run_eval.py and #24's
remask_floor/run_eval.py, code unchanged).

- install_recorder: next to the run's files, filters.jsonl records per scanned item the count per filter name and
  each removed finding's adapter, rule id, filter name and offsets. No text.
- install_boundary: PG_REMASK_SHORT belongs to the Native Mod, which the scorer replays in Python
  (promptguard_adapter.ModSession); for boundary this swaps in a ModSession that re-masks a known value shorter than 8
  characters only where no [A-Za-z0-9_] stands next to it, as register.mjs does. The scorer does not restore
  tool_input, so a restored short value is not replayed here; register.mjs applies the same rule to it.
- install_no_remask: PG_REMASK=off (release/defaults-1120) swaps in a ModSession whose re-mask does nothing, as
  register.mjs does: the ledger and the reverse map still fill, only the re-mask pass is skipped. Installed last, it
  also skips install_boundary's short-value pass.
- install_verifier_recorder: candidate_policy "verifier" (configuration 9) writes verifier.jsonl: per item, the
  ambiguous candidates' spans, verifier scores and whether each was masked, and verifier timeouts and fail-closed.
The scorer's repository is not changed.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

def install_recorder(module: Any, rows: list[dict[str, Any]]) -> None:
    adapter_class = module.PromptGuardAdapter
    run_session, scan = adapter_class.run_session, adapter_class._scan

    def recording_run_session(self: Any, session: Any) -> Any:
        self._filter_queue = [item.item_id for item in session.items if module.CHANNEL_MAP.get(item.channel) is not None]
        self._filter_session = session.session_id
        return run_session(self, session)

    def recording_scan(self: Any, text: str, source: str) -> Any:
        filters = getattr(self.detector, "filters", None)
        removed: list[dict[str, Any]] = []
        if filters is not None and not getattr(filters, "_recording", False):
            apply = filters.apply

            def apply_and_record(adapter: str, findings: Any, scanned: str, counts: Counter) -> Any:
                kept = apply(adapter, findings, scanned, counts)
                kept_ids = {id(finding) for finding in kept}
                for finding in findings:
                    if id(finding) not in kept_ids:
                        filters._removed.append({"adapter": adapter, "rule_id": finding.rule_id,
                                                 "filter": filters.reason(adapter, finding, scanned),
                                                 "start": finding.start, "end": finding.end})
                return kept

            filters.apply, filters._recording = apply_and_record, True
        if filters is not None:
            filters._removed = removed
        result = scan(self, text, source)
        item_id = self._filter_queue.pop(0) if getattr(self, "_filter_queue", None) else None
        counts = result.get("filtered", {}) if isinstance(result, dict) else {}
        rows.append({"session_id": getattr(self, "_filter_session", None), "item_id": item_id,
                     "filtered": counts, "removed": removed})
        return result

    adapter_class.run_session, adapter_class._scan = recording_run_session, recording_scan



SHORT_REMASK = 8  # register.mjs SHORT_REMASK


WORD_CHAR = "[A-Za-z0-9_]"


class LongItems(dict):
    """The re-mask map, whose items() leave out short values: the scorer's whole-value pass then skips them."""

    def items(self):  # type: ignore[override]
        return [(raw, value) for raw, value in super().items() if len(raw.encode("utf-16-le")) // 2 >= SHORT_REMASK]


def install_boundary(module: Any) -> None:
    base, edit_type = module.ModSession, module.Edit

    class BoundaryModSession(base):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__()
            self.reverse = LongItems()

        def _remask(self, text: str, out: str, edits: list[Any]) -> tuple[str, list[Any]]:
            out, edits = super()._remask(text, out, edits)  # long values and the partial re-mask, unchanged
            short = sorted(((raw, value) for raw, value in dict.items(self.reverse) if (raw, value) not in self.reverse.items()),
                           key=lambda pair: -len(pair[0]))
            patterns = [(re.compile(rf"(?<!{WORD_CHAR}){re.escape(raw)}(?!{WORD_CHAR})"), raw, value) for raw, value in short]
            if not any(pattern.search(out) for pattern, _, _ in patterns):
                return out, edits
            # The scorer's own way of keeping edits in original coordinates: each output character with its range.
            chars: list[tuple[str, int, int, bool]] = []
            cursor = 0
            for edit in edits:
                chars += [(char, index, index + 1, True) for index, char in enumerate(text[cursor:edit.start], cursor)]
                chars += [(char, edit.start, edit.end, False) for char in edit.replacement]
                cursor = edit.end
            chars += [(char, index, index + 1, True) for index, char in enumerate(text[cursor:], cursor)]
            for pattern, raw, value in patterns:
                current = "".join(char for char, *_ in chars)
                starts = [match.start() for match in pattern.finditer(current)]
                if not starts:
                    continue
                rebuilt, cursor = [], 0
                for at in starts:
                    covered = chars[at:at + len(raw)]
                    start, end = min(c[1] for c in covered), max(c[2] for c in covered)
                    rebuilt += chars[cursor:at] + [(char, start, end, False) for char in value]
                    cursor = at + len(raw)
                chars = rebuilt + chars[cursor:]
            merged: list[list[Any]] = []
            previous_kept = True
            for char, start, end, kept in chars:
                if not kept:
                    if not previous_kept and start < merged[-1][1]:
                        merged[-1][1] = max(merged[-1][1], end)
                        merged[-1][2] += char
                    else:
                        merged.append([start, end, char])
                previous_kept = kept
            return "".join(char for char, *_ in chars), [edit_type(start=s, end=e, replacement=r) for s, e, r in merged]

    module.ModSession = BoundaryModSession


def install_no_remask(module: Any) -> None:
    base = module.ModSession

    class NoRemaskModSession(base):  # type: ignore[misc, valid-type]
        def _remask(self, text: str, out: str, edits: list[Any]) -> tuple[str, list[Any]]:
            return out, edits

    module.ModSession = NoRemaskModSession



def install_verifier_recorder(module: Any, rows: list[dict[str, Any]]) -> None:
    """candidate_policy "verifier" (configuration 9): per scanned item, each ambiguous candidate's span (code points),
    verifier score and whether it was masked, and whether the verifier timed out or failed (fail-closed). No text.

    Installed after install_recorder, so it reads the item id that install_recorder's wrapper pops next."""
    adapter_class = module.PromptGuardAdapter
    scan = adapter_class._scan

    def code_points(text: str, unit: int) -> int:
        count = 0
        for index, char in enumerate(text):
            if count >= unit:
                return index
            count += 2 if ord(char) > 0xFFFF else 1
        return len(text)

    def recording_scan(self: Any, text: str, source: str) -> Any:
        verifier = getattr(self.detector, "verifier", None)
        state = {"timeout": False, "failure": False}
        if verifier is not None and not getattr(verifier, "_pg_recording", False):
            original = verifier.score

            def score(*args: Any, **kwargs: Any) -> Any:
                try:
                    return original(*args, **kwargs)
                except Exception as exc:  # re-raised: the detector fails closed as it would
                    verifier._pg_state["failure"] = True
                    verifier._pg_state["timeout"] = "timed out" in str(exc)
                    raise

            verifier.score, verifier._pg_recording = score, True
        if verifier is not None:
            verifier._pg_state = state
        queue = getattr(self, "_filter_queue", None)
        item_id = queue[0] if queue else None
        result = scan(self, text, source)
        if verifier is None or not isinstance(result, dict):
            return result
        threshold = verifier.threshold
        ambiguous = []
        for candidate in result.get("candidates", []):
            if candidate.get("strength") != "ambiguous":
                continue
            score_value = candidate.get("verifier_score")
            utf16 = candidate.get("offset_unit", "utf16_code_units") == "utf16_code_units"
            start = code_points(text, candidate["start"]) if utf16 else candidate["start"]
            end = code_points(text, candidate["end"]) if utf16 else candidate["end"]
            masked = state["failure"] or (score_value is not None and score_value >= threshold)
            ambiguous.append({"start": start, "end": end, "score": score_value, "masked": masked,
                              "rule_id": candidate.get("rule_id"), "detectors": candidate.get("detectors")})
        rows.append({"session_id": getattr(self, "_filter_session", None), "item_id": item_id, "ambiguous": ambiguous,
                     "timeout": state["timeout"], "failure": state["failure"]})
        return result

    adapter_class._scan = recording_scan


def install_runtime_recorder(module: Any, adapters: list[Any]) -> None:
    """Keeps the scorer's PromptGuard adapter, so the run can record what its detector actually ran with
    (runtime.runtime_record: policy, adapters, model device, timeout and bundle name)."""
    adapter_class = module.PromptGuardAdapter
    init = adapter_class.__init__

    def recording_init(self: Any, *args: Any, **kwargs: Any) -> None:
        init(self, *args, **kwargs)
        adapters.append(self)

    adapter_class.__init__ = recording_init
