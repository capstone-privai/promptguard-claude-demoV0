"""Scorer instrumentation for scripts/eval_integration (moved from #23's detector_filters/run_eval.py and #24's
remask_floor/run_eval.py, code unchanged).

- install_recorder: next to the run's files, filters.jsonl records per scanned item the count per filter name and
  each removed finding's adapter, rule id, filter name and offsets. No text.
- install_boundary: PG_REMASK_SHORT belongs to the Native Mod, which the scorer replays in Python
  (promptguard_adapter.ModSession); for boundary this swaps in a ModSession that re-masks a known value shorter than 8
  characters only where no [A-Za-z0-9_] stands next to it, as register.mjs does. The scorer does not restore
  tool_input, so a restored short value is not replayed here; register.mjs applies the same rule to it.
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

