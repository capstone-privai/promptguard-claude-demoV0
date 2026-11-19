"""Run promptguard-data's metric-detection scorer with PG_REMASK_SHORT and PG_SHELL_POSITIONAL_MIN set.

    python scripts/remask_floor/run_eval.py --data-root ../promptguard-data --config floor -- \\
        run --system promptguard --system-root . --sessions metric-detection/data_test/sessions_from_SWE-Gym.jsonl \\
        --out metric-detection/results/floor

--config: default (today: substring, positional minimum 1), boundary (PG_REMASK_SHORT=boundary only), min4
(PG_SHELL_POSITIONAL_MIN=4 only) or floor (both). PG_SHELL_POSITIONAL_MIN is read by the system's shell-aware
adapter, which the scorer loads in this process. PG_REMASK_SHORT belongs to the Native Mod, which the scorer replays
in Python (promptguard_adapter.ModSession); for boundary this script swaps in a ModSession that re-masks a known
value shorter than 8 characters only where no [A-Za-z0-9_] stands next to it, as register.mjs does. Values of 8
characters and more, and the partial re-mask, run the scorer's own code. The scorer's repository is not changed.

The scorer does not restore tool_input, so a restored short value is not replayed here; register.mjs applies the
same boundary rule to it.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

CONFIGS = {"default": ("substring", "1"), "boundary": ("boundary", "1"), "min4": ("substring", "4"), "floor": ("boundary", "4")}
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-root", type=Path, required=True, help="promptguard-data checkout")
    parser.add_argument("--config", choices=tuple(CONFIGS), required=True)
    parser.add_argument("scorer_args", nargs=argparse.REMAINDER, help="-- then the scorer's arguments (run ...)")
    args = parser.parse_args(argv)
    scorer_args = args.scorer_args[1:] if args.scorer_args[:1] == ["--"] else args.scorer_args
    remask, positional = CONFIGS[args.config]
    os.environ["PG_REMASK_SHORT"], os.environ["PG_SHELL_POSITIONAL_MIN"] = remask, positional
    root = args.data_root.resolve()
    os.chdir(root)
    sys.path.insert(0, str(root / "metric-detection"))
    from evaluation import cli
    from evaluation.adapters import promptguard_adapter

    if remask == "boundary":
        install_boundary(promptguard_adapter)
    print(f"config {args.config}: PG_REMASK_SHORT={remask} PG_SHELL_POSITIONAL_MIN={positional}")
    return cli.main(scorer_args)


if __name__ == "__main__":
    raise SystemExit(main())
