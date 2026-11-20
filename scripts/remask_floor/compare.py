"""Compare scorer runs of the re-mask floor (run_eval.py): spans and distinct values side by side.

    python scripts/remask_floor/compare.py --data-root ../promptguard-data \\
        --run default=metric-detection/results/floor_default --run floor=metric-detection/results/floor_floor \\
        [--out compare.md]

Per dataset and configuration, each as spans / distinct values:
- recall exact and covered (every gold character masked): gold covered / gold
- precision (the scorer's: edits inside gold, or masked characters in gold on creddata-trajectory-data)
- re-mask false positives: edits that are not a merged finding span and overlap no gold (values: the masked text)
- "hex key, partly masked": gold spans whose value is 16+ hex characters and whose status is partial
- newly missed: gold covered under the first --run and not under another, by gold type and value length
A distinct value counts as covered when all its gold spans are covered, and lost when it was covered under the
first --run and is not now. Values are hashed in memory to count them and are never printed.

Adoption (task): no distinct gold value lost, and fewer re-mask false positives.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

MAX_SPAN = 8192
HEX = re.compile(r"[0-9a-fA-F]{16,}")


def jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def merge(spans: list[tuple[int, int]]) -> set[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return {(s, e) for s, e in merged if e - s <= MAX_SPAN}


def runs_by_dataset(folder: Path) -> dict[str, Path]:
    out = {}
    for meta_path in sorted(folder.rglob("run_meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        out[Path(meta["dataset"]["sessions_path"]).stem] = meta_path.parent
    return out


class Run:
    def __init__(self, folder: Path, data_root: Path) -> None:
        meta = json.loads((folder / "run_meta.json").read_text(encoding="utf-8"))
        sessions = Path(meta["dataset"]["sessions_path"])
        sessions = sessions if sessions.is_absolute() else data_root / sessions
        self.texts = {(r["session_id"], i["item_id"]): i["text"] for r in jsonl(sessions) for i in r["items"]}
        self.metrics = json.loads((folder / "metrics.json").read_text(encoding="utf-8"))
        self.spans = [r for r in jsonl(folder / "per_span.jsonl") if r["scored"]]
        found: dict[tuple[str, int], list[tuple[int, int]]] = defaultdict(list)
        for row in jsonl(folder / "per_finding.jsonl"):
            if row["valid"] and row["scored"]:
                found[(row["session_id"], row["item_id"])].append((row["start"], row["end"]))
        unions = {key: merge(spans) for key, spans in found.items()}
        self.remask_fp: list[str] = []
        for edit in jsonl(folder / "per_edit.jsonl"):
            key = (edit["session_id"], edit["item_id"])
            if edit["scored"] and not edit["overlaps_gold"] and (edit["start"], edit["end"]) not in unions.get(key, ()):
                self.remask_fp.append(digest(self.texts[key][edit["start"]:edit["end"]]))

    def value(self, span: dict[str, Any]) -> str:
        return self.texts[(span["session_id"], span["item_id"])][span["start"]:span["end"]]

    def covered_keys(self) -> set[tuple[str, int, int]]:
        return {(s["session_id"], s["item_id"], s["span_id"]) for s in self.spans if s["status"] in ("exact", "over")}

    def values_covered(self, statuses: tuple[str, ...]) -> tuple[int, int, int, int]:
        """(spans with a status, gold spans, distinct values all of whose spans have one, distinct values)."""
        by_value: dict[str, list[bool]] = defaultdict(list)
        for span in self.spans:
            by_value[digest(self.value(span))].append(span["status"] in statuses)
        hit = sum(s["status"] in statuses for s in self.spans)
        return hit, len(self.spans), sum(all(flags) for flags in by_value.values()), len(by_value)

    def hex_partial(self) -> tuple[int, int]:
        rows = [s for s in self.spans if s["status"] == "partial" and HEX.fullmatch(self.value(s).strip().strip("\"'"))]
        return len(rows), len({digest(self.value(s)) for s in rows})


def ratio(hit: int, total: int) -> str:
    return "-" if not total else f"{hit / total:.4f} ({hit}/{total})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="append", required=True, metavar="NAME=FOLDER")
    parser.add_argument("--data-root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    configs = [(name, Path(folder) if Path(folder).is_absolute() else args.data_root / folder)
               for name, folder in (item.split("=", 1) for item in args.run)]
    runs = {name: runs_by_dataset(folder) for name, folder in configs}
    datasets = sorted(set.intersection(*(set(r) for r in runs.values())))
    if not datasets:
        print("no dataset run under every configuration", file=sys.stderr)
        return 1
    base_name = configs[0][0]
    lines = ["# Re-mask floor: comparison (spans / distinct values)", "",
             "| dataset | config | recall exact | recall covered | values covered | precision | re-mask FP spans | re-mask FP values | hex key partly masked (spans / values) |",
             "|---|---|---|---|---|---|---|---|---|"]
    missed_rows: list[str] = []
    verdicts: list[str] = []
    for dataset in datasets:
        loaded = {name: Run(runs[name][dataset], args.data_root) for name, _ in configs}
        base = loaded[base_name]
        for name, _ in configs:
            run = loaded[name]
            exact, total, _, _ = run.values_covered(("exact",))
            covered, _, values_ok, values = run.values_covered(("exact", "over"))
            hex_spans, hex_values = run.hex_partial()
            precision = run.metrics.get("precision")
            lines.append(f"| {dataset} | {name} | {ratio(exact, total)} | {ratio(covered, total)} | {ratio(values_ok, values)} | "
                         f"{'-' if precision is None else f'{precision:.4f}'} | {len(run.remask_fp)} | {len(set(run.remask_fp))} | {hex_spans} / {hex_values} |")
            if name == base_name:
                continue
            now = run.covered_keys()
            lost = [s for s in base.spans if (s["session_id"], s["item_id"], s["span_id"]) in base.covered_keys()
                    and (s["session_id"], s["item_id"], s["span_id"]) not in now]
            groups: dict[tuple[str, str], list[str]] = defaultdict(list)
            for span in lost:
                length = len(base.value(span))
                bucket = "<4" if length < 4 else "4-7" if length < 8 else "8+"
                groups[(span["type"], bucket)].append(digest(base.value(span)))
            for (gold_type, bucket), hashes in sorted(groups.items()):
                missed_rows.append(f"| {dataset} | {name} | {gold_type} | {bucket} | {len(hashes)} | {len(set(hashes))} |")
            base_values = {digest(base.value(s)) for s in base.spans}
            covered_before = {v for v in base_values if all(s["status"] in ("exact", "over")
                                                             for s in base.spans if digest(base.value(s)) == v)}
            covered_after = {v for v in base_values if all(s["status"] in ("exact", "over")
                                                            for s in run.spans if digest(run.value(s)) == v)}
            lost_values = len(covered_before - covered_after)
            fewer = len(run.remask_fp) < len(base.remask_fp) or (not base.remask_fp and not run.remask_fp)
            verdicts.append(f"| {dataset} | {name} | {lost_values} | {'pass' if lost_values == 0 else 'FAIL'} | "
                            f"{len(base.remask_fp)} -> {len(run.remask_fp)} | {'pass' if fewer else 'FAIL'} |")
    lines += ["", f"## Gold covered under {base_name}, not under another configuration", ""]
    lines += (["| dataset | config | gold type | value length | spans | distinct values |", "|---|---|---|---|---|---|", *missed_rows]
              if missed_rows else ["None."])
    lines += ["", "## Adoption: no distinct gold value lost, fewer re-mask false positives", "",
              "| dataset | config | distinct values lost | recall check | re-mask FP spans | FP check |",
              "|---|---|---|---|---|---|", *verdicts]
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"{len(datasets)} datasets -> {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
