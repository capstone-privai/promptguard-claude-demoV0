"""Compare scorer runs of the detector filters (run_eval.py) with each other and with the CredSweeper-only prototype.

    python scripts/detector_filters/compare.py --data-root ../promptguard-data \\
        --run off=metric-detection/results/filters_off --run on=metric-detection/results/filters_on \\
        [--run on+dummy=...] [--prototype runs/creddata-traj-eval/results/credsweeper-mloff] [--out compare.md]

Per dataset and configuration: gold spans, recall (exact) and covered recall (every gold character masked), precision,
F2 when the scorer reports it (promptguard-data creddata-trajectory-data: recall = covered, precision = masked
characters in gold), edits, false-positive edits from the detector (an edit equal to a merged finding span) and from
re-masking (any other edit), the recall change against the first --run in percentage points, and the filter counts
by name. Then the gold spans the first --run covers and another does not, by gold type, the filter that removed a
finding over it and that finding's adapter:rule. Values are never printed.

The adoption check (CredData-trajectory test): covered recall loss within 1 percentage point against off and F2 at
least the prototype's (0.816 in metric-detection/results/creddata-trajectory/summary.md).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

MAX_SPAN = 8192  # pgdetector core.MAX_SPAN, as fp_analysis rebuilds the union


def jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def merge(spans: list[tuple[int, int]]) -> set[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return {(start, end) for start, end in merged if end - start <= MAX_SPAN}


def runs_by_dataset(folder: Path) -> dict[str, Path]:
    runs = {}
    for meta_path in sorted(folder.rglob("run_meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        runs[Path(meta["dataset"]["sessions_path"]).stem] = meta_path.parent
    return runs


def numbers(run: Path) -> dict[str, Any]:
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    counts = metrics["counts"]
    if "exact_recall" in metrics:  # creddata-trajectory-data: recall covers, precision counts characters
        exact, covered, precision = metrics["exact_recall"], metrics["recall"], metrics["precision"]
    else:
        exact, precision = metrics["recall"], metrics["precision"]
        covered = None if exact is None else exact + (metrics.get("over_rate") or 0)
    found: dict[tuple[str, int], list[tuple[int, int]]] = defaultdict(list)
    for row in jsonl(run / "per_finding.jsonl"):
        if row["valid"] and row["scored"]:
            found[(row["session_id"], row["item_id"])].append((row["start"], row["end"]))
    unions = {key: merge(spans) for key, spans in found.items()}
    detector_fp = remask_fp = 0
    has_findings = (run / "per_finding.jsonl").is_file()
    for edit in jsonl(run / "per_edit.jsonl"):
        if not edit["scored"] or edit["overlaps_gold"]:
            continue
        if (edit["start"], edit["end"]) in unions.get((edit["session_id"], edit["item_id"]), ()):
            detector_fp += 1
        else:
            remask_fp += 1
    filtered: Counter = Counter()
    for row in jsonl(run / "filters.jsonl"):
        filtered.update(row["filtered"])
    return {"gold": counts["gold_total"], "exact": exact, "covered": covered, "precision": precision,
            "f2": metrics.get("f2") if "exact_recall" in metrics else None, "edits": counts["edits_total"],
            "detector_fp": detector_fp if has_findings else None, "remask_fp": remask_fp if has_findings else None,
            "filtered": filtered}


def covered_spans(run: Path) -> dict[tuple[str, int, int], dict[str, Any]]:
    return {(r["session_id"], r["item_id"], r["span_id"]): r for r in jsonl(run / "per_span.jsonl")
            if r["scored"] and r["status"] in ("exact", "over")}


def lost(base: Path, other: Path) -> Counter:
    after = covered_spans(other)
    removed: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in jsonl(other / "filters.jsonl"):
        removed[(row["session_id"], row["item_id"])] += row["removed"]
    out: Counter = Counter()
    for key, span in covered_spans(base).items():
        if key in after:
            continue
        over = [r for r in removed[(span["session_id"], span["item_id"])] if r["start"] < span["end"] and span["start"] < r["end"]]
        reasons = sorted({(r["filter"], f"{r['adapter']}:{r['rule_id']}") for r in over}) or [("(no filter)", "-")]
        for name, rule in reasons:
            out[(span["type"], name, rule)] += 1
    return out


def fmt(value: Any) -> str:
    return "-" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="append", required=True, metavar="NAME=FOLDER")
    parser.add_argument("--prototype", type=Path, help="CredSweeper-only run folder(s) (evaluate.py --system credsweeper --ml off)")
    parser.add_argument("--prototype-f2", type=float, default=0.816)
    parser.add_argument("--data-root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    configs = [(name, (args.data_root / folder) if not Path(folder).is_absolute() else Path(folder))
               for name, folder in (item.split("=", 1) for item in args.run)]
    runs = {name: runs_by_dataset(folder) for name, folder in configs}
    prototype = runs_by_dataset(args.prototype if args.prototype.is_absolute() else args.data_root / args.prototype) if args.prototype else {}
    base_name = configs[0][0]
    datasets = sorted(set.intersection(*(set(r) for r in runs.values())))
    if not datasets:
        print("no dataset run under every configuration", file=sys.stderr)
        return 1
    lines = ["# Detector filters: comparison", "",
             "| dataset | config | gold | recall (exact) | recall (covered) | precision | F2 | edits | detector FP | re-mask FP | covered recall change (%p) | filtered by name |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    lost_rows: list[str] = []
    checks: list[str] = []
    for dataset in datasets:
        if dataset in prototype:
            p = numbers(prototype[dataset])
            lines.append(f"| {dataset} | prototype (CredSweeper only) | {p['gold']} | {fmt(p['exact'])} | {fmt(p['covered'])} | {fmt(p['precision'])} | {fmt(p['f2'])} | {p['edits']} | - | - | | |")
        base = numbers(runs[base_name][dataset])
        for name, _ in configs:
            n = base if name == base_name else numbers(runs[name][dataset])
            change = None if name == base_name or n["covered"] is None or base["covered"] is None else (n["covered"] - base["covered"]) * 100
            filtered = ", ".join(f"{k} {v}" for k, v in sorted(n["filtered"].items())) or "-"
            lines.append(f"| {dataset} | {name} | {n['gold']} | {fmt(n['exact'])} | {fmt(n['covered'])} | {fmt(n['precision'])} | {fmt(n['f2'])} | "
                         f"{n['edits']} | {fmt(n['detector_fp'])} | {fmt(n['remask_fp'])} | {fmt(change)} | {filtered} |")
            if name != base_name:
                for (gold_type, filter_name, rule), count in lost(runs[base_name][dataset], runs[name][dataset]).most_common():
                    lost_rows.append(f"| {dataset} | {name} | {gold_type} | {filter_name} | {rule} | {count} |")
                if n["f2"] is not None:
                    ok_recall = change is not None and change >= -1.0
                    ok_f2 = n["f2"] >= args.prototype_f2
                    checks.append(f"| {dataset} | {name} | {fmt(change)} | {'pass' if ok_recall else 'FAIL'} | {fmt(n['f2'])} | "
                                  f"{'pass' if ok_f2 else 'FAIL'} |")
    lines += ["", f"## Gold spans covered under {base_name} and not under another configuration", ""]
    lines += (["| dataset | config | gold type | filter over it | adapter:rule | spans |", "|---|---|---|---|---|---|", *lost_rows]
              if lost_rows else ["None."])
    if checks:
        lines += ["", f"## Adoption check: covered recall loss within 1 %p of {base_name}, F2 at least {args.prototype_f2}", "",
                  "| dataset | config | recall change (%p) | recall | F2 | F2 check |", "|---|---|---|---|---|---|", *checks,
                  "", "When a check fails, the rules to look at are in the table above (filter and adapter:rule per lost span)."]
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"{len(datasets)} datasets -> {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
