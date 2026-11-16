"""PG_REMASK_POLICY=all against admitted, from two sets of metric-detection run folders (policy_eval.py).

Per dataset: recall (exact), covered recall (recall + over_rate: every gold character masked), precision, re-mask
edits by tp / over / fp, the recall change in percentage points, and the secrets admitted no longer masks exactly,
by gold type, value shape and the rule that found the value elsewhere in its session (or "re-mask only"). Values are
never printed.

    python scripts/remask_admission/compare.py --data-root ../promptguard-data \\
        --all ../promptguard-data/metric-detection/results/remask_all \\
        --admitted ../promptguard-data/metric-detection/results/remask_admitted [--out compare.md]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import breakdown  # noqa: E402
import shapes  # noqa: E402


def by_dataset(folder: Path) -> dict[str, Path]:
    runs = {}
    for run in breakdown.find_runs([folder]):
        meta = json.loads((run / "run_meta.json").read_text(encoding="utf-8"))
        runs[Path(meta["dataset"]["sessions_path"]).stem] = run
    return runs


def numbers(run: Path, data_root: Path, rules: set[tuple[str, str]]) -> dict[str, Any]:
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    remask = Counter(row["class"] for row in breakdown.analyse_run(run, data_root, rules))
    over = metrics.get("over_rate") or 0
    return {"recall": metrics["recall"], "covered": None if metrics["recall"] is None else metrics["recall"] + over,
            "precision": metrics["precision"], "gold": metrics["counts"]["gold_total"], "edits": metrics["counts"]["edits_total"],
            "remask": (remask["tp"], remask["over"], remask["fp"])}


def lost_spans(all_run: Path, admitted_run: Path, data_root: Path) -> Counter:
    status = lambda run: {(r["session_id"], r["item_id"], r["span_id"]): r for r in breakdown.jsonl(run / "per_span.jsonl") if r["scored"]}  # noqa: E731
    before, after = status(all_run), status(admitted_run)
    meta = json.loads((all_run / "run_meta.json").read_text(encoding="utf-8"))
    sessions_path = Path(meta["dataset"]["sessions_path"])
    sessions_path = sessions_path if sessions_path.is_absolute() else data_root / sessions_path
    texts = {(r["session_id"], i["item_id"]): i["text"] for r in breakdown.jsonl(sessions_path) for i in r["items"]}
    found: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in breakdown.jsonl(admitted_run / "per_finding.jsonl"):
        if row["valid"]:
            found[(row["session_id"], row["item_id"])].append(row)
    lost: Counter = Counter()
    for key, row in before.items():
        if row["status"] != "exact" or after.get(key, {}).get("status") == "exact":
            continue
        value = texts[(row["session_id"], row["item_id"])][row["start"]:row["end"]]
        here = sorted({f"{f['adapter']}:{f['rule_id']}" for f in found[(row["session_id"], row["item_id"])]
                       if f["start"] < row["end"] and row["start"] < f["end"]})
        lost[(row["type"], shapes.value_shape(value), ",".join(here) or "re-mask only")] += 1
    return lost


def fmt(value: Any) -> str:
    return "-" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--all", type=Path, required=True)
    parser.add_argument("--admitted", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    rules = shapes.high_confidence_rules()
    left, right = by_dataset(args.all), by_dataset(args.admitted)
    common = sorted(set(left) & set(right))
    if not common:
        print("no dataset run under both policies", file=sys.stderr)
        return 1
    lines = ["# PG_REMASK_POLICY: all vs admitted", "",
             "| dataset | policy | gold | recall | covered recall | precision | edits | re-mask tp/over/fp | recall change (%p) |",
             "|---|---|---|---|---|---|---|---|---|"]
    lost_all: Counter = Counter()
    for name in common:
        a, b = numbers(left[name], args.data_root, rules), numbers(right[name], args.data_root, rules)
        change = None if a["recall"] is None else (b["recall"] - a["recall"]) * 100
        for policy, n, delta in (("all", a, ""), ("admitted", b, fmt(change))):
            lines.append(f"| {name} | {policy} | {n['gold']} | {fmt(n['recall'])} | {fmt(n['covered'])} | {fmt(n['precision'])} | "
                         f"{n['edits']} | {'/'.join(map(str, n['remask']))} | {delta} |")
        lost = lost_spans(left[name], right[name], args.data_root)
        lost_all.update({(name, *key): count for key, count in lost.items()})
    lines += ["", "Adoption rule: recall loss within 1 percentage point per dataset.", "",
              "## Secrets masked exactly under all but not under admitted", ""]
    if lost_all:
        lines += ["| dataset | gold type | value shape | rules that found it there | spans |", "|---|---|---|---|---|"]
        lines += [f"| {d} | {t} | {s} | {r} | {n} |" for (d, t, s, r), n in lost_all.most_common()]
    else:
        lines.append("None.")
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"{len(common)} datasets -> {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
