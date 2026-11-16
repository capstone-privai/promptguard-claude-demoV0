"""Where the Mod's re-mask false positives come from, from promptguard-data metric-detection run folders.

For each run folder of system promptguard (run_meta.json, per_edit.jsonl, per_finding.jsonl), a re-mask edit is an
edit the run made that is not one of the merged finding spans (fp_analysis's edits_only_in_run). Each is classified:

- kind: whole (the text of a value the detector found earlier in the session), part (a run of such a value, the
  [TYPE_N_PART] re-mask), or unknown (neither, such as two placeholders merged into one edit)
- the adapter:rule that first found the value in the session, the value's shape (shapes.py) and length
- repeats: re-mask edits of that value in its session
- tp / over / fp against gold, and whether PG_REMASK_POLICY=admitted would keep the value on the re-mask list
  (high-confidence rule or secret-like shape; a value restored into a command is not visible here)

Values are read from the sessions file to compute shapes and are never printed or written: the output is counts,
shapes, lengths and rule names.

    python scripts/remask_admission/breakdown.py --data-root ../promptguard-data RUN_FOLDER [RUN_FOLDER ...] \\
        [--sample 100] [--out breakdown.md]
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
import shapes  # noqa: E402

MAX_SPAN = 8192  # pgdetector core.MAX_SPAN, as fp_analysis rebuilds the union
SCORED = {"prompt", "instructions", "tool_output"}


def jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """fp_analysis._merge: overlapping (not touching) spans are one."""
    merged: list[list[int]] = []
    for start, end in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def find_runs(folders: list[Path]) -> list[Path]:
    runs = []
    for folder in folders:
        for meta in sorted(folder.rglob("run_meta.json")):
            data = json.loads(meta.read_text(encoding="utf-8"))
            if data.get("system", {}).get("system") == "promptguard" and (meta.parent / "per_finding.jsonl").is_file():
                runs.append(meta.parent)
    return runs


def edit_class(edit: dict[str, Any]) -> str:
    return "tp" if edit["within_gold"] else "over" if edit["overlaps_gold"] else "fp"


def analyse_run(run: Path, data_root: Path, rules: set[tuple[str, str]]) -> list[dict[str, Any]]:
    meta = json.loads((run / "run_meta.json").read_text(encoding="utf-8"))
    sessions_path = Path(meta["dataset"]["sessions_path"])
    if not sessions_path.is_absolute():
        sessions_path = data_root / sessions_path
    texts: dict[tuple[str, int], str] = {}
    order: dict[str, list[int]] = {}
    for record in jsonl(sessions_path):
        order[record["session_id"]] = [item["item_id"] for item in record["items"]]
        for item in record["items"]:
            texts[(record["session_id"], item["item_id"])] = item["text"]

    findings: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in jsonl(run / "per_finding.jsonl"):
        if row["valid"] and row["scored"]:
            findings[(row["session_id"], row["item_id"])].append(row)
    edits: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in jsonl(run / "per_edit.jsonl"):
        if row["scored"]:
            edits[(row["session_id"], row["item_id"])].append(row)

    rows: list[dict[str, Any]] = []
    for session_id, item_ids in order.items():
        # Values the detector found, in session order, with the rules that found them so far.
        first_seen: dict[str, tuple[int, int, str]] = {}
        rules_so_far: dict[str, set[tuple[str, str]]] = defaultdict(set)
        pending: list[tuple[int, dict[str, Any]]] = []
        for position, item_id in enumerate(item_ids):
            key = (session_id, item_id)
            text = texts[key]
            found = findings.get(key, [])
            union = [span for span in merge([(f["start"], f["end"]) for f in found]) if span[1] - span[0] <= MAX_SPAN]
            for start, end in union:
                raw = text[start:end]
                contributors = {(f["adapter"], f["rule_id"]) for f in found if f["start"] < end and start < f["end"]}
                rules_so_far[raw] |= contributors
                if raw not in first_seen:
                    first_seen[raw] = (position, start, ",".join(sorted(f"{a}:{r}" for a, r in contributors)))
            for edit in edits.get(key, []):
                if (edit["start"], edit["end"]) in set(union):
                    continue
                pending.append((position, edit))
        values = sorted(first_seen, key=len, reverse=True)
        session_rows = []
        for position, edit in pending:
            fragment = texts[(session_id, edit["item_id"])][edit["start"]:edit["end"]]
            earlier = lambda raw: first_seen[raw][:2] < (position, edit["start"])  # noqa: E731
            if fragment in first_seen and earlier(fragment):
                kind, owner = "whole", fragment
            else:
                owner = next((raw for raw in values if len(fragment) >= 8 and fragment in raw and earlier(raw)), None)
                kind = "part" if owner else "unknown"
            if owner is None:
                session_rows.append({"kind": kind, "rule": "(unknown)", "shape": "(unknown)", "length": len(fragment),
                                     "class": edit_class(edit), "admitted": None, "owner": None})
                continue
            adapters_rules = rules_so_far[owner]
            high = any(shapes.is_high_confidence(rules, [adapter], rule) for adapter, rule in adapters_rules)
            shape = shapes.value_shape(owner)
            session_rows.append({"kind": kind, "rule": first_seen[owner][2] or "(none)", "shape": shape,
                                 "length": len(owner), "fragment_length": len(fragment), "class": edit_class(edit),
                                 "admitted": high or shape == "secret_like", "owner": owner})
        repeats = Counter(row["owner"] for row in session_rows if row["owner"] is not None)
        for row in session_rows:
            row["repeats"] = repeats[row["owner"]] if row["owner"] is not None else 1
            # The value itself never leaves this function: a per-session index stands for it.
            row["value_id"] = f"{session_id}#{values.index(row['owner'])}" if row["owner"] is not None else None
            del row["owner"]
            row["dataset"] = Path(meta["dataset"]["sessions_path"]).stem
        rows += session_rows
    return rows


def bucket(repeats: int) -> str:
    for limit, name in ((1, "1"), (5, "2-5"), (20, "6-20"), (100, "21-100")):
        if repeats <= limit:
            return name
    return ">100"


def table(header: list[str], body: list[list[Any]]) -> list[str]:
    return ["| " + " | ".join(header) + " |", "|" + "---|" * len(header), *("| " + " | ".join(str(c) for c in row) + " |" for row in body)]


def report(rows: list[dict[str, Any]], sample: int, seed: int) -> str:
    out = ["# Re-mask edits: breakdown", "",
           f"{len(rows)} re-mask edits (edits not equal to a merged finding span). Values are not shown.", ""]
    by = Counter((row["kind"], row["class"]) for row in rows)
    out += ["## Kind", ""] + table(["kind", "tp", "over", "fp", "total"],
                                   [[kind, by[(kind, "tp")], by[(kind, "over")], by[(kind, "fp")],
                                     sum(by[(kind, c)] for c in ("tp", "over", "fp"))] for kind in ("whole", "part", "unknown")])

    def grouped(field: str, title: str, limit: int = 25) -> list[str]:
        fp = [row for row in rows if row["class"] == "fp"]
        counts = Counter(row[field] for row in fp)
        body = []
        for name, count in counts.most_common(limit):
            group = [row for row in fp if row[field] == name]
            values = {row["value_id"] for row in group}
            tp = sum(1 for row in rows if row[field] == name and row["class"] == "tp")
            lengths = [row["length"] for row in group]
            body.append([name, count, sum(r["kind"] == "whole" for r in group), sum(r["kind"] == "part" for r in group),
                         len(values), round(statistics.median(lengths)), tp,
                         sum(1 for r in group if r["admitted"] is False)])
        return ["", f"## False positives by {title}", ""] + table(
            [title, "fp edits", "whole", "part", "distinct values", "median length", "tp edits (same group)",
             "fp edits admitted would drop"], body)

    out += grouped("rule", "first rule")
    out += grouped("shape", "shape")
    fp_values: dict[str, int] = {}
    for row in rows:
        if row["class"] == "fp" and row["value_id"]:
            fp_values[row["value_id"]] = row["repeats"]
    buckets = Counter(bucket(r) for r in fp_values.values())
    edits_in = Counter(bucket(row["repeats"]) for row in rows if row["class"] == "fp" and row["value_id"])
    out += ["", "## Repeats of a false-positive value in its session", ""] + table(
        ["re-mask edits per value", "values", "fp edits"],
        [[name, buckets[name], edits_in[name]] for name in ("1", "2-5", "6-20", "21-100", ">100")])

    kept = [row for row in rows if row["admitted"] is not False]
    dropped = [row for row in rows if row["admitted"] is False]
    out += ["", "## Under PG_REMASK_POLICY=admitted (estimate)", "",
            "A value restored into a command is admitted too; that is not visible in these files, so this is an upper "
            "bound on what admitted drops.", ""] + table(
        ["", "tp", "over", "fp"],
        [["kept", *(sum(r["class"] == c for r in kept) for c in ("tp", "over", "fp"))],
         ["dropped", *(sum(r["class"] == c for r in dropped) for c in ("tp", "over", "fp"))]])
    lost = Counter((row["rule"], row["shape"]) for row in dropped if row["class"] == "tp")
    if lost:
        out += ["", "True-positive re-masks admitted would drop, by first rule and shape:", ""] + table(
            ["first rule", "shape", "tp edits"], [[rule, shape, n] for (rule, shape), n in lost.most_common(25)])

    fp_rows = [row for row in rows if row["class"] == "fp"]
    picked = random.Random(seed).sample(fp_rows, min(sample, len(fp_rows)))
    out += ["", f"## Sample of {len(picked)} false-positive re-masks (seed {seed})", ""] + table(
        ["dataset", "kind", "first rule", "shape", "value length", "fragment length", "repeats in session", "admitted"],
        [[r["dataset"], r["kind"], r["rule"], r["shape"], r["length"], r.get("fragment_length", r["length"]),
          r["repeats"], r["admitted"]] for r in picked])
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=Path, help="run folders, or folders that contain them")
    parser.add_argument("--data-root", type=Path, default=Path("."), help="promptguard-data checkout (relative sessions paths)")
    parser.add_argument("--sample", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    runs = find_runs(args.runs)
    if not runs:
        print("no promptguard run folder with per_finding.jsonl found", file=sys.stderr)
        return 1
    rules = shapes.high_confidence_rules()
    rows = [row for run in runs for row in analyse_run(run, args.data_root, rules)]
    text = report(rows, args.sample, args.seed)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"{len(runs)} runs, {len(rows)} re-mask edits -> {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
