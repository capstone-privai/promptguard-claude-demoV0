from __future__ import annotations

import json
import math
import statistics
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector import load_detector  # noqa: E402


BASELINE = {"credsweeper", "gitleaks", "promptguard-rules"}
SHELL = "shell-aware"


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * q
    low, high = math.floor(position), math.ceil(position)
    return ordered[low] if low == high else ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def latency(values: list[float]) -> dict[str, float]:
    return {
        "samples": len(values), "mean_ms": round(statistics.fmean(values), 4),
        "p50_ms": round(percentile(values, 0.50), 4), "p95_ms": round(percentile(values, 0.95), 4),
        "max_ms": round(max(values), 4),
    }


def utf16_to_cp(text: str, offset: int) -> int:
    used = 0
    for index, char in enumerate(text):
        if used >= offset:
            return index
        used += len(char.encode("utf-16-le")) // 2
    return len(text)


def spans(text: str, findings: Iterable[dict[str, Any]]) -> list[tuple[int, int]]:
    return [(utf16_to_cp(text, row["start"]), utf16_to_cp(text, row["end"])) for row in findings]


def gold_spans(case: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    cursors: dict[str, int] = {}
    for gold in case["gold"]:
        start = case["text"].index(gold["value"], cursors.get(gold["value"], 0))
        cursors[gold["value"]] = start + len(gold["value"])
        output.append({"start": start, "end": start + len(gold["value"]), "family": gold["family"]})
    return output


def overlaps(span: tuple[int, int], gold: dict[str, Any]) -> bool:
    return span[0] < gold["end"] and span[1] > gold["start"]


def covers(span: tuple[int, int], gold: dict[str, Any]) -> bool:
    return span[0] <= gold["start"] and span[1] >= gold["end"]


def metrics(records: list[dict[str, Any]], key: str) -> dict[str, Any]:
    totals = Counter()
    fp_cases = []
    for record in records:
        predicted = record[key]
        golds = record["gold"]
        totals["requests"] += 1
        totals["candidates"] += len(predicted)
        false_here = 0
        for span in predicted:
            if any(overlaps(span, gold) for gold in golds):
                totals["tp_candidates"] += 1
            else:
                totals["fp"] += 1
                false_here += 1
        if false_here:
            fp_cases.append(record["id"])
        for gold in golds:
            totals["gold"] += 1
            exact = any(span == (gold["start"], gold["end"]) for span in predicted)
            overlap = any(overlaps(span, gold) for span in predicted)
            exposure = any(covers(span, gold) for span in predicted)
            totals["exact"] += int(exact)
            totals["overlap"] += int(overlap)
            totals["exposure"] += int(exposure)
            totals["fn"] += int(not exposure)
            totals["partial_leak"] += int(overlap and not exposure)
            totals["boundary_only"] += int(exposure and not exact)
    precision = totals["tp_candidates"] / totals["candidates"] if totals["candidates"] else 1.0
    recall = totals["exposure"] / totals["gold"] if totals["gold"] else 1.0
    f2 = 5 * precision * recall / (4 * precision + recall) if precision + recall else 0.0
    return {
        "requests": totals["requests"], "gold": totals["gold"], "candidate_count": totals["candidates"],
        "tp_candidate_count": totals["tp_candidates"], "fp": totals["fp"], "fn": totals["fn"],
        "candidate_recall": round(totals["overlap"] / totals["gold"], 6),
        "secret_value_exposure_recall": round(recall, 6),
        "exact_span_recall": round(totals["exact"] / totals["gold"], 6),
        "precision": round(precision, 6), "f2": round(f2, 6),
        "fp_per_request": round(totals["fp"] / totals["requests"], 6),
        "candidates_per_request": round(totals["candidates"] / totals["requests"], 6),
        "partial_leak_count": totals["partial_leak"], "boundary_only_count": totals["boundary_only"],
        "false_positive_case_ids": sorted(fp_cases),
    }


def scan_adapters(adapters: list[Any], text: str) -> None:
    with ThreadPoolExecutor(max_workers=max(1, len(adapters))) as pool:
        list(pool.map(lambda adapter: adapter.scan(text), adapters))


def main() -> int:
    fixture = json.loads((Path(__file__).with_name("shell_aware_cases.json")).read_text(encoding="utf-8"))
    cases = fixture["cases"]
    detector = load_detector()
    active = set(detector.names)
    missing_old = sorted(BASELINE - active)
    shell_adapter = next(adapter for adapter in detector.adapters if adapter.name == SHELL)
    old_adapters = [adapter for adapter in detector.adapters if adapter.name in BASELINE]
    full_adapters = [*old_adapters, shell_adapter]
    texts = [case["text"] for case in cases]
    ballots_list, adapter_errors = detector.collect(texts)
    records = []
    family = defaultdict(Counter)
    added_ids, legacy_regressions = [], []
    shell_tp_golds = independent_golds = 0

    for case, ballots in zip(cases, ballots_list):
        text = case["text"]
        golds = gold_spans(case)
        old_ballots = {name: rows for name, rows in ballots.items() if name in BASELINE}
        new_ballots = {name: rows for name, rows in ballots.items() if name in BASELINE | {SHELL}}
        shell_ballots = {SHELL: ballots.get(SHELL, [])}
        old, old_errors = detector.decide(text, "evaluation", old_ballots, 1, candidate_scope=True, include_evidence=True)
        new, new_errors = detector.decide(text, "evaluation", new_ballots, 1, candidate_scope=True, include_evidence=True)
        shell, shell_errors = detector.decide(text, "evaluation", shell_ballots, 1, candidate_scope=True, include_evidence=True)
        if old_errors or new_errors or shell_errors:
            raise RuntimeError("invalid candidate offsets")
        old_spans, new_spans, shell_spans = spans(text, old), spans(text, new), spans(text, shell)
        for old_span in old_spans:
            if not any(start <= old_span[0] and end >= old_span[1] for start, end in new_spans):
                legacy_regressions.append(case["id"])
        for gold in golds:
            old_hit = any(covers(span, gold) for span in old_spans)
            new_hit = any(covers(span, gold) for span in new_spans)
            shell_hit = any(covers(span, gold) for span in shell_spans)
            if new_hit and not old_hit:
                added_ids.append({"case_id": case["id"], "family": gold["family"]})
            if shell_hit:
                shell_tp_golds += 1
                independent_golds += int(not old_hit)
            stats = family[gold["family"]]
            stats["gt"] += 1
            stats["tp"] += int(shell_hit)
            stats["fn"] += int(not shell_hit)
        for raw in ballots.get(SHELL, []):
            raw_span = (raw.start, raw.end)
            if not any(overlaps(raw_span, gold) for gold in golds):
                family[raw.family or raw.rule_id]["fp"] += 1
        records.append({"id": case["id"], "gold": golds, "old": old_spans, "new": new_spans, "shell": shell_spans})

    # Warm each path once; measured values exclude model loading.
    if cases:
        scan_adapters(old_adapters, cases[0]["text"])
        scan_adapters(full_adapters, cases[0]["text"])
        shell_adapter.scan(cases[0]["text"])
    old_latency, full_latency, shell_latency = [], [], []
    for index, case in enumerate(cases):
        # Alternate AB/BA order so the full union does not always receive the
        # second-call cache/thermal advantage.
        if index % 2:
            started = time.perf_counter(); scan_adapters(old_adapters, case["text"]); old_latency.append((time.perf_counter() - started) * 1000)
            started = time.perf_counter(); scan_adapters(full_adapters, case["text"]); full_latency.append((time.perf_counter() - started) * 1000)
        else:
            started = time.perf_counter(); scan_adapters(full_adapters, case["text"]); full_latency.append((time.perf_counter() - started) * 1000)
            started = time.perf_counter(); scan_adapters(old_adapters, case["text"]); old_latency.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter(); shell_adapter.scan(case["text"]); shell_latency.append((time.perf_counter() - started) * 1000)

    old_metrics, new_metrics, shell_metrics = metrics(records, "old"), metrics(records, "new"), metrics(records, "shell")
    family_output = {}
    for name, row in sorted(family.items()):
        precision = row["tp"] / (row["tp"] + row["fp"]) if row["tp"] + row["fp"] else 1.0
        recall = row["tp"] / row["gt"] if row["gt"] else 0.0
        family_output[name] = {
            "gt": row["gt"],
            "tp": row["tp"],
            "fn": row["fn"],
            "fp": row["fp"],
            "precision": round(precision, 6),
            "recall": round(recall, 6),
        }
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    common = {
        "schema_version": 1, "fixture_version": fixture["schema_version"], "git_revision": revision,
        "active_adapters": detector.names, "skipped_adapters": detector.skipped,
        "required_baseline_missing": missing_old, "adapter_errors": adapter_errors,
        "synthetic_only": True, "raw_values_persisted": False,
    }
    comparison = {
        **common, "candidate_policy": detector.candidate_policy, "baseline_3_detector_union": old_metrics, "with_shell_aware_union": new_metrics,
        "shell_aware_only": shell_metrics, "shell_added_true_positive_count": len(added_ids),
        "shell_added_true_positives": added_ids,
        "old_candidate_coverage_regression_count": len(set(legacy_regressions)),
        "old_candidate_coverage_regression_case_ids": sorted(set(legacy_regressions)),
        "shell_independent_secret_ratio": round(independent_golds / old_metrics["gold"], 6) if old_metrics["gold"] else 0.0,
    }
    shell_output = {**common, "metrics": shell_metrics, "added_true_positive_count": len(added_ids), "added_case_ids": [row["case_id"] for row in added_ids]}
    old_latency_summary, full_latency_summary = latency(old_latency), latency(full_latency)
    latency_output = {
        **common, "measurement": "warm in-process per-input; adapter scans concurrent within each union; excludes model load and HTTP/MCP",
        "baseline_3_detector_union": old_latency_summary, "with_shell_aware_union": full_latency_summary,
        "shell_aware_only": latency(shell_latency),
        "paired_delta_ms": latency([new - old for new, old in zip(full_latency, old_latency)]),
        "p50_union_difference_ms": round(full_latency_summary["p50_ms"] - old_latency_summary["p50_ms"], 4),
        "p95_union_difference_ms": round(full_latency_summary["p95_ms"] - old_latency_summary["p95_ms"], 4),
        "interpretation": "Union adapters run concurrently. When shell-aware latency is below the existing critical path, the union difference is dominated by Gitleaks process startup and scheduling noise.",
    }
    outputs = ROOT / "outputs"
    outputs.mkdir(exist_ok=True)
    for name, value in {
        "shell-aware-metrics.json": shell_output,
        "detector-union-comparison.json": comparison,
        "shell-aware-family-breakdown.json": {**common, "families": family_output},
        "shell-aware-latency.json": latency_output,
    }.items():
        (outputs / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "active": detector.names, "missing_baseline": missing_old,
        "old_recall": old_metrics["secret_value_exposure_recall"], "new_recall": new_metrics["secret_value_exposure_recall"],
        "added_tp": len(added_ids), "shell_fp": shell_metrics["fp"], "regressions": len(set(legacy_regressions)),
    }))
    return 0 if not missing_old and not adapter_errors and not legacy_regressions else 2


if __name__ == "__main__":
    raise SystemExit(main())
