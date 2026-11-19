"""One report for the integration measurement (run.py writes the runs; this reads them). Values are read in memory
to tell shapes and count distinct values, and are never written: the report holds counts, rule names and shapes.

Per run (scored channels only):
- recall: gold spans fully masked (exact or over) / gold spans
- character precision: masked characters inside gold / masked characters
- F2 from those two
- missed: gold spans not fully masked, and their distinct values
- re-mask FP: edits outside gold that are not a merged finding span (the Native Mod re-masked a known value)
- FP per 1,000 lines on real traffic: the scorer's fp_per_1k_lines (edits outside gold) on each traffic set
- filtered: findings removed per filter name (filters.jsonl)
- newly missed: gold covered under the baseline configuration (configs.BASELINE) and not here, by gold type, the rule
  that found it under the baseline, the filter over it here and the value's shape
Configuration 7 on CredData-trajectory is also split by candidate tier: immediate (a rule of
src/detector/high-confidence-rules.json, or confidence strong) and ambiguous (any other moderate or ambiguous
finding), with each tier's true and false positives and, per rule, the gold spans only that rule found in the
ambiguous tier.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterator

from configs import BASELINE, CONFIGS

MAX_SPAN = 8192  # pgdetector core.MAX_SPAN


def jsonl(path: Path) -> Iterator[dict[str, Any]]:
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def merge(spans: list[tuple[int, int]], cap: int | None = None) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(set(spans)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged if cap is None or e - s <= cap]


def overlap(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> int:
    total, j = 0, 0
    for start, end in a:
        while j < len(b) and b[j][1] <= start:
            j += 1
        k = j
        while k < len(b) and b[k][0] < end:
            total += min(end, b[k][1]) - max(start, b[k][0])
            k += 1
    return total


def shape(value: str) -> str:
    n = len(value)
    size = "<4" if n < 4 else "4-7" if n < 8 else "8-15" if n < 16 else "16-31" if n < 32 else "32+"
    if n >= 8 and re.fullmatch(r"[0-9a-fA-F]+", value) and not value.isdigit():
        kind = "16진수"
    elif value.isdigit():
        kind = "숫자"
    elif re.fullmatch(r"[A-Za-z]+", value):
        kind = "영문자"
    elif re.fullmatch(r"[A-Za-z0-9]+", value):
        kind = "영숫자"
    elif n >= 16 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
        kind = "base64형"
    elif any(c.isspace() for c in value):
        kind = "공백 포함"
    else:
        kind = "기호 포함"
    return f"{kind} {size}자"


class Texts:
    """Item texts per sessions file, read once."""

    def __init__(self) -> None:
        self.cache: dict[str, dict[tuple[str, int], str]] = {}

    def get(self, path: str) -> dict[tuple[str, int], str]:
        if path not in self.cache:
            self.cache[path] = {(row["session_id"], item["item_id"]): item["text"] for row in jsonl(Path(path)) for item in row["items"]}
        return self.cache[path]


def find_run(folder: Path) -> Path | None:
    runs = sorted(meta.parent for meta in folder.rglob("run_meta.json") if (meta.parent / "eval_config.json").is_file()) if folder.is_dir() else []
    return runs[-1] if runs else None


def numbers(run: Path, texts: Texts) -> dict[str, Any]:
    meta = json.loads((run / "run_meta.json").read_text(encoding="utf-8"))
    metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
    items = texts.get(meta["dataset"]["sessions_path"])
    gold = [r for r in jsonl(run / "per_span.jsonl") if r["scored"]]
    edits = [r for r in jsonl(run / "per_edit.jsonl") if r["scored"]]
    findings = [r for r in jsonl(run / "per_finding.jsonl") if r["valid"] and r["scored"]]
    covered = {(r["session_id"], r["item_id"], r["span_id"]) for r in gold if r["status"] in ("exact", "over")}
    gold_by_item: dict[tuple[str, int], list[tuple[int, int]]] = defaultdict(list)
    for r in gold:
        gold_by_item[(r["session_id"], r["item_id"])].append((r["start"], r["end"]))
    edits_by_item: dict[tuple[str, int], list[tuple[int, int]]] = defaultdict(list)
    for r in edits:
        edits_by_item[(r["session_id"], r["item_id"])].append((r["start"], r["end"]))
    masked = inside = 0
    for key, spans in edits_by_item.items():
        merged = merge(spans)
        masked += sum(e - s for s, e in merged)
        inside += overlap(merged, merge(gold_by_item.get(key, [])))
    recall = len(covered) / len(gold) if gold else None
    precision = inside / masked if masked else None
    f2 = (5 * precision * recall / (4 * precision + recall)) if recall is not None and precision and (4 * precision + recall) else None
    value_of = lambda r: items.get((r["session_id"], r["item_id"]), "")[r["start"]:r["end"]]  # noqa: E731
    missed = [r for r in gold if (r["session_id"], r["item_id"], r["span_id"]) not in covered]
    unions: dict[tuple[str, int], set[tuple[int, int]]] = defaultdict(set)
    by_item: dict[tuple[str, int], list[tuple[int, int]]] = defaultdict(list)
    for r in findings:
        by_item[(r["session_id"], r["item_id"])].append((r["start"], r["end"]))
    for key, spans in by_item.items():
        unions[key] = set(merge(spans, MAX_SPAN))
    remask_fp = sum(1 for r in edits if not r["overlaps_gold"] and (r["start"], r["end"]) not in unions.get((r["session_id"], r["item_id"]), set()))
    filtered: Counter = Counter()
    filtered_rules: Counter = Counter()
    removed: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in jsonl(run / "filters.jsonl"):
        filtered.update(row["filtered"])
        removed[(row["session_id"], row["item_id"])] += row["removed"]
        for r in row["removed"]:
            filtered_rules[(r["filter"], f"{r['adapter']}:{r['rule_id']}")] += 1
    # secret-assignment declines a reference or code value inside the rule (assignment_*), so it never reaches
    # the ensemble's removed list: what the counts hold beyond removed is that rule's.
    for name, count in filtered.items():
        extra = count - sum(c for (f, _), c in filtered_rules.items() if f == name)
        if extra > 0:
            filtered_rules[(name, "promptguard-rules:secret-assignment (규칙 안에서)")] += extra
    rules_over: dict[tuple[str, int, int], set[str]] = defaultdict(set)
    for r in findings:
        for span_id in r["gold_span_ids"]:
            rules_over[(r["session_id"], r["item_id"], span_id)].add(f"{r['adapter']}:{r['rule_id']}")
    return {
        "gold": gold, "covered": covered, "recall": recall, "precision": precision, "f2": f2,
        "missed_spans": len(missed), "missed_values": len({value_of(r) for r in missed}),
        "remask_fp": remask_fp, "fp_per_1k": metrics.get("fp_per_1k_lines"), "filtered": filtered, "filtered_rules": filtered_rules,
        "removed": removed, "rules_over": rules_over, "findings": findings, "value_of": value_of,
        "scorer": (metrics.get("recall"), metrics.get("precision")),
    }


def newly_missed(base: dict[str, Any], run: dict[str, Any]) -> Counter:
    out: Counter = Counter()
    for r in base["gold"]:
        key = (r["session_id"], r["item_id"], r["span_id"])
        if key not in base["covered"] or key in run["covered"]:
            continue
        over = [x for x in run["removed"].get((r["session_id"], r["item_id"]), []) if x["start"] < r["end"] and r["start"] < x["end"]]
        filters = ", ".join(sorted({x["filter"] for x in over})) or "(거르기 없음)"
        found_by = ", ".join(sorted(base["rules_over"].get(key, ()))) or "(재마스킹)"
        out[(r["type"], found_by, filters, shape(base["value_of"](r)))] += 1
    return out


def tiers(run: dict[str, Any], high: set[tuple[str, str]]) -> tuple[dict[str, Counter], Counter]:
    tier_of = lambda r: "바로 가림" if (r["adapter"], r["rule_id"]) in high or r.get("confidence") == "strong" else "애매함"  # noqa: E731
    counts: dict[str, Counter] = {"바로 가림": Counter(), "애매함": Counter()}
    over: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for r in run["findings"]:
        counts[tier_of(r)]["TP" if r["overlaps_gold"] else "FP"] += 1
        for span_id in r["gold_span_ids"]:
            over[(r["session_id"], r["item_id"], span_id)].append(r)
    solo: Counter = Counter()
    for found in over.values():
        if any(tier_of(r) == "바로 가림" for r in found):
            continue
        rules = {f"{r['adapter']}:{r['rule_id']}" for r in found}
        if len(rules) == 1:
            solo[rules.pop()] += 1
    return counts, solo


def fmt(value: Any) -> str:
    return "-" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)


def build(out: Path, main_root: Path, branch_root: Path) -> Path:
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    texts = Texts()
    runs: dict[tuple[str, str], dict[str, Any]] = {}
    for config in manifest["configs"]:
        for name in [manifest["creddata"], *manifest["nine"]]:
            run = find_run(out / config / name)
            if run:
                runs[(config, name)] = numbers(run, texts)
    high = {(r["adapter"], r["rule_id"]) for r in json.loads((branch_root / "src/detector/high-confidence-rules.json").read_text(encoding="utf-8"))["high_confidence_rules"]}
    cred = manifest["creddata"]
    traffic = manifest["traffic"]
    lines = ["# 통합 측정 (eval/integration-1118)", "",
             f"- 데이터: CredData-trajectory `{cred}` (7개 설정), 기존 셋 {len(manifest['nine'])}개 (1·7번), 실제 트래픽 {', '.join(traffic) or '-'} (7개 설정)",
             "- recall은 정답 span을 다 덮었는가, precision은 가린 글자 중 정답 글자의 비율이다. 값은 적지 않는다.", "",
             f"## CredData-trajectory ({cred})", "",
             "| 설정 | recall | 글자 precision | F2 | 못 가린 span / 고유 값 | 재마스킹 오탐 | " + " | ".join(f"{t} 1,000줄당 오탐" for t in traffic) + " | 걸러낸 수 (거르기별) | 새로 놓친 정답 |",
             "|" + "---|" * (8 + len(traffic))]
    missed_rows, rule_rows, warnings = [], [], []
    for config in manifest["configs"]:
        n = runs.get((config, cred))
        label = f"{config} ({CONFIGS[config][2]})"
        if n is None:
            lines.append(f"| {label} | 실행 없음 |" + " |" * (7 + len(traffic)))
            continue
        base = runs.get((BASELINE.get(config, ""), cred))
        lost = newly_missed(base, n) if base else Counter()
        for (gold_type, found_by, filters, value_shape), count in lost.most_common():
            missed_rows.append(f"| {config} | {BASELINE[config]} | {gold_type} | {found_by} | {filters} | {value_shape} | {count} |")
        for (filter_name, rule), count in n["filtered_rules"].most_common():
            rule_rows.append(f"| {config} | {filter_name} | {rule} | {count} |")
        fp = [fmt(runs[(config, t)]["fp_per_1k"]) if (config, t) in runs else "-" for t in traffic]
        filtered = ", ".join(f"{k} {v}" for k, v in sorted(n["filtered"].items())) or "-"
        lines.append(f"| {label} | {fmt(n['recall'])} | {fmt(n['precision'])} | {fmt(n['f2'])} | {n['missed_spans']} / {n['missed_values']} | "
                     f"{n['remask_fp']} | " + " | ".join(fp) + f" | {filtered} | {sum(lost.values()) if base else '-'} |")
    for (config, name), n in runs.items():
        recall, precision = n["scorer"]
        if recall is not None and n["recall"] is not None and abs(recall - n["recall"]) > 1e-9:
            warnings.append(f"- {config} {name}: recall {n['recall']:.4f}, 채점기 {recall:.4f}")
        if precision is not None and n["precision"] is not None and abs(precision - n["precision"]) > 1e-9:
            warnings.append(f"- {config} {name}: precision {n['precision']:.4f}, 채점기 {precision:.4f}")
    lines += ["", "## 새로 놓친 정답 (기준 설정에서는 덮었고 이 설정에서는 못 덮은 span)", ""]
    lines += (["| 설정 | 기준 | 정답 유형 | 기준에서 찾은 규칙 | 이 설정에서 덮은 거르기 | 값 모양 | span |", "|---|---|---|---|---|---|---|", *missed_rows]
              if missed_rows else ["없음."])
    lines += ["", "## 걸러낸 후보 (거르기 × adapter:rule)", ""]
    lines += (["| 설정 | 거르기 | adapter:rule | 수 |", "|---|---|---|---|", *rule_rows] if rule_rows else ["없음."])
    if ("7-all", cred) in runs:
        counts, solo = tiers(runs[("7-all", cred)], high)
        lines += ["", "## 7번(전부 on) 후보 등급별", "",
                  "바로 가림: `src/detector/high-confidence-rules.json`의 규칙 또는 strong 등급. 애매함: 그 밖의 moderate·ambiguous.", "",
                  "| 등급 | TP | FP |", "|---|---|---|",
                  *[f"| {tier} | {c['TP']} | {c['FP']} |" for tier, c in counts.items()],
                  "", "애매함 구간에서 그 규칙만 찾은 정답 span (바로 가림 후보가 겹치지 않은 정답):", ""]
        lines += (["| adapter:rule | 정답 span |", "|---|---|", *[f"| {rule} | {count} |" for rule, count in solo.most_common()]] if solo else ["없음."])
    if manifest["nine"]:
        lines += ["", "## 기존 셋 (1번과 7번)", "",
                  "| 데이터셋 | 설정 | recall | 글자 precision | F2 | 못 가린 span / 고유 값 | 재마스킹 오탐 | 1,000줄당 오탐 |", "|---|---|---|---|---|---|---|---|"]
        for name in manifest["nine"]:
            for config in ("1-main", "7-all"):
                n = runs.get((config, name))
                if n:
                    lines.append(f"| {name} | {config} | {fmt(n['recall'])} | {fmt(n['precision'])} | {fmt(n['f2'])} | {n['missed_spans']} / {n['missed_values']} | {n['remask_fp']} | {fmt(n['fp_per_1k'])} |")
    if warnings:
        lines += ["", "## 채점기 값과 다른 곳 (이 보고서가 다시 센 값과 채점기 metrics.json)", "", *warnings]
    path = out / "report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
