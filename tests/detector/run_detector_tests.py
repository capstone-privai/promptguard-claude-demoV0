from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))
from pgdetector import load_detector  # noqa: E402
from pgdetector.core import utf16_len  # noqa: E402

EXPECTED = {
    ".env": [("MyS3cretPass!2026", "PASSWORD"), ("sk_test_PGDEMO_7xQ9mK2pR5vN8cL4", "API_KEY"), ("pgdemoToken_4mN8qR2vX7kP5sL9", "TOKEN")],
    "urls.txt": [("PgDemo!42xQ", "PASSWORD"), ("MySqlDemo!73q", "PASSWORD"), ("RedisDemo!72q", "PASSWORD"), ("BasicDemo!33z", "PASSWORD")],
    "tokens.txt": [("pgdemoBearerToken_7xQ9mK2pR5vN8cL4", "TOKEN"), ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMtZGVtbyJ9.invalidsignature", "JWT"), ("ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "GITHUB_TOKEN"), ("AKIAIOSFODNN7EXAMPLE", "AWS_KEY"), ("pgdemo-slack-AbCdEfGhIjKlMnOpQrStUvWx9876543210", "SLACK_TOKEN"), ("syntheticSecret_4rT8mK2pQ7vN5xL9", "SECRET")],
    "config.json": [("JsonPass!62qDemo", "PASSWORD"), ("sk_test_PGDEMO_7xQ9mK2pR5vN8cL4", "API_KEY")],
    "config.yaml": [("YamlPass!84zDemo", "PASSWORD"), ("YamlToken_7qM2vK9pR5xN8sL4", "TOKEN")],
    "app.log": [("LogPass!73mDemo", "PASSWORD"), ("LogToken_8qM3vK7pR2xN5sL9", "TOKEN")],
    "mcp.json": [("McpPass!52rDemo", "PASSWORD"), ("McpToken_6qN2vK8pR4xM7sL9", "TOKEN")],
    "repeat.txt": [("RepeatPass!92qDemo", "PASSWORD"), ("RepeatPass!92qDemo", "PASSWORD"), ("RepeatPass!92qDemo", "PASSWORD")],
    "unicode.txt": [("KoreanPass!82qDemo", "PASSWORD"), ("JapaneseToken_8qN2vK5pR7xM4sL9", "TOKEN"), ("EmojiKey_4qM8vK2pR7xN5sL9", "API_KEY"), ("CrLfPass!62mDemo", "PASSWORD")],
    "private.pem": [(value, "PRIVATE_KEY") for value in (
        "RkFLRV9QUk9NUFRHVUFSRF9ERU1PX1BSSVZBVEVfS0VZX0JPRFlfTk9UX1ZBTElEXzAx",
        "RkFLRV9QUk9NUFRHVUFSRF9ERU1PX1BSSVZBVEVfS0VZX0JPRFlfTk9UX1ZBTElEXzAy",
        "RkFLRV9QUk9NUFRHVUFSRF9ERU1PX1BSSVZBVEVfS0VZX0JPRFlfTk9UX1ZBTElEXzAz",
        "RkFLRV9QUk9NUFRHVUFSRF9ERU1PX1BSSVZBVEVfS0VZX0JPRFlfTk9UX1ZBTElEXzA0",
    )],
}

def expected_spans(text, specs):
    cursors = {}
    rows = []
    for value, kind in specs:
        start = text.index(value, cursors.get(value, 0))
        cursors[value] = start + len(value)
        rows.append({"type": kind, "start": utf16_len(text[:start]), "end": utf16_len(text[:start + len(value)]), "source": "fixture"})
    return rows

def score(gt, pr):
    tp, fp, fn = len(gt & pr), len(pr - gt), len(gt - pr)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    f2 = 5 * precision * recall / (4 * precision + recall) if precision + recall else 0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "f2": f2}

def predictions(detector, cases, ballots_of, required_votes=None, *, candidate_scope=False):
    predicted = set()
    for name, text, ballots in cases:
        findings, _ = detector.decide(text, "fixture", ballots_of(ballots), required_votes, candidate_scope=candidate_scope)
        predicted |= {(name, r["type"], r["start"], r["end"]) for r in findings}
    return predicted

def main():
    detector = load_detector()
    cases = []
    ground_truth = []
    per_file = []
    for name, specs in EXPECTED.items():
        text = (ROOT / "fixtures" / "positive" / name).read_text(encoding="utf-8")
        cases.append((name, text, specs))
    for path in sorted((ROOT / "fixtures" / "negative").iterdir()):
        cases.append((path.name, path.read_text(encoding="utf-8"), []))
    # Every adapter scans each fixture once; policies are then replayed on the same ballots.
    collected, adapter_errors = detector.collect([text for _, text, _ in cases])
    scored = []
    for (name, text, specs), ballots in zip(cases, collected):
        expected = expected_spans(text, specs)
        found, errors = detector.decide(text, "fixture", ballots)
        ground_truth += [(name, r["type"], r["start"], r["end"]) for r in expected]
        per_file.append({"file": name, "expected": len(expected), "found": len(found), "errors": sorted(set(adapter_errors + errors)), "votes": {adapter: len(rows) for adapter, rows in ballots.items()}})
        scored.append((name, text, ballots))
    gt = set(ground_truth)
    pr = predictions(detector, scored, lambda ballots: ballots)
    metrics = score(gt, pr)
    voters = len(detector.protection_names)
    policy_comparison = [{"required_votes": k, "label": "any" if k == 1 else "unanimous" if k == voters else f"at_least:{k}", **score(gt, predictions(detector, scored, lambda ballots: ballots, k))} for k in range(1, voters + 1)]
    per_adapter = {adapter.name: score(gt, predictions(detector, scored, lambda ballots, name=adapter.name: {name: ballots[name]}, 1, candidate_scope=True)) for adapter in detector.adapters}
    union_pr = predictions(detector, scored, lambda ballots: ballots, 1, candidate_scope=True)
    union_metrics = score(gt, union_pr)
    output = {**detector.describe(), "offset_unit": "utf16_code_units", **metrics, "candidate_union": union_metrics, "adapter_errors": adapter_errors, "policy_comparison": policy_comparison, "per_adapter": per_adapter, "false_positives": [{"file": f, "type": t, "start": s, "end": e} for f, t, s, e in sorted(pr - gt)], "false_negatives": [{"file": f, "type": t, "start": s, "end": e} for f, t, s, e in sorted(gt - pr)], "candidate_union_false_positives": [{"file": f, "type": t, "start": s, "end": e} for f, t, s, e in sorted(union_pr - gt)], "candidate_union_false_negatives": [{"file": f, "type": t, "start": s, "end": e} for f, t, s, e in sorted(gt - union_pr)], "per_file": per_file, "ground_truth": [{"file": f, "expected_type": t, "expected_start": s, "expected_end": e} for f, t, s, e in ground_truth]}
    (ROOT / "outputs" / "detector-metrics.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"consensus": output["consensus"], **metrics, "adapter_errors": adapter_errors}))
    for row in policy_comparison:
        print(f"  policy {row['label']:<12} tp={row['tp']:>2} fp={row['fp']:>2} fn={row['fn']:>2} f2={row['f2']:.3f}")
    for name, row in per_adapter.items():
        print(f"  adapter {name:<18} tp={row['tp']:>2} fp={row['fp']:>2} fn={row['fn']:>2} f2={row['f2']:.3f}")
    print(f"  candidate union      tp={union_metrics['tp']:>2} fp={union_metrics['fp']:>2} fn={union_metrics['fn']:>2} f2={union_metrics['f2']:.3f}")
    raise SystemExit(0 if metrics["fp"] == 0 and metrics["fn"] == 0 and not adapter_errors else 1)

if __name__ == "__main__":
    main()
