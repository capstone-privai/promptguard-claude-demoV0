from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "credsweeper-adapter"))
from worker import Adapter, utf16_len  # noqa: E402

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

def main():
    adapter = Adapter()
    ground_truth = []
    predicted = []
    per_file = []
    for name, specs in EXPECTED.items():
        text = (ROOT / "fixtures" / "positive" / name).read_text(encoding="utf-8")
        expected = expected_spans(text, specs)
        result = adapter.scan(text, "fixture")
        found = [{k: row[k] for k in ("type", "start", "end", "source")} for row in result["findings"]]
        ground_truth += [(name, r["type"], r["start"], r["end"]) for r in expected]
        predicted += [(name, r["type"], r["start"], r["end"]) for r in found]
        per_file.append({"file": name, "expected": len(expected), "found": len(found), "errors": result["errors"]})
    for path in sorted((ROOT / "fixtures" / "negative").iterdir()):
        result = adapter.scan(path.read_text(encoding="utf-8"), "fixture")
        predicted += [(path.name, r["type"], r["start"], r["end"]) for r in result["findings"]]
        per_file.append({"file": path.name, "expected": 0, "found": len(result["findings"]), "errors": result["errors"]})
    gt, pr = set(ground_truth), set(predicted)
    tp, fp, fn = len(gt & pr), len(pr - gt), len(gt - pr)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    f2 = 5 * precision * recall / (4 * precision + recall) if precision + recall else 0
    output = {"detector": "CredSweeper", "ml": False, "offset_unit": "utf16_code_units", "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "f2": f2, "false_positives": [{"file": f, "type": t, "start": s, "end": e} for f, t, s, e in sorted(pr - gt)], "false_negatives": [{"file": f, "type": t, "start": s, "end": e} for f, t, s, e in sorted(gt - pr)], "per_file": per_file, "ground_truth": [{"file": f, "expected_type": t, "expected_start": s, "expected_end": e} for f, t, s, e in ground_truth]}
    (ROOT / "outputs" / "detector-metrics.json").write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({k: output[k] for k in ("tp", "fp", "fn", "precision", "recall", "f1", "f2")}))
    raise SystemExit(0 if fp == 0 and fn == 0 else 1)

if __name__ == "__main__":
    main()
