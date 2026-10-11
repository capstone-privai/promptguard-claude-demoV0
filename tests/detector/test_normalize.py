from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))
from pgdetector.core import normalize, utf16_len  # noqa: E402

def row(start, end, kind="TOKEN", rule="unit"):
    return {"cp_start": start, "cp_end": end, "type": kind, "rule_id": rule, "confidence": "moderate", "value_hash": "0" * 64}

def main():
    checks = {}
    findings, errors = normalize([row(1, 4), row(1, 4)], "abcdef", "unit")
    checks["duplicate_deduped"] = len(findings) == 1 and not errors
    findings, errors = normalize([row(1, 5, "CREDENTIAL"), row(2, 4, "TOKEN")], "abcdef", "unit")
    checks["nested_merged"] = len(findings) == 1 and findings[0]["start"] == 1 and findings[0]["end"] == 5 and findings[0]["type"] == "TOKEN"
    findings, errors = normalize([row(1, 3), row(2, 5)], "abcdef", "unit")
    checks["overlap_merged"] = len(findings) == 1 and findings[0]["start"] == 1 and findings[0]["end"] == 5
    findings, errors = normalize([row(0, 2), row(4, 6)], "abcdef", "unit")
    checks["repeated_locations_preserved"] = len(findings) == 2
    findings, errors = normalize([row(1, 4)], "a\nbc\nd", "unit")
    checks["multiline_span_preserved"] = len(findings) == 1 and findings[0]["start"] == 1 and findings[0]["end"] == 4
    findings, errors = normalize([row(-1, 2), row(2, 2), row(0, 99)], "abcdef", "unit")
    checks["invalid_zero_out_of_range_rejected"] = len(findings) == 0 and "INVALID_OFFSET_RANGE" in errors
    text = "🔐abc"
    findings, errors = normalize([row(1, 4)], text, "unit")
    checks["utf16_conversion"] = findings[0]["start"] == utf16_len("🔐") and findings[0]["end"] == utf16_len("🔐abc")
    output = {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks, "offset_unit": "utf16_code_units"}
    (ROOT / "outputs" / "span-normalization-results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output))
    raise SystemExit(0 if output["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
