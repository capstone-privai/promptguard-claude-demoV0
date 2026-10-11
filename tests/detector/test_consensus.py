from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))
from pgdetector import AdapterUnavailable, ConsensusPolicy, Detector, DetectorAdapter, RawFinding, load_detector  # noqa: E402

TEXT = "token=abcd efgh ijkl mnop"

class StubAdapter(DetectorAdapter):
    """Votes for fixed spans; stands in for any real module."""

    def __init__(self, name, options, config_dir):
        super().__init__(name, options, config_dir)
        self.spans = [tuple(span) for span in options.get("spans", [])]
        self.fail = options.get("fail", False)

    def scan(self, text):
        if self.fail:
            raise RuntimeError("stub failure")
        return [RawFinding(start, end, "TOKEN", "stub") for start, end in self.spans]

class MissingToolAdapter(DetectorAdapter):
    def __init__(self, name, options, config_dir):
        raise AdapterUnavailable("stub tool not installed")

    def scan(self, text):
        return []

def stub(name, *spans, fail=False):
    return StubAdapter(name, {"spans": spans, "fail": fail}, ROOT)

def spans(detector, text=TEXT):
    result = detector.scan(text, "unit")
    return [(row["start"], row["end"]) for row in result["findings"]], result

def refuses(build):
    try:
        build()
    except ValueError:
        return True
    return False

def load(adapters, consensus):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "detector.json"
        path.write_text(json.dumps({"consensus": consensus, "adapters": adapters}), encoding="utf-8")
        return load_detector(path)

def main():
    checks = {}
    parse = ConsensusPolicy.parse
    checks["policy_any"] = parse("any").required_votes(3) == 1
    checks["policy_majority"] = parse("majority").required_votes(3) == 2 and parse("majority").required_votes(4) == 3
    checks["policy_unanimous"] = parse("unanimous").required_votes(3) == 3
    checks["policy_at_least_forms"] = all(parse(spec).required_votes(3) == 2 for spec in ("at_least:2", "2", 2, {"mode": "at_least", "n": 2}))
    checks["policy_unreachable_threshold_refused"] = refuses(lambda: parse("at_least:4").required_votes(3))
    checks["policy_unknown_mode_refused"] = refuses(lambda: parse("most"))

    # a and b overlap on "abcd efgh", c is alone on "mnop".
    adapters = lambda: [stub("a", (6, 10)), stub("b", (8, 15)), stub("c", (21, 25))]
    found, _ = spans(Detector(adapters(), parse("any")))
    checks["any_keeps_every_vote"] = found == [(6, 15), (21, 25)]
    found, _ = spans(Detector(adapters(), parse("at_least:2")))
    checks["at_least_2_keeps_overlap_union"] = found == [(6, 15)]
    found, _ = spans(Detector(adapters(), parse("unanimous")))
    checks["unanimous_rejects_partial_agreement"] = found == []

    found, _ = spans(Detector([stub("a", (6, 10)), stub("b", (10, 15))], parse("unanimous")))
    checks["adjacent_spans_do_not_agree"] = found == []
    found, _ = spans(Detector([stub("a", (6, 10), (8, 12)), stub("b")], parse("at_least:2")))
    checks["one_adapter_counts_once"] = found == []
    found, result = spans(Detector([stub("a", (6, 10)), stub("b", (6, 10))], parse("unanimous")))
    checks["rule_id_names_every_voter"] = found == [(6, 10)] and result["findings"][0]["rule_id"] == "a:stub+b:stub"

    _, result = spans(Detector([stub("a", (6, 10)), stub("b", fail=True)], parse("any")))
    checks["adapter_failure_fails_closed"] = result["ok"] is False and result["errors"] == ["ADAPTER_FAILURE:b"]
    _, result = spans(Detector([stub("a", (6, 99))], parse("any")))
    checks["invalid_adapter_span_fails_closed"] = result["ok"] is False and "INVALID_OFFSET_RANGE" in result["errors"]
    checks["duplicate_names_refused"] = refuses(lambda: Detector([stub("a"), stub("a")], parse("any")))

    plugin = "test_consensus:StubAdapter"
    detector = load([
        {"name": "x", "type": plugin, "options": {"spans": [[6, 10]]}},
        {"name": "y", "type": plugin, "options": {"spans": [[6, 10]]}},
        {"name": "off", "type": plugin, "enabled": False},
        {"name": "missing", "type": "test_consensus:MissingToolAdapter", "required": False},
    ], {"mode": "unanimous"})
    found, _ = spans(detector)
    checks["plugin_adapters_loaded_by_path"] = detector.names == ["x", "y"] and found == [(6, 10)]
    checks["optional_missing_adapter_skipped"] = [row["name"] for row in detector.skipped] == ["missing"]
    try:
        load([{"name": "missing", "type": "test_consensus:MissingToolAdapter"}], "any")
        checks["required_missing_adapter_refused"] = False
    except AdapterUnavailable:
        checks["required_missing_adapter_refused"] = True
    checks["threshold_above_active_adapters_refused"] = refuses(lambda: load([
        {"name": "x", "type": plugin},
        {"name": "missing", "type": "test_consensus:MissingToolAdapter", "required": False},
    ], "at_least:2"))

    output = {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks}
    (ROOT / "outputs" / "consensus-results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output))
    raise SystemExit(0 if output["status"] == "PASS" else 1)

if __name__ == "__main__":
    main()
