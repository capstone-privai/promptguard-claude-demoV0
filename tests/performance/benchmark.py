from __future__ import annotations

import json
import re
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "credsweeper-adapter"))
from worker import Adapter  # noqa: E402

SAMPLE = (ROOT / "fixtures" / "positive" / ".env").read_text(encoding="utf-8")

def summary(values):
    ordered = sorted(values)
    return {"runs": len(values), "mean_ms": round(statistics.mean(values), 3), "p50_ms": round(statistics.median(values), 3), "p95_ms": round(ordered[max(0, int(len(ordered) * .95) - 1)], 3)}

def measured(fn, count=40):
    values = []
    for _ in range(count):
        start = time.perf_counter(); fn(); values.append((time.perf_counter() - start) * 1000)
    return summary(values)

def main():
    adapter = Adapter()
    deterministic = re.compile(r"(?i)(?:password|api_key|token)\s*=\s*([^\s]+)")
    results = {
        "A_baseline": measured(lambda: len(SAMPLE)),
        "B_mod_deterministic": measured(lambda: list(deterministic.finditer(SAMPLE))),
        "C_mod_credsweeper_persistent": measured(lambda: adapter.scan(SAMPLE, "benchmark")),
        "D_mod_credsweeper_guard": measured(lambda: (adapter.scan(SAMPLE, "mod"), adapter.scan(SAMPLE, "guard"))),
    }
    startup = measured(lambda: Adapter(), 5)
    large = {}
    for label, size in (("10KB", 10_000), ("100KB", 100_000), ("1MB", 1_000_000), ("5MB", 5_000_000)):
        unit = "HOST=db.internal PORT=5432 DATABASE=payments\n"
        text = (unit * (size // len(unit) + 1))[:size - 50] + "\nTOKEN=LargeToken_8qM3vK7pR2xN5sL9\n"
        start = time.perf_counter(); result = adapter.scan(text, "large_output"); elapsed = (time.perf_counter() - start) * 1000
        large[label] = {"bytes": len(text.encode()), "latency_ms": round(elapsed, 3), "findings": len(result["findings"]), "errors": result["errors"]}
    output = {"configurations": results, "persistent_worker_startup": startup, "large_output": large, "note": "Detector microbenchmark; not end-to-end UI latency. D runs independent Mod and Guard scans."}
    (ROOT / "outputs" / "latency-results.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output))

if __name__ == "__main__":
    main()
