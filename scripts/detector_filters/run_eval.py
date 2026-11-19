"""Run promptguard-data's metric-detection scorer with the detector filters set, and record what they removed.

    python scripts/detector_filters/run_eval.py --data-root ../promptguard-data --filters on -- \\
        run --system promptguard --system-root . --sessions metric-detection/data_test/sessions_from_SWE-Gym.jsonl \\
        --out metric-detection/results/filters_on

--filters off | on | on+dummy sets PG_DETECTOR_FILTERS and PG_DETECTOR_FILTER_DUMMY for the scorer, which loads the
system's pgdetector in this process. The scorer is not changed. Next to the run's own files this writes
filters.jsonl: per scanned item, the count per filter name and each removed finding's adapter, rule id, filter name
and code point offsets. No text is written.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SETTINGS = {"off": ("off", "off"), "on": ("on", "off"), "on+dummy": ("on", "on")}


def install_recorder(module: Any, rows: list[dict[str, Any]]) -> None:
    adapter_class = module.PromptGuardAdapter
    run_session, scan = adapter_class.run_session, adapter_class._scan

    def recording_run_session(self: Any, session: Any) -> Any:
        self._filter_queue = [item.item_id for item in session.items if module.CHANNEL_MAP.get(item.channel) is not None]
        self._filter_session = session.session_id
        return run_session(self, session)

    def recording_scan(self: Any, text: str, source: str) -> Any:
        filters = getattr(self.detector, "filters", None)
        removed: list[dict[str, Any]] = []
        if filters is not None and not getattr(filters, "_recording", False):
            apply = filters.apply

            def apply_and_record(adapter: str, findings: Any, scanned: str, counts: Counter) -> Any:
                kept = apply(adapter, findings, scanned, counts)
                kept_ids = {id(finding) for finding in kept}
                for finding in findings:
                    if id(finding) not in kept_ids:
                        filters._removed.append({"adapter": adapter, "rule_id": finding.rule_id,
                                                 "filter": filters.reason(adapter, finding, scanned),
                                                 "start": finding.start, "end": finding.end})
                return kept

            filters.apply, filters._recording = apply_and_record, True
        if filters is not None:
            filters._removed = removed
        result = scan(self, text, source)
        item_id = self._filter_queue.pop(0) if getattr(self, "_filter_queue", None) else None
        counts = result.get("filtered", {}) if isinstance(result, dict) else {}
        rows.append({"session_id": getattr(self, "_filter_session", None), "item_id": item_id,
                     "filtered": counts, "removed": removed})
        return result

    adapter_class.run_session, adapter_class._scan = recording_run_session, recording_scan


def run_folders(out: Path) -> set[Path]:
    return {meta.parent for meta in out.rglob("run_meta.json")} if out.is_dir() else set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-root", type=Path, required=True, help="promptguard-data checkout")
    parser.add_argument("--filters", choices=tuple(SETTINGS), required=True)
    parser.add_argument("scorer_args", nargs=argparse.REMAINDER, help="-- then the scorer's arguments (run ...)")
    args = parser.parse_args(argv)
    scorer_args = args.scorer_args[1:] if args.scorer_args[:1] == ["--"] else args.scorer_args
    structure, dummy = SETTINGS[args.filters]
    os.environ["PG_DETECTOR_FILTERS"], os.environ["PG_DETECTOR_FILTER_DUMMY"] = structure, dummy
    root = args.data_root.resolve()
    os.chdir(root)  # the scorer's defaults are relative to the repository root
    sys.path.insert(0, str(root / "metric-detection"))
    from evaluation import cli
    from evaluation.adapters import promptguard_adapter

    out = Path(scorer_args[scorer_args.index("--out") + 1]) if "--out" in scorer_args else Path("metric-detection/results")
    before = run_folders(out)
    rows: list[dict[str, Any]] = []
    install_recorder(promptguard_adapter, rows)
    code = cli.main(scorer_args)
    new = sorted(run_folders(out) - before)
    if len(new) == 1:
        with (new[0] / "filters.jsonl").open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        (new[0] / "filters_setting.json").write_text(json.dumps({"filters": args.filters}) + "\n", encoding="utf-8")
        total = Counter()
        for row in rows:
            total.update(row["filtered"])
        print(f"filters {args.filters}: " + (", ".join(f"{name} {count}" for name, count in sorted(total.items())) or "nothing removed"))
    else:
        print(f"filters.jsonl not written: expected one new run folder under {out}, found {len(new)}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
