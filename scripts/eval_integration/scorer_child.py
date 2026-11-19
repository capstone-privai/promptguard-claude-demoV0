"""One scorer run for one configuration and dataset (called by run.py in its own process, so every setting is read
fresh by the system's pgdetector the scorer loads).

    python scripts/eval_integration/scorer_child.py --data-root PGDATA --config 3-filters --system-root ROOT \\
        --sessions SESSIONS.jsonl [--gold GOLD.jsonl] --out FOLDER

Writes the scorer's run folder under FOLDER plus filters.jsonl (instrument.install_recorder) and eval_config.json
(the configuration and its settings, no text).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from configs import CONFIGS, SETTINGS  # noqa: E402
from instrument import install_boundary, install_recorder  # noqa: E402


def run_folders(out: Path) -> set[Path]:
    return {meta.parent for meta in out.rglob("run_meta.json")} if out.is_dir() else set()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--config", choices=tuple(CONFIGS), required=True)
    parser.add_argument("--system-root", type=Path, required=True)
    parser.add_argument("--sessions", type=Path, required=True)
    parser.add_argument("--gold", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    _, env, _ = CONFIGS[args.config]
    for name in SETTINGS:
        os.environ.pop(name, None)
    os.environ.update(env or {})
    root = args.data_root.resolve()
    out = args.out.resolve()
    os.chdir(root)  # the scorer's defaults are relative to the repository root
    sys.path.insert(0, str(root / "metric-detection"))
    from evaluation import cli
    from evaluation.adapters import promptguard_adapter

    rows: list[dict] = []
    install_recorder(promptguard_adapter, rows)
    if (env or {}).get("PG_REMASK_SHORT") == "boundary":
        install_boundary(promptguard_adapter)
    before = run_folders(out)
    scorer_args = ["run", "--system", "promptguard", "--system-root", str(args.system_root.resolve()),
                   "--sessions", str(args.sessions.resolve()), "--out", str(out)]
    if args.gold:
        scorer_args += ["--gold", str(args.gold.resolve())]
    code = cli.main(scorer_args)
    new = sorted(run_folders(out) - before)
    if len(new) != 1:
        print(f"expected one new run folder under {out}, found {len(new)}", file=sys.stderr)
        return code or 1
    with (new[0] / "filters.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    (new[0] / "eval_config.json").write_text(json.dumps({"config": args.config, "settings": env}, indent=2) + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
