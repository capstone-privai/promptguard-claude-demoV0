"""Integration measurement: the eight configurations of configs.py in one go, one table (report.py).

Run from anywhere; the scorer is promptguard-data's metric-detection (creddata-trajectory-data branch: covered recall,
character precision, F2, per_finding.jsonl). promptguard-data is only read.

    python scripts/eval_integration/run.py --data-root ../promptguard-data \\
        --creddata metric-detection/data_test/sessions_from_CredData-trajectory.jsonl \\
        --nine metric-detection/data_test/sessions_from_*.jsonl \\
        --out runs/eval-integration-1118 [--jobs 2] [--gitleaks ../tools/gitleaks-8.30.1]

- CredData-trajectory test (--creddata): all eight configurations.
- The nine sets (--nine): configurations 1, 7 and 8 only (configs.ALL_SETS).
- Real traffic (--traffic, default the --nine files named openhands-feedback and SWE-Gym): all eight, for the
  false positives per 1,000 lines column.
- Configuration 1 runs main 668c2c1 from a detached worktree (--main-root, made under --out when not given).
Finished runs are kept and skipped on the next call (--force runs them again). Relative paths are taken from
--data-root. No value is printed or written outside the scorer's own run folders.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from configs import ALL_SETS, CONFIGS, MAIN_COMMIT  # noqa: E402

BRANCH_ROOT = HERE.parents[1]
TRAFFIC_NAMES = ("openhands-feedback", "SWE-Gym")


def stem(path: Path) -> str:
    return path.stem.removeprefix("sessions_from_")


def main_worktree(out: Path, given: Path | None) -> Path:
    if given:
        return given.resolve()
    target = out / f"_main-{MAIN_COMMIT}"
    if not (target / "src" / "detector").is_dir():
        subprocess.run(["git", "-C", str(BRANCH_ROOT), "worktree", "add", "--detach", str(target), MAIN_COMMIT], check=True)
    return target


def done(folder: Path) -> bool:
    return any((meta.parent / "eval_config.json").is_file() for meta in folder.rglob("run_meta.json")) if folder.is_dir() else False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-root", type=Path, required=True, help="promptguard-data checkout (creddata-trajectory-data)")
    parser.add_argument("--creddata", type=Path, required=True, help="CredData-trajectory test sessions")
    parser.add_argument("--nine", type=Path, nargs="*", default=[], help="the nine sets' sessions files")
    parser.add_argument("--traffic", nargs="*", default=None, help=f"names among --nine run in every configuration (default: {', '.join(TRAFFIC_NAMES)})")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--main-root", type=Path, help=f"checkout of main {MAIN_COMMIT} (default: a worktree under --out)")
    parser.add_argument("--configs", nargs="*", choices=tuple(CONFIGS), default=list(CONFIGS))
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--gitleaks", type=Path, help="folder holding the gitleaks binary, put first on PATH")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args(argv)

    data_root = args.data_root.resolve()
    resolve = lambda p: p if p.is_absolute() else (data_root / p)  # noqa: E731
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    creddata = resolve(args.creddata)
    nine = [resolve(p) for p in args.nine]
    traffic_names = TRAFFIC_NAMES if args.traffic is None else tuple(args.traffic)
    traffic = [p for p in nine if any(name in stem(p) for name in traffic_names)]
    manifest = {"creddata": stem(creddata), "nine": [stem(p) for p in nine], "traffic": [stem(p) for p in traffic],
                "configs": args.configs, "data_root": str(data_root)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    jobs: list[tuple[str, Path]] = []
    for config in args.configs:
        sets = [creddata] + [p for p in nine if config in ALL_SETS or p in traffic]
        jobs += [(config, p) for p in dict.fromkeys(sets)]
    if not args.report_only:
        main_root = main_worktree(out, args.main_root) if "1-main" in args.configs else None
        env = dict(os.environ)
        if args.gitleaks:
            env["PATH"] = f"{args.gitleaks.resolve()}{os.pathsep}{env.get('PATH', '')}"

        def run(job: tuple[str, Path]) -> tuple[str, str, int]:
            config, sessions = job
            folder = out / config / stem(sessions)
            if done(folder) and not args.force:
                return config, stem(sessions), 0
            root = main_root if CONFIGS[config][0] == "main" else BRANCH_ROOT
            log = out / "logs" / f"{config}__{stem(sessions)}.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("w", encoding="utf-8") as handle:
                code = subprocess.run([args.python, str(HERE / "scorer_child.py"), "--data-root", str(data_root), "--config", config,
                                       "--system-root", str(root), "--sessions", str(sessions), "--out", str(folder)],
                                      cwd=data_root, env=env, stdout=handle, stderr=subprocess.STDOUT).returncode
            return config, stem(sessions), code

        failed = []
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            for config, name, code in pool.map(run, jobs):
                print(f"{'ok  ' if code == 0 else 'FAIL'} {config} {name}")
                if code:
                    failed.append((config, name))
        if failed:
            print(f"{len(failed)} run(s) failed; see {out / 'logs'}", file=sys.stderr)
    from report import build

    path = build(out, Path(args.main_root or out / f"_main-{MAIN_COMMIT}"), BRANCH_ROOT)
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
