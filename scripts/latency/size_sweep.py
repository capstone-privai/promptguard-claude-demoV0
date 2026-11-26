"""Detector latency by input size (1-64 KB), per detector configuration, in-process and through the Mod's MCP bridge.

    python scripts/latency/size_sweep.py [--gitleaks ../tools/gitleaks-8.30.1] [--configs a b c d] [--sizes 1 2 4 ...]
        [--scan-runs 10] [--bridge-runs 50] [--seed 20261123] [--out outputs/latency]

Texts: per size, 20 different texts mixing Python, Java and JavaScript code, logs, .env, YAML and JSON pieces with
random names and numbers, cut to the size in bytes. Half of them get 1-3 synthetic secrets made here from the seed.
The seed is recorded; no text and no secret is written anywhere (only timings, counts and settings).

Configurations, each in its own process so every setting is read fresh:
  a  defaults (the four rule adapters, ML off)
  b  defaults + --policy verifier (skipped as "번들 없음" when the verifier bundle cannot be loaded)
  c  defaults + ml-span (the model repository's v10 unless PG_ML_CHECKPOINT says otherwise; skipped when absent)
  d  prototype: CredSweeper only

Measured:
  scan    detector.scan(text, "tool_output") only: 10 warm-up calls, then texts x --scan-runs (20 x 10 = 200) per size
  bridge  the Native Mod's path: a JSON-RPC tools/call scan_batch to src/detector/mcp-bridge.cjs, which posts to a
          detector worker (src/detector/worker.py) with the same configuration; --bridge-runs (50) round trips per size
Percentiles are nearest-rank. "Timeouts" counts calls over PG_DETECTOR_TIMEOUT_MS (default 5000, the bridge's);
a bridge call that comes back as DETECTOR_FAILURE counts as well.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import platform
import random
import socket
import string
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SIZES_KB = (1, 2, 4, 8, 16, 32, 64)
TEXTS_PER_SIZE = 20
WARMUP = 10
SEED = 20261123
TARGET_4KB_P90_MS = 300.0  # midterm goal
HOOK_BUDGET_MS = 10_000.0  # Claude Code's limit for one Mod hook
CONFIGS = {
    "a": ("기본값 (규칙 4개, ML 끔)", {}),
    "b": ("기본값 + --policy verifier", {"PG_DETECTOR_CANDIDATE_POLICY": "verifier"}),
    "c": ("기본값 + ml-span", {"PG_DETECTOR_ENABLE": "ml-span"}),
    "d": ("프로토타입: CredSweeper만", {"PG_DETECTOR_DISABLE": "gitleaks,promptguard-rules,shell-aware"}),
}

# ---- synthetic texts ---------------------------------------------------------------------------------------------

WORDS = ["order", "user", "cache", "queue", "invoice", "session", "report", "payment", "upload", "metric", "worker", "index",
         "tenant", "region", "shipment", "profile", "audit", "billing", "search", "export"]


def ident(rng: random.Random, style: str = "snake") -> str:
    parts = rng.sample(WORDS, 2)
    if style == "camel":
        return parts[0] + parts[1].capitalize()
    if style == "pascal":
        return "".join(p.capitalize() for p in parts)
    return "_".join(parts)


def python_piece(rng: random.Random) -> str:
    name, arg = ident(rng), ident(rng)
    return (f"def {name}({arg}, limit={rng.randint(1, 500)}):\n"
            f"    \"\"\"Return the {rng.choice(WORDS)} rows for {arg}.\"\"\"\n"
            f"    rows = [row for row in {arg} if row.get(\"{rng.choice(WORDS)}\") is not None]\n"
            f"    if len(rows) > limit:\n        rows = rows[:limit]\n    return sorted(rows, key=lambda r: r[\"id\"])\n\n")


def java_piece(rng: random.Random) -> str:
    cls, field = ident(rng, "pascal"), ident(rng, "camel")
    return (f"public class {cls}Service {{\n    private final int {field} = {rng.randint(0, 9999)};\n"
            f"    public List<{cls}> find{cls}s(String {ident(rng, 'camel')}) {{\n"
            f"        return repository.findAll().stream().filter(x -> x.getId() > {field}).collect(Collectors.toList());\n"
            f"    }}\n}}\n\n")


def js_piece(rng: random.Random) -> str:
    fn = ident(rng, "camel")
    return (f"export async function {fn}(req, res) {{\n  const {{ {ident(rng, 'camel')} }} = req.query;\n"
            f"  const result = await db.collection('{rng.choice(WORDS)}s').find({{ status: '{rng.choice(['open', 'closed', 'pending'])}' }}).limit({rng.randint(5, 200)});\n"
            f"  res.json({{ ok: true, count: result.length }});\n}}\n\n")


def log_piece(rng: random.Random) -> str:
    lines = []
    for _ in range(rng.randint(3, 8)):
        lines.append(f"2026-11-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}Z "
                     f"{rng.choice(['INFO', 'WARN', 'DEBUG', 'ERROR'])} {ident(rng)} handled request_id={rng.getrandbits(48):012x} "
                     f"in {rng.randint(1, 900)}ms status={rng.choice([200, 201, 204, 404, 500])}")
    return "\n".join(lines) + "\n"


def env_piece(rng: random.Random) -> str:
    return (f"{ident(rng).upper()}_HOST={rng.choice(WORDS)}.internal\n{ident(rng).upper()}_PORT={rng.randint(1024, 65000)}\n"
            f"LOG_LEVEL={rng.choice(['info', 'debug', 'warn'])}\nFEATURE_{rng.choice(WORDS).upper()}={rng.choice(['true', 'false'])}\n")


def yaml_piece(rng: random.Random) -> str:
    return (f"{ident(rng)}:\n  replicas: {rng.randint(1, 9)}\n  image: registry.example.test/{rng.choice(WORDS)}:{rng.randint(1, 40)}.{rng.randint(0, 9)}\n"
            f"  resources:\n    limits:\n      cpu: \"{rng.randint(1, 4)}\"\n      memory: {rng.choice([256, 512, 1024])}Mi\n")


def json_piece(rng: random.Random) -> str:
    value = {"id": rng.randint(1, 10**6), "name": ident(rng), "tags": rng.sample(WORDS, 3), "active": rng.random() > .5,
             "score": round(rng.random() * 100, 2)}
    return json.dumps(value) + "\n"


PIECES = (python_piece, java_piece, js_piece, log_piece, env_piece, yaml_piece, json_piece)


def secret_line(rng: random.Random) -> str:
    """One synthetic secret in a common form; values come from the seeded generator and are never written out."""
    alnum = string.ascii_letters + string.digits
    token = lambda n: "".join(rng.choice(alnum) for _ in range(n))  # noqa: E731
    return rng.choice([
        f"API_KEY={token(32)}",
        f"db_password = \"{token(12)}!{rng.randint(10, 99)}\"",
        f"GITHUB_TOKEN=ghp_{token(36)}",
        f"aws_access_key_id = AKIA{''.join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(16))}",
        f"  \"client_secret\": \"{token(40)}\",",
        f"Authorization: Bearer {token(48)}",
    ])


def make_texts(seed: int, size_kb: int) -> list[tuple[str, int]]:
    """(text, planted secret count) x 20 for one size. Same seed and size, same texts."""
    rng = random.Random(f"{seed}:{size_kb}")
    target = size_kb * 1024
    out = []
    for index in range(TEXTS_PER_SIZE):
        lines: list[str] = []
        size = 0
        while size < target:
            piece = rng.choice(PIECES)(rng)
            lines.extend(piece.splitlines(keepends=True))
            size += len(piece)
        planted = rng.randint(1, 3) if index % 2 == 0 else 0
        # Secrets go in among the lines that fit the size, so cutting the text keeps them.
        fitting, total = 0, 0
        for line in lines:
            if total + len(line) > target - 200:
                break
            total += len(line)
            fitting += 1
        for _ in range(planted):
            lines.insert(rng.randint(0, max(0, fitting - 1)), secret_line(rng) + "\n")
        text = "".join(lines).encode("ascii")[:target].decode("ascii")
        out.append((text, planted))
    return out


# ---- statistics ----------------------------------------------------------------------------------------------------

def percentile(ordered: list[float], q: float) -> float:
    return ordered[max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))]


def stats(values: list[float], timeout_ms: float, failures: int = 0) -> dict[str, Any]:
    ordered = sorted(values)
    return {"runs": len(values), "p50_ms": round(percentile(ordered, .50), 2), "p90_ms": round(percentile(ordered, .90), 2),
            "p95_ms": round(percentile(ordered, .95), 2), "p99_ms": round(percentile(ordered, .99), 2), "max_ms": round(ordered[-1], 2),
            "over_timeout": sum(1 for v in values if v > timeout_ms) + failures}


def timeout_ms() -> float:
    return float(os.environ.get("PG_DETECTOR_TIMEOUT_MS") or 5000)


# ---- child: in-process detector.scan ------------------------------------------------------------------------------

def child(args: argparse.Namespace) -> int:
    sys.path.insert(0, str(ROOT / "src" / "detector"))
    from pgdetector import load_detector

    result: dict[str, Any] = {"config": args.child}
    try:
        detector = load_detector()
    except Exception as exc:  # noqa: BLE001 - reported as unavailable, by type only
        result["unavailable"] = f"{type(exc).__name__}"
        print(json.dumps(result))
        return 0
    described = detector.describe()
    names = [row["name"] for row in described.get("adapters", [])]
    if args.child == "c" and "ml-span" not in names:
        result["unavailable"] = "ml-span 없음"
        print(json.dumps(result))
        return 0
    result["detector"] = {"adapters": described.get("adapters"), "skipped": described.get("skipped"),
                          "candidate_policy": described.get("candidate_policy"), "consensus": described.get("consensus"),
                          "filter_settings": described.get("filter_settings"), "runtime_settings": described.get("runtime_settings"),
                          "verifier": described.get("verifier")}
    limit = timeout_ms()
    sizes = {}
    for size_kb in args.sizes:
        texts = make_texts(args.seed, size_kb)
        for i in range(WARMUP):
            detector.scan(texts[i % len(texts)][0], "tool_output")
        values, errors = [], 0
        for _ in range(args.scan_runs):
            for text, _planted in texts:
                started = time.perf_counter()
                scanned = detector.scan(text, "tool_output")
                values.append((time.perf_counter() - started) * 1000)
                errors += bool(scanned.get("errors"))
        sizes[str(size_kb)] = {**stats(values, limit), "scans_with_errors": errors}
    result["scan"] = sizes
    print(json.dumps(result))
    return 0


# ---- bridge: the Mod's path ----------------------------------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def bridge_sweep(config: str, env: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    port = free_port()
    worker_env = {**env, "PG_DETECTOR_PORT": str(port), "PYTHONIOENCODING": "utf-8"}
    worker = subprocess.Popen([sys.executable, str(ROOT / "src" / "detector" / "worker.py")], cwd=ROOT, env=worker_env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    bridge = None
    try:
        deadline = time.monotonic() + 300
        while True:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/ready", timeout=2) as response:
                    if response.status == 200:
                        break
            except Exception:  # noqa: BLE001 - not up yet
                pass
            if worker.poll() is not None or time.monotonic() > deadline:
                return {"unavailable": "worker did not start"}
            time.sleep(0.2)
        bridge = subprocess.Popen(["node", str(ROOT / "src" / "detector" / "mcp-bridge.cjs")], cwd=ROOT,
                                  env={**env, "PG_DETECTOR_URL": f"http://127.0.0.1:{port}"},
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        ids = iter(range(1, 10**9))

        def call(method: str, params: dict[str, Any]) -> dict[str, Any]:
            message = {"jsonrpc": "2.0", "id": next(ids), "method": method, "params": params}
            bridge.stdin.write(json.dumps(message) + "\n")
            bridge.stdin.flush()
            return json.loads(bridge.stdout.readline())

        call("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "size-sweep", "version": "1"}})
        limit = timeout_ms()
        sizes = {}
        for size_kb in args.sizes:
            texts = make_texts(args.seed, size_kb)
            for i in range(3):  # connection and first-call warm-up, not measured
                call("tools/call", {"name": "scan_batch", "arguments": {"items": [{"id": 0, "text": texts[i][0], "source": "tool_output"}]}})
            values, failures = [], 0
            for run in range(args.bridge_runs):
                text = texts[run % len(texts)][0]
                started = time.perf_counter()
                reply = call("tools/call", {"name": "scan_batch", "arguments": {"items": [{"id": 0, "text": text, "source": "tool_output"}]}})
                values.append((time.perf_counter() - started) * 1000)
                failures += bool(reply.get("result", {}).get("isError"))
            sizes[str(size_kb)] = {**stats(values, limit, failures), "detector_failures": failures}
        return {"bridge": sizes}
    finally:
        if bridge is not None:
            bridge.kill()
        worker.kill()


# ---- environment and report ----------------------------------------------------------------------------------------

def run_text(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def machine(gitleaks_dir: Path | None) -> dict[str, Any]:
    info: dict[str, Any] = {"os": platform.platform(), "python": platform.python_version(), "logical_cpus": os.cpu_count(),
                            "node": run_text(["node", "--version"])}
    if sys.platform == "win32":
        query = ("$p = Get-CimInstance Win32_Processor; $c = Get-CimInstance Win32_ComputerSystem; "
                 "'{0}|{1}|{2}' -f ($p | Select-Object -First 1).Name, ($p | Measure-Object -Property NumberOfCores -Sum).Sum, $c.TotalPhysicalMemory")
        parts = run_text(["powershell", "-NoProfile", "-Command", query]).split("|")
        if len(parts) == 3:
            info.update(cpu=parts[0].strip(), physical_cores=int(parts[1]), memory_gb=round(int(parts[2]) / 2**30, 1))
    else:
        info["cpu"] = platform.processor() or run_text(["uname", "-m"])
        try:
            pages, size = os.sysconf("SC_PHYS_PAGES"), os.sysconf("SC_PAGE_SIZE")
            info["memory_gb"] = round(pages * size / 2**30, 1)
        except (ValueError, OSError, AttributeError):
            pass
    gitleaks = str(gitleaks_dir / ("gitleaks.exe" if sys.platform == "win32" else "gitleaks")) if gitleaks_dir else "gitleaks"
    info["gitleaks"] = run_text([gitleaks, "version"]) or "없음"
    try:
        import credsweeper
        info["credsweeper"] = credsweeper.__version__
    except Exception:  # noqa: BLE001
        info["credsweeper"] = "없음"
    return info


def fmt_row(label: str, s: dict[str, Any] | None, mark: str = "") -> str:
    if s is None:
        return f"| {label} | - | - | - | - | - | - |{mark}"
    return f"| {label} | {s['p50_ms']} | {s['p90_ms']} | {s['p95_ms']} | {s['p99_ms']} | {s['max_ms']} | {s['over_timeout']} |{mark}"


def markdown(result: dict[str, Any]) -> str:
    m, limit = result["machine"], result["timeout_ms"]
    lines = [f"# 입력 크기별 탐지기 지연 시간 ({result['date']})", "",
             f"- 기계: {m.get('cpu', '?')}, 물리 코어 {m.get('physical_cores', '?')}개(논리 {m.get('logical_cpus')}), 메모리 {m.get('memory_gb', '?')} GB, {m['os']}",
             f"- Python {m['python']}, Node {m['node']}, gitleaks {m['gitleaks']}, CredSweeper {m['credsweeper']}",
             f"- 텍스트: 크기마다 서로 다른 20개(코드·로그·.env·YAML·JSON 조각을 섞음), 그중 10개에 합성 비밀 1~3개. seed `{result['seed']}`. 텍스트와 비밀 값은 남기지 않음",
             f"- 탐지기 호출: 크기·구성마다 워밍업 {WARMUP}회 뒤 {result['scan_runs_per_size']}회(`detector.scan`만). Mod 경로: 실제 브리지(`mcp-bridge.cjs` → worker) 왕복 {result['bridge_runs_per_size']}회",
             f"- 타임아웃 기준: `PG_DETECTOR_TIMEOUT_MS` = {int(limit)} ms. 백분위는 nearest-rank", ""]
    for key, config in result["configs"].items():
        lines += [f"## ({key}) {config['label']}", ""]
        if config.get("unavailable"):
            lines += [f"건너뜀: {config['unavailable']}", ""]
            continue
        d = config["detector"]
        adapters = ", ".join(f"{a['name']} {a['version']}" for a in d["adapters"])
        runtime = (d.get("runtime_settings") or {}).get("adapters") or {}
        lines += [f"- 엔진 설정: 정책 `{d['candidate_policy']}`, 합의 `{d['consensus']}`, 모듈 {adapters}",
                  f"- 필터: {d.get('filter_settings')}" + (f", 실행 설정: {json.dumps(runtime, ensure_ascii=False)}" if runtime else ""),
                  f"- 건너뛴 모듈: {', '.join(s['name'] for s in d.get('skipped') or []) or '없음'}", "",
                  "**탐지기 한 번 호출 (`detector.scan`)**", "",
                  "| 크기 (KB) | p50 | p90 | p95 | p99 | 최대 | 타임아웃 넘음 | 4KB 목표 (p90 300ms) |", "|---|---|---|---|---|---|---|---|"]
        for size, s in config["scan"].items():
            goal = (" 달성 |" if s["p90_ms"] <= TARGET_4KB_P90_MS else " 미달 |") if size == "4" else " |"
            lines.append(fmt_row(size, s, goal))
        lines += ["", "**Mod 경로 (브리지 왕복)**", "",
                  "| 크기 (KB) | p50 | p90 | p95 | p99 | 최대 | 타임아웃 넘음 | 훅 예산 10초 대비 (최대) |", "|---|---|---|---|---|---|---|---|"]
        for size, s in (config.get("bridge") or {}).items():
            share = f" {s['max_ms'] / HOOK_BUDGET_MS * 100:.1f}% |"
            lines.append(fmt_row(size, s, share))
        lines.append("")
    lines += ["단위는 ms. \"타임아웃 넘음\"은 호출 시간이 기준을 넘은 수(브리지에서는 DETECTOR_FAILURE 응답 포함)."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--configs", nargs="*", choices=tuple(CONFIGS), default=list(CONFIGS))
    parser.add_argument("--sizes", nargs="*", type=int, default=list(SIZES_KB))
    parser.add_argument("--scan-runs", type=int, default=10, help="passes over the 20 texts per size (10: 200 calls)")
    parser.add_argument("--bridge-runs", type=int, default=50)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--gitleaks", type=Path, help="folder holding the gitleaks binary, put first on PATH")
    parser.add_argument("--out", type=Path, default=ROOT / "outputs" / "latency")
    parser.add_argument("--child", choices=tuple(CONFIGS), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child:
        return child(args)

    base = dict(os.environ)
    for name in ("PG_DETECTOR_ENABLE", "PG_DETECTOR_DISABLE", "PG_DETECTOR_CANDIDATE_POLICY"):
        base.pop(name, None)
    if args.gitleaks:
        base["PATH"] = f"{args.gitleaks.resolve()}{os.pathsep}{base.get('PATH', '')}"
    result: dict[str, Any] = {"date": dt.date.today().isoformat(), "seed": args.seed, "sizes_kb": args.sizes,
                              "texts_per_size": TEXTS_PER_SIZE, "texts_with_secrets_per_size": TEXTS_PER_SIZE // 2,
                              "scan_runs_per_size": TEXTS_PER_SIZE * args.scan_runs, "bridge_runs_per_size": args.bridge_runs,
                              "timeout_ms": timeout_ms(), "machine": machine(args.gitleaks.resolve() if args.gitleaks else None), "configs": {}}
    for key in args.configs:
        label, extra = CONFIGS[key]
        env = {**base, **extra}
        print(f"({key}) {label}: detector.scan ...", file=sys.stderr, flush=True)
        done = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child", key, "--seed", str(args.seed),
                               "--scan-runs", str(args.scan_runs), "--sizes", *map(str, args.sizes)],
                              cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")
        if done.returncode != 0 or not done.stdout.strip():
            config = {"unavailable": f"측정 실패 (exit {done.returncode})"}
        else:
            config = json.loads(done.stdout.strip().splitlines()[-1])
        if config.get("unavailable") and key == "b":
            config["unavailable"] = f"번들 없음 ({config['unavailable']})"
        config["label"] = label
        if not config.get("unavailable"):
            print(f"({key}) {label}: bridge ...", file=sys.stderr, flush=True)
            config.update(bridge_sweep(key, env, args))
        result["configs"][key] = config
    args.out.mkdir(parents=True, exist_ok=True)
    stem = args.out / f"size-sweep-{result['date']}"
    # LF on every OS, so the committed results do not change with the machine they ran on.
    stem.with_suffix(".json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    stem.with_suffix(".md").write_text(markdown(result), encoding="utf-8", newline="\n")
    print(f"{stem}.md", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
