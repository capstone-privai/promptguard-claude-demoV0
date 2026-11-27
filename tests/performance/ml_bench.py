"""What the ML span detectors cost a tool call, and what would make them cheap enough to leave on.

Measurement only: nothing here changes the detector. Exported models and results stay in .runtime/ml-bench (git-ignored).
Values are synthetic or come from promptguard-model's synthetic test sets, and only counts and timings are printed.

    python tests/performance/ml_bench.py baseline     # step 1: worker over HTTP, ML off / ml-v9 / ml-span
    python tests/performance/ml_bench.py export       # step 2: fp32 and dynamic int8 ONNX
    python tests/performance/ml_bench.py backends     # step 2: fp32 PyTorch, fp32 ONNX, int8 ONNX, same inputs
    python tests/performance/ml_bench.py accuracy     # step 3: the same fixed test sets through each backend
    python tests/performance/ml_bench.py threads      # step 4: intra_op threads, alone and with the other detectors
    python tests/performance/ml_bench.py order        # step 5: ML only on lines the fast detectors left uncovered
    python tests/performance/ml_bench.py final        # step 6: one tool call, candidate combinations

Needs: PG_GITLEAKS_BIN or gitleaks on PATH, promptguard-model next to this repository with LFS weights, and for
`export` the onnx and onnxscript packages (PYTHONPATH is fine).
"""

from __future__ import annotations

import json
import os
import random
import re
import statistics
import string
import subprocess
import sys
import time
import types
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODEL_REPO = ROOT.parent / "promptguard-model"
OUT = ROOT / ".runtime" / "ml-bench"
BUNDLES = {"ml-span": "span-detector-v10", "ml-v9": "span-detector-v9"}
SIZES = {"200B": 200, "2KB": 2048, "20KB": 20480}
BRIDGE_LIMIT_MS = 5000
sys.path.insert(0, str(ROOT / "src" / "detector"))


# ---- inputs ----------------------------------------------------------------------------------------------------------

def corpus() -> dict[str, str]:
    """Real-looking tool output, built from this repository so a rerun needs nothing else."""
    log = subprocess.run(["git", "log", "--stat", "-n", "300"], cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8", "replace")
    code = "".join((ROOT / p).read_text(encoding="utf-8", errors="replace") for p in (
        "src/native-mod/hooks/register.mjs", "src/guard/lib.cjs", "src/detector/pgdetector/ensemble.py"))
    listing = "".join(f"-rw-r--r-- 1 user staff {p.stat().st_size:>8} {p.relative_to(ROOT).as_posix()}\n" for p in sorted((ROOT / "src").rglob("*")) if p.is_file() and "__pycache__" not in p.parts)
    return {
        "git log": log,
        "package-lock": (ROOT / "package-lock.json").read_text(encoding="utf-8", errors="replace"),
        "source": code,
        "metrics json": (ROOT / "outputs" / "detector-metrics.json").read_text(encoding="utf-8", errors="replace"),
        "ls": listing * 3,
    }


ALNUM = string.ascii_letters + string.digits


def synthetic_lines(rng: random.Random) -> list[str]:
    value = lambda n: "".join(rng.choice(ALNUM) for _ in range(n))  # noqa: E731
    return [
        f"DB_PASSWORD={value(16)}",
        f"I rotated it this morning, the new one is {value(18)} so update the deploy.",
        f'export AUTH_TOKEN="{value(32)}"',
    ]


def make_text(bodies: dict[str, str], size: int, secret: bool, index: int) -> str:
    """The index-th input of a cell: it cycles through the corpus so one cell is a mix of kinds of output."""
    rng = random.Random(f"{size}:{secret}:{index}")
    names = list(bodies)
    body = bodies[names[index % len(names)]]
    while len(body) < size * 2:
        body += body
    lines = body[rng.randrange(0, len(body) - size - 1):].split("\n")[1:]
    if secret:
        extras = synthetic_lines(rng)[:1 if size <= 200 else 3]
        keep = max(1, len(lines) // (len(extras) + 1))
        chosen: list[str] = []
        for i, extra in enumerate(extras):
            chosen += lines[i * keep:i * keep + max(1, size // (len(extras) * 60))] + [extra]
        lines = chosen + lines[len(extras) * keep:]
    return "\n".join(lines)[:size]


def stats(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {"p50": round(statistics.median(ordered), 1),
            "p95": round(ordered[min(len(ordered) - 1, max(0, int(round(0.95 * len(ordered))) - 1))], 1),
            "max": round(ordered[-1], 1)}


def save(name: str, value: Any) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.json").write_text(json.dumps(value, indent=1, ensure_ascii=False), encoding="utf-8")


# ---- step 1 ----------------------------------------------------------------------------------------------------------

def post(port: int, text: str) -> tuple[float, bool]:
    body = json.dumps({"items": [{"id": "1", "text": text, "source": "tool_result"}]}).encode("utf-8")
    request = urllib.request.Request(f"http://127.0.0.1:{port}/scan-batch", body, {"content-type": "application/json"})
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=60) as response:
        ok = json.loads(response.read())["ok"]
    return (time.perf_counter() - started) * 1000, bool(ok)


def get_status(port: int) -> dict[str, Any] | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/ready", timeout=2) as response:
            return json.loads(response.read())
    except Exception:
        return None


def baseline(runs: int = 30) -> None:
    bodies = corpus()
    rows = []
    for offset, (label, enable) in enumerate((("ML 꺼짐", ""), ("ml-v9", "ml-v9"), ("ml-span", "ml-span"))):
        port = 18990 + offset
        env = {**os.environ, "PG_DETECTOR_PORT": str(port), "PG_DETECTOR_ENABLE": enable, "PYTHONIOENCODING": "utf-8"}
        started = time.perf_counter()
        worker = subprocess.Popen([sys.executable, str(ROOT / "src" / "detector" / "worker.py")], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            status = None
            while status is None and time.perf_counter() - started < 300:
                time.sleep(0.1)
                status = get_status(port)
            if status is None:
                raise SystemExit(f"{label}: worker did not start")
            startup = (time.perf_counter() - started) * 1000
            versions = {a["name"]: a["version"] for a in status["adapters"]}
            post(port, "warm up")
            print(f"{label}: startup {startup:.0f} ms, rss {status['rss_bytes'] // 1048576} MB, ML {[v for k, v in versions.items() if k.startswith('ml-')]}", flush=True)
            row: dict[str, Any] = {"config": label, "startup_ms": round(startup), "rss_mb": status["rss_bytes"] // 1048576, "cells": {}}
            for size_name, size in SIZES.items():
                for secret in (False, True):
                    times, blocked = [], 0
                    for index in range(runs):
                        ms, ok = post(port, make_text(bodies, size, secret, index))
                        times.append(ms)
                        blocked += not ok
                    cell = {**stats(times), "blocked": blocked, "over_5s": sum(t > BRIDGE_LIMIT_MS for t in times)}
                    row["cells"][f"{size_name} {'비밀 있음' if secret else '비밀 없음'}"] = cell
                    print(f"  {size_name} secret={secret}: {cell}", flush=True)
            rows.append(row)
        finally:
            worker.terminate()
            worker.wait(timeout=20)
    save("baseline", rows)


# ---- backends --------------------------------------------------------------------------------------------------------

def bundle_dir(name: str) -> Path:
    return MODEL_REPO / "models" / BUNDLES[name]


def onnx_path(name: str, kind: str) -> Path:
    return OUT / "onnx" / BUNDLES[name] / f"{kind}.onnx"


def export() -> None:
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    class Logits(torch.nn.Module):
        def __init__(self, model):
            super().__init__()
            self.model = model

        def forward(self, input_ids, attention_mask):
            return self.model(input_ids=input_ids, attention_mask=attention_mask).logits

    rows = []
    for name in BUNDLES:
        folder = bundle_dir(name)
        tokenizer = AutoTokenizer.from_pretrained(folder, local_files_only=True)
        model = AutoModelForTokenClassification.from_pretrained(folder, local_files_only=True, attn_implementation="eager").eval()
        sample = tokenizer("export sample password value for tracing the graph", return_tensors="pt")
        target = onnx_path(name, "fp32")
        target.parent.mkdir(parents=True, exist_ok=True)
        started = time.perf_counter()
        torch.onnx.export(Logits(model), (sample["input_ids"], sample["attention_mask"]), str(target), dynamo=False, opset_version=18,
                          input_names=["input_ids", "attention_mask"], output_names=["logits"],
                          dynamic_axes={"input_ids": {0: "batch", 1: "tokens"}, "attention_mask": {0: "batch", 1: "tokens"}, "logits": {0: "batch", 1: "tokens"}})
        exported = time.perf_counter() - started
        started = time.perf_counter()
        quantize_dynamic(str(target), str(onnx_path(name, "int8")), weight_type=QuantType.QInt8)
        quantized = time.perf_counter() - started
        size = lambda p: sum(f.stat().st_size for f in p.parent.glob(p.name + "*")) // 1048576  # noqa: E731
        row = {"model": name, "bundle": BUNDLES[name], "fp32_mb": size(target), "int8_mb": size(onnx_path(name, "int8")), "export_s": round(exported), "quantize_s": round(quantized)}
        rows.append(row)
        print(row, flush=True)
    save("export", rows)


class OnnxModel:
    """Stands in for the transformers model inside MLSpanDetector: same call, same output shape."""

    def __init__(self, path: Path, config: Any, threads: int) -> None:
        import onnxruntime as ort
        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        self.session = ort.InferenceSession(str(path), options, providers=["CPUExecutionProvider"])
        self.config = config

    def to(self, _device: Any) -> "OnnxModel":
        return self

    def eval(self) -> "OnnxModel":
        return self

    def __call__(self, input_ids: Any, attention_mask: Any) -> Any:
        import torch
        logits = self.session.run(None, {"input_ids": input_ids.numpy(), "attention_mask": attention_mask.numpy()})[0]
        return types.SimpleNamespace(logits=torch.from_numpy(logits))


def detector_for(name: str, backend: str, threads: int = 0) -> Any:
    """The real MLSpanDetector of a bundle (filters, boundary refiner, threshold) on the chosen backend."""
    source = MODEL_REPO / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    import torch
    from privai_model.ml_span import runtime
    from transformers import AutoConfig

    if backend == "pt":
        if threads:
            torch.set_num_threads(threads)
        return runtime.MLSpanDetector(bundle_dir(name), device="cpu")
    config = AutoConfig.from_pretrained(bundle_dir(name), local_files_only=True)
    model = OnnxModel(onnx_path(name, backend), config, threads)
    with mock.patch.object(runtime.AutoModelForTokenClassification, "from_pretrained", return_value=model):
        return runtime.MLSpanDetector(bundle_dir(name), device="cpu")


def timed(detector: Any, texts: Iterable[str]) -> list[float]:
    out = []
    for text in texts:
        started = time.perf_counter()
        detector.scan_text(text)
        out.append((time.perf_counter() - started) * 1000)
    return out


def fixed_chars(bodies: dict[str, str], chars: int, runs: int) -> list[str]:
    return [make_text(bodies, chars, False, index) for index in range(runs)]


def backends(runs: int = 30) -> None:
    bodies = corpus()
    rows = []
    for name in BUNDLES:
        for backend in ("pt", "fp32", "int8"):
            detector = detector_for(name, backend)
            detector.scan_text("warm up the model once")
            row: dict[str, Any] = {"model": name, "backend": backend}
            for chars in (200, 2000, 6000):
                row[f"{chars}자"] = stats(timed(detector, fixed_chars(bodies, chars, runs)))
            rows.append(row)
            print(row, flush=True)
    save("backends", rows)


# ---- step 3 ----------------------------------------------------------------------------------------------------------

TEST_SETS = {
    "holdout-v11": "data/span-holdout-v11/test.jsonl",
    "context-v10 test": "data/span-context-v10/test.jsonl",
    "negative-challenge": "data/span-negative-challenge-v1/test.jsonl",
}


def overlaps(a: dict[str, int], b: dict[str, int]) -> bool:
    return a["start"] < b["end"] and b["start"] < a["end"]


def score_rows(rows: list[dict[str, Any]], found: list[list[dict[str, Any]]]) -> dict[str, Any]:
    gold = hit = predicted = correct = exact = clean_rows = clean_fp = 0
    for row, spans in zip(rows, found):
        wanted = row.get("spans") or []
        gold += len(wanted)
        hit += sum(any(overlaps(g, s) for s in spans) for g in wanted)
        exact += sum(any((g["start"], g["end"]) == (s["start"], s["end"]) for s in spans) for g in wanted)
        predicted += len(spans)
        correct += sum(any(overlaps(g, s) for g in wanted) for s in spans)
        if not wanted:
            clean_rows += 1
            clean_fp += bool(spans)
    return {"gold": gold, "recall": round(hit / gold, 4) if gold else None, "exact_recall": round(exact / gold, 4) if gold else None,
            "predicted": predicted, "precision": round(correct / predicted, 4) if predicted else None,
            "negative_rows": clean_rows, "negative_rows_flagged": clean_fp}


def accuracy() -> None:
    sets = {label: [json.loads(line) for line in (MODEL_REPO / path).read_text(encoding="utf-8").splitlines() if line.strip()] for label, path in TEST_SETS.items()}
    results: dict[str, Any] = {}
    for name in BUNDLES:
        reference: dict[str, list[list[dict[str, Any]]]] = {}
        for backend in ("pt", "fp32", "int8"):
            detector = detector_for(name, backend)
            for label, rows in sets.items():
                started = time.perf_counter()
                found = [detector.scan_text(row["text"]) for row in rows]
                row = {**score_rows(rows, found), "seconds": round(time.perf_counter() - started)}
                if backend == "pt":
                    reference[label] = found
                keys = lambda spans: {(s["start"], s["end"]) for s in spans}  # noqa: E731
                row["same_spans_as_pt"] = round(sum(keys(a) == keys(b) for a, b in zip(found, reference[label])) / len(rows), 4)
                results.setdefault(name, {}).setdefault(label, {})[backend] = row
                print(name, backend, label, row, flush=True)
    save("accuracy", results)


# ---- step 4 ----------------------------------------------------------------------------------------------------------

def load_fast() -> Any:
    os.environ["PG_DETECTOR_DISABLE"] = "ml-v9,ml-span,ml-qwen"
    from pgdetector import load_detector
    detector = load_detector()
    os.environ.pop("PG_DETECTOR_DISABLE")
    return detector


def threads(runs: int = 30) -> None:
    import threading
    bodies = corpus()
    cores = os.cpu_count() or 1
    fast = load_fast()
    rows = []
    texts = fixed_chars(bodies, 2000, runs) + fixed_chars(bodies, 6000, runs)
    for name in ("ml-span",):
        for backend in ("fp32", "int8"):
            for count in sorted({1, 2, 4, cores}):
                detector = detector_for(name, backend, count)
                detector.scan_text("warm up the model once")
                alone = timed(detector, texts)
                # Next to the other detectors of the same tool call, and next to the second worker (Final Guard).
                together: list[float] = []
                for text in texts[:runs // 2] + texts[runs:runs + runs // 2]:
                    started = time.perf_counter()
                    background = threading.Thread(target=fast.scan, args=(make_text(bodies, 20480, False, 1), "tool_result"))
                    background.start()
                    detector.scan_text(text)
                    together.append((time.perf_counter() - started) * 1000)
                    background.join()
                twin = detector_for(name, backend, count)
                paired: list[float] = []
                for text in texts[:runs // 2] + texts[runs:runs + runs // 2]:
                    other = threading.Thread(target=twin.scan_text, args=(text,))
                    started = time.perf_counter()
                    other.start()
                    detector.scan_text(text)
                    paired.append((time.perf_counter() - started) * 1000)
                    other.join()
                row = {"model": name, "backend": backend, "intra_op": count, "alone": stats(alone), "with_fast_detectors": stats(together), "two_models_at_once": stats(paired)}
                rows.append(row)
                print(row, flush=True)
    save("threads", rows)


# ---- steps 5 and 6 ---------------------------------------------------------------------------------------------------

BUDGET = 6000
WINDOW_LINES = 2
TOKEN = re.compile(r"[^\s\"'`<>()\[\]{},;=:|]{8,}")
LETTER, DIGIT, SYMBOL = re.compile(r"[A-Za-z]"), re.compile(r"\d"), re.compile(r"[!@#$%^&*+?~]")
WORDS = re.compile(r"\b[A-Za-z]{2,}\b")
# Shapes that fill real tool output and are not credentials.
NOT_SECRET = re.compile(
    r"(?i:[0-9a-f]{7,})"
    r"|sha(?:1|256|384|512)-\S+"
    r"|[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
    r"|https?://\S+"
    r"|[a-z0-9_.~-]*(?:[/\\][a-z0-9_.~-]+)+[/\\]?"
    r"|@?[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?@[\^~<>=v]*\d[\w.-]*"
    r"|v?\d+(?:\.\d+)+[\w.-]*"
)
FILE_NAME = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\.[a-z]{1,5}")
HOSTED = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+|sha(?:1|256|384|512)-[A-Za-z0-9+/=]+")


def ml_adapter(name: str, backend: str, threads_count: int = 0) -> Any:
    """The real adapter with detector.json's options, on the chosen backend."""
    from pgdetector.adapters.span_models import MLSpanAdapter, MLV9Adapter
    config_dir = ROOT / "src" / "detector"
    options = next(e for e in json.loads((config_dir / "detector.json").read_text(encoding="utf-8"))["adapters"] if e["name"] == name)["options"]
    kind = MLSpanAdapter if name == "ml-span" else MLV9Adapter
    return kind(name, options, config_dir, factory=lambda _checkpoint, device: detector_for(name, backend, threads_count))


def fast_detector(with_gitleaks: bool) -> Any:
    from pgdetector import ConsensusPolicy, Detector
    full = load_fast()
    keep = [a for a in full.adapters if with_gitleaks or a.name != "gitleaks"]
    return Detector(keep, ConsensusPolicy.parse("majority"), candidate_only=[a.name for a in keep if a.name == "shell-aware"], candidate_policy="union")


def candidate(token: str) -> bool:
    from pgdetector.adapters.shell_aware import PROSE_WORDS
    word = token.strip(".")
    if len(word) < 8 or word.lower() in PROSE_WORDS or NOT_SECRET.fullmatch(word) or FILE_NAME.fullmatch(word):
        return False
    return bool(LETTER.search(word)) and bool(DIGIT.search(word) or SYMBOL.search(word))


def text_lines(text: str) -> list[tuple[int, str]]:
    out, offset = [], 0
    for line in text.splitlines(keepends=True):
        out.append((offset, line))
        offset += len(line)
    return out


def windows_of(lines: list[tuple[int, str]], chosen: list[int]) -> list[tuple[int, str]]:
    ranges: list[list[int]] = []
    for index in sorted(chosen):
        start, end = max(0, index - WINDOW_LINES), min(len(lines), index + WINDOW_LINES + 1)
        if ranges and start <= ranges[-1][1]:
            ranges[-1][1] = max(ranges[-1][1], end)
        else:
            ranges.append([start, end])
    return [(lines[s][0], "".join(line for _, line in lines[s:e])) for s, e in ranges]


def size_of(regions: list[tuple[int, str]]) -> int:
    return sum(len(piece) for _, piece in regions)


def is_covered(base: int, line: str, covered: list[tuple[int, int]]) -> bool:
    return any(s < base + len(line) and base < e for s, e in covered)


def cue_skip_covered(adapter: Any, text: str, covered: list[tuple[int, int]]) -> list[tuple[int, str]]:
    """The literal request: today's cue lines, minus the lines a fast detector already found something on."""
    from pgdetector.adapters.span_models import CUE
    if len(text) <= adapter.whole_text_chars:
        return [(0, text)]
    lines = text_lines(text)
    regions = windows_of(lines, [i for i, (base, line) in enumerate(lines) if CUE.search(line) and not is_covered(base, line, covered)])
    return [] if size_of(regions) > BUDGET else regions


def candidate_lines(adapter: Any, text: str, covered: list[tuple[int, int]], min_priority: int = 1) -> list[tuple[int, str]]:
    """Report section 6: lines with a candidate no fast detector covered, by priority up to the budget."""
    from pgdetector.adapters.span_models import CUE
    if len(text) <= adapter.whole_text_chars:
        return [(0, text)]
    lines = text_lines(text)
    priority: dict[int, int] = {}
    for index, (base, line) in enumerate(lines):
        if CUE.search(line) and not is_covered(base, line, covered):
            priority[index] = 3
        for match in TOKEN.finditer(line):
            start, end = base + match.start(), base + match.end()
            if candidate(match.group()) and not any(s < end and start < e for s, e in covered):
                priority[index] = max(priority.get(index, 0), 2 if len(WORDS.findall(line)) >= 5 else 1)
    chosen: list[int] = []
    for index in sorted((i for i, p in priority.items() if p >= min_priority), key=lambda i: (-priority[i], i)):
        if size_of(windows_of(lines, chosen + [index])) <= BUDGET:
            chosen.append(index)
    return windows_of(lines, chosen)


def ml_spans(adapter: Any, regions: list[tuple[int, str]], drop_hosted: bool = False) -> list[tuple[int, int]]:
    out = []
    for base, piece in regions:
        hosts = [(m.start(), m.end()) for m in HOSTED.finditer(piece)] if drop_hosted else []
        for start, end, _score in adapter._spans(piece):
            if adapter._plausible(piece[start:end]) and not any(a <= start and end <= b for a, b in hosts):
                out.append((base + start, base + end))
    return out


ORDER_MODES: dict[str, Callable[[Any, str, list[tuple[int, int]]], list[tuple[int, str]]]] = {
    "단서 주변 (지금)": lambda adapter, text, _covered: adapter._cue_windows(text),
    "단서 주변 - 덮인 줄 제외": cue_skip_covered,
    "후보 줄 (전체)": lambda adapter, text, covered: candidate_lines(adapter, text, covered, 1),
    "후보 줄 (단서·문장만)": lambda adapter, text, covered: candidate_lines(adapter, text, covered, 2),
}
ORDER_BACKEND = os.environ.get("ML_BENCH_BACKEND", "pt")
ORDER_THREADS = int(os.environ.get("ML_BENCH_THREADS", "0"))


def order() -> None:
    rng = random.Random(23)
    bodies = corpus()
    names = list(bodies)
    rows = []
    for label, path in (("holdout-v11", TEST_SETS["holdout-v11"]), ("negative-challenge", TEST_SETS["negative-challenge"])):
        loaded = [json.loads(line) for line in (MODEL_REPO / path).read_text(encoding="utf-8").splitlines() if line.strip()]
        rows += [(label, row) for row in (loaded[::4] if label == "holdout-v11" else loaded[::2])]
    fast = fast_detector(with_gitleaks=False)
    adapter = ml_adapter("ml-span", ORDER_BACKEND, ORDER_THREADS)
    table = {mode: {"gold": 0, "union_hit": 0, "ml_only": 0, "negative_rows": 0, "negative_flagged": 0, "filler_spans": 0, "texts": 0, "ms": [], "chars": [], "skipped": 0} for mode in ORDER_MODES}
    reference = {"gold": 0, "union_hit": 0, "ml_only": 0, "fast_hit": 0}
    filler_by_kind: dict[str, dict[str, int]] = {}
    for count, (_label, row) in enumerate(rows):
        kind = names[count % len(names)]
        body = make_text(bodies, 20480, False, count * 5 + names.index(kind))
        cuts = [0] + [m.end() for m in re.finditer("\n", body)]
        at = rng.choice(cuts)
        sample = row["text"] + "\n"
        text = body[:at] + sample + body[at:]
        result = fast.scan(text, "tool_result")
        covered = [(f["start"], f["end"]) for f in result["findings"]] if result["ok"] else []
        gold = [(at + s["start"], at + s["end"]) for s in (row.get("spans") or [])]
        hit = lambda spans, g: any(s < g[1] and g[0] < e for s, e in spans)  # noqa: E731
        alone = [(at + a, at + b) for a, b in ml_spans(adapter, [(0, sample)])]
        reference["gold"] += len(gold)
        reference["fast_hit"] += sum(hit(covered, g) for g in gold)
        reference["ml_only"] += sum(hit(alone, g) and not hit(covered, g) for g in gold)
        reference["union_hit"] += sum(hit(alone, g) or hit(covered, g) for g in gold)
        for mode, select in ORDER_MODES.items():
            started = time.perf_counter()
            regions = select(adapter, text, covered)
            drop = mode.startswith("후보")
            spans = ml_spans(adapter, regions, drop) if regions else []
            cell = table[mode]
            cell["ms"].append((time.perf_counter() - started) * 1000)
            cell["chars"].append(size_of(regions))
            cell["skipped"] += not regions
            cell["texts"] += 1
            cell["gold"] += len(gold)
            cell["union_hit"] += sum(hit(spans, g) or hit(covered, g) for g in gold)
            cell["ml_only"] += sum(hit(spans, g) and not hit(covered, g) for g in gold)
            for limit in (3000, 4000):  # today's rule skips ML when the windows exceed the limit
                readable = size_of(regions) <= limit
                cell[f"union_hit_if_limit_{limit}"] = cell.get(f"union_hit_if_limit_{limit}", 0) + sum((readable and hit(spans, g)) or hit(covered, g) for g in gold)
            if not gold:
                cell["negative_rows"] += 1
                cell["negative_flagged"] += any(s < at + len(sample) and at < e and not hit(covered, (s, e)) for s, e in spans)
            outside = sum(1 for s, e in spans if (e <= at or s >= at + len(sample)) and not hit(covered, (s, e)))
            cell["filler_spans"] += outside
            filler_by_kind.setdefault(mode, {}).setdefault(kind, 0)
            filler_by_kind[mode][kind] += outside
        if (count + 1) % 40 == 0:
            print(f"{count + 1}/{len(rows)}", flush=True)
    summary = {"backend": ORDER_BACKEND, "threads": ORDER_THREADS, "rows": len(rows), "reference_ml_reading_each_sample_alone": reference, "modes": {}}
    for mode, cell in table.items():
        summary["modes"][mode] = {
            **{k: v for k, v in cell.items() if k not in ("ms", "chars")},
            "ml_ms": stats(cell["ms"]), "chars_read": stats(cell["chars"]),
            "filler_spans_per_text": round(cell["filler_spans"] / cell["texts"], 2), "filler_by_kind": filler_by_kind.get(mode, {}),
        }
        print(mode, summary["modes"][mode], flush=True)
    print("reference", reference, flush=True)
    save(f"order-{ORDER_BACKEND}", summary)


def final(runs: int = 30) -> None:
    import threading
    from pgdetector import ConsensusPolicy, Detector
    bodies = corpus()
    full_fast = fast_detector(with_gitleaks=True)
    plain_fast = fast_detector(with_gitleaks=False)
    gitleaks = next(a for a in full_fast.adapters if a.name == "gitleaks")
    combos = json.loads(os.environ["ML_BENCH_COMBOS"])
    rows = []
    for combo in combos:
        adapter = None
        if combo["backend"] != "off":
            adapter = ml_adapter("ml-span", combo["backend"], combo.get("threads", 0))
            if combo.get("limit"):
                adapter.max_text_chars = combo["limit"]
            adapter.timeout = combo.get("timeout", adapter.timeout)
            adapter.scan("warm up the model once")
        ensemble = full_fast if adapter is None else Detector(
            [*full_fast.adapters, adapter], ConsensusPolicy.parse("majority"), candidate_only=["shell-aware", adapter.name], candidate_policy="union")

        def one_call(text: str) -> bool:
            if combo.get("order") != "candidates":
                return bool(ensemble.scan(text, "tool_result")["ok"])
            worker = threading.Thread(target=gitleaks.scan, args=(text,))
            worker.start()
            result = plain_fast.scan(text, "tool_result")
            covered = [(f["start"], f["end"]) for f in result["findings"]]
            regions = candidate_lines(adapter, text, covered, combo.get("priority", 2))
            ok = result["ok"]
            if regions:
                try:
                    adapter._call(lambda: adapter._region_spans(regions))
                except RuntimeError:
                    ok = False
            worker.join()
            return bool(ok)

        all_times: list[float] = []
        blocked = 0
        cells = {}
        for size_name, size in SIZES.items():
            for secret in (False, True):
                times = []
                for index in range(runs):
                    text = make_text(bodies, size, secret, index)
                    started = time.perf_counter()
                    ok = one_call(text)
                    times.append((time.perf_counter() - started) * 1000)
                    blocked += not ok
                all_times += times
                cells[f"{size_name} {'비밀 있음' if secret else '비밀 없음'}"] = stats(times)
        row = {"combo": combo["name"], "calls": len(all_times), "all": stats(all_times), "cells": cells, "blocked": blocked,
               "over_5s": sum(t > BRIDGE_LIMIT_MS for t in all_times), "over_4s": sum(t > 4000 for t in all_times)}
        rows.append(row)
        print(row, flush=True)
        if adapter is not None:
            adapter._executor.shutdown(wait=True)
    save("final", rows)


COMMANDS: dict[str, Callable[[], None]] = {"baseline": baseline, "export": export, "backends": backends, "accuracy": accuracy, "threads": threads, "order": order, "final": final}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        raise SystemExit(__doc__)
    COMMANDS[sys.argv[1]]()


if __name__ == "__main__":
    main()
