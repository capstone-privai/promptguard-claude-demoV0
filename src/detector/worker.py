"""Raw-free detector worker for PromptGuard Demo V0.

Serves the adapter ensemble described in detector.json over localhost HTTP.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# Detector diagnostics can contain candidate text. Only explicit raw-free status is emitted.
logging.disable(logging.CRITICAL)

from pgdetector import Detector, load_detector  # noqa: E402


HOST = "127.0.0.1"
PORT = int(os.environ.get("PG_DETECTOR_PORT", "18771"))
MAX_BODY = int(os.environ.get("PG_DETECTOR_MAX_BODY", str(8 * 1024 * 1024)))
ROLE = os.environ.get("PG_DETECTOR_ROLE", "shared")
DELAY_MS = max(0, int(os.environ.get("PG_DETECTOR_DELAY_MS", "0")))
STARTED_AT = time.monotonic()
METRICS_LOCK = threading.Lock()
METRICS = {
    "scan_count": 0,
    "error_count": 0,
    "in_flight": 0,
    "last_latency_ms": 0.0,
}


DETECTOR: Detector | None = None


def rss_bytes() -> int | None:
    """Best-effort resident memory without exposing scanned content."""
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            if psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
            return None
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if os.uname().sysname == "Darwin" else value * 1024)
    except Exception:
        return None


def runtime_status() -> dict[str, Any]:
    with METRICS_LOCK:
        metrics = dict(METRICS)
    return {
        "ok": DETECTOR is not None,
        "ready": DETECTOR is not None,
        "role": ROLE,
        "pid": os.getpid(),
        "uptime_ms": round((time.monotonic() - STARTED_AT) * 1000),
        "rss_bytes": rss_bytes(),
        **metrics,
        **(DETECTOR.describe() if DETECTOR is not None else {}),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "PromptGuardDetector/0.2"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def send_json(self, status: int, value: Any) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path not in {"/health", "/ready", "/status"}:
            self.send_json(404, {"ok": False, "error": "NOT_FOUND"})
            return
        status = runtime_status()
        self.send_json(200 if status["ready"] else 503, status)

    def do_POST(self) -> None:
        if self.path not in {"/scan", "/scan-batch"}:
            self.send_json(404, {"ok": False, "error": "NOT_FOUND"})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            if length <= 0 or length > MAX_BODY:
                self.send_json(413, {"ok": False, "error": "BODY_SIZE"})
                return
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            request_id = payload.get("request_id")
            if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
                request_id = str(uuid.uuid4())
            if DETECTOR is None:
                raise RuntimeError("detector unavailable")
            if self.path == "/scan":
                text = payload.get("text")
                source = payload.get("source", "unknown")
                if not isinstance(text, str) or not isinstance(source, str):
                    self.send_json(400, {"ok": False, "error": "INVALID_INPUT"})
                    return
                if DELAY_MS:
                    time.sleep(DELAY_MS / 1000)
                with METRICS_LOCK:
                    METRICS["scan_count"] += 1
                    METRICS["in_flight"] += 1
                try:
                    result = DETECTOR.scan(text, source)
                    with METRICS_LOCK:
                        METRICS["last_latency_ms"] = result.get("latency_ms", 0.0)
                    self.send_json(200, {"request_id": request_id, **result})
                finally:
                    with METRICS_LOCK:
                        METRICS["in_flight"] -= 1
                return
            items = payload.get("items")
            if not isinstance(items, list) or len(items) > 4096:
                self.send_json(400, {"ok": False, "error": "INVALID_BATCH"})
                return
            if not all(isinstance(item, dict) and isinstance(item.get("text"), str) for item in items):
                self.send_json(400, {"ok": False, "error": "INVALID_ITEM"})
                return
            if DELAY_MS:
                time.sleep(DELAY_MS / 1000)
            with METRICS_LOCK:
                METRICS["scan_count"] += len(items)
                METRICS["in_flight"] += len(items)
            try:
                results = DETECTOR.scan_many([(item["text"], str(item.get("source", "unknown"))) for item in items])
                output = [{"id": item.get("id"), **result} for item, result in zip(items, results)]
                if results:
                    with METRICS_LOCK:
                        METRICS["last_latency_ms"] = max(result.get("latency_ms", 0.0) for result in results)
                self.send_json(200, {"ok": all(item.get("ok") for item in output), "request_id": request_id, "items": output})
            finally:
                with METRICS_LOCK:
                    METRICS["in_flight"] -= len(items)
        except Exception:
            with METRICS_LOCK:
                METRICS["error_count"] += 1
            self.send_json(500, {"ok": False, "error": "DETECTOR_EXCEPTION"})


def main() -> None:
    global DETECTOR
    DETECTOR = load_detector()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True

    def stop_server(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop_server)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_server)
    print(json.dumps({"ready": True, "role": ROLE, "pid": os.getpid(), "host": HOST, "port": PORT, **DETECTOR.describe()}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
