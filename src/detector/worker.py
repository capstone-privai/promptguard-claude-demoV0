"""Raw-free detector worker for PromptGuard Demo V0.

Serves the adapter ensemble described in detector.json over localhost HTTP.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pgdetector import Detector, load_detector


HOST = "127.0.0.1"
PORT = int(os.environ.get("PG_DETECTOR_PORT", "18771"))
MAX_BODY = int(os.environ.get("PG_DETECTOR_MAX_BODY", str(8 * 1024 * 1024)))


DETECTOR: Detector | None = None


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
        if self.path != "/health":
            self.send_json(404, {"ok": False, "error": "NOT_FOUND"})
            return
        if DETECTOR is None:
            self.send_json(503, {"ok": False, "error": "DETECTOR_UNAVAILABLE"})
            return
        self.send_json(200, {"ok": True, **DETECTOR.describe()})

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
            if DETECTOR is None:
                raise RuntimeError("detector unavailable")
            if self.path == "/scan":
                text = payload.get("text")
                source = payload.get("source", "unknown")
                if not isinstance(text, str) or not isinstance(source, str):
                    self.send_json(400, {"ok": False, "error": "INVALID_INPUT"})
                    return
                self.send_json(200, DETECTOR.scan(text, source))
                return
            items = payload.get("items")
            if not isinstance(items, list) or len(items) > 4096:
                self.send_json(400, {"ok": False, "error": "INVALID_BATCH"})
                return
            if not all(isinstance(item, dict) and isinstance(item.get("text"), str) for item in items):
                self.send_json(400, {"ok": False, "error": "INVALID_ITEM"})
                return
            results = DETECTOR.scan_many([(item["text"], str(item.get("source", "unknown"))) for item in items])
            output = [{"id": item.get("id"), **result} for item, result in zip(items, results)]
            self.send_json(200, {"ok": all(item.get("ok") for item in output), "items": output})
        except Exception:
            self.send_json(500, {"ok": False, "error": "DETECTOR_EXCEPTION"})


def main() -> None:
    global DETECTOR
    DETECTOR = load_detector()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(json.dumps({"ready": True, "host": HOST, "port": PORT, **DETECTOR.describe()}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
