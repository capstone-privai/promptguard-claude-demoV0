"""PG_GITLEAKS_PRESPAWN: a gitleaks process waits on stdin so a call does not pay its ~0.3 s start.

Against the real binary (skipped when gitleaks is not installed; set PG_GITLEAKS_BIN when it is not on PATH).
- on and off find exactly the same things (size sweep texts, detector fixtures, shell_aware_cases)
- the call uses the waiting process and a new one is started after it; off starts one per call as before
- a dead waiting process is replaced once on the spot; a second failure raises (fail-closed)
- concurrent calls never wait for the waiting process; only one is left waiting afterwards
- the timeout counts from the write, not the wait
- no gitleaks process outlives the detector process (normal exit, exception, hard kill)
Values are synthetic.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))
sys.path.insert(0, str(ROOT / "scripts" / "latency"))

from pgdetector import load_detector  # noqa: E402
from pgdetector.adapters.gitleaks import GitleaksAdapter, _discard  # noqa: E402
import size_sweep  # noqa: E402

BINARY = os.environ.get("PG_GITLEAKS_BIN") or "gitleaks"
AVAILABLE = shutil.which(BINARY) is not None
CONFIG_DIR = ROOT / "src" / "detector"
GITHUB = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
TEXT = f"export GITHUB_TOKEN={GITHUB}\n"


def alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes

        kernel = ctypes.windll.kernel32
        handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie is not running; reap check via /proc where present.
    status = Path(f"/proc/{pid}/status")
    return not (status.exists() and "\nState:\tZ" in status.read_text())


def gone(pid: int, within: float = 10.0) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.1)
    return False


def adapter(prespawn: str | None, **options) -> GitleaksAdapter:
    env = {"PG_GITLEAKS_PRESPAWN": prespawn} if prespawn is not None else {}
    with mock.patch.dict(os.environ, env):
        if prespawn is None:
            os.environ.pop("PG_GITLEAKS_PRESPAWN", None)
        return GitleaksAdapter("gitleaks", {"binary": BINARY, **options}, CONFIG_DIR)


def counting(subject: GitleaksAdapter) -> list[subprocess.Popen]:
    spawned: list[subprocess.Popen] = []
    original = subject._spawn

    def spawn() -> subprocess.Popen:
        process = original()
        spawned.append(process)
        return process

    subject._spawn = spawn  # type: ignore[method-assign]
    return spawned


def settle(subject: GitleaksAdapter) -> None:
    """Wait for the background refill to finish."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with subject._lock:
            if subject._idle is not None and not subject._refilling:
                return
        time.sleep(0.02)
    raise AssertionError("no waiting gitleaks process after 10 s")


@unittest.skipUnless(AVAILABLE, "gitleaks binary not found (set PG_GITLEAKS_BIN)")
class Setting(unittest.TestCase):
    def test_default_is_on_and_a_process_waits(self) -> None:
        subject = adapter(None)
        try:
            self.assertTrue(subject.prespawn)
            self.assertEqual(subject.runtime_settings(), {"prespawn": "on"})
            self.assertIsNotNone(subject._idle)
            self.assertIsNone(subject._idle.poll())
        finally:
            subject.close()

    def test_off_keeps_nothing_waiting_and_starts_one_per_call(self) -> None:
        subject = adapter("off")
        try:
            self.assertFalse(subject.prespawn)
            self.assertEqual(subject.runtime_settings(), {"prespawn": "off"})
            self.assertIsNone(subject._idle)
            spawned = counting(subject)
            subject.scan(TEXT)
            subject.scan(TEXT)
            self.assertEqual(len(spawned), 2)
            self.assertIsNone(subject._idle)
        finally:
            subject.close()


@unittest.skipUnless(AVAILABLE, "gitleaks binary not found (set PG_GITLEAKS_BIN)")
class CallPath(unittest.TestCase):
    def setUp(self) -> None:
        self.subject = adapter("on")
        self.expected = adapter("off").scan(TEXT)
        self.assertTrue(self.expected, "the synthetic token is found")

    def tearDown(self) -> None:
        self.subject.close()

    def test_the_call_uses_the_waiting_process_and_a_new_one_waits_after(self) -> None:
        waiting = self.subject._idle
        spawned = counting(self.subject)
        self.assertEqual(self.subject.scan(TEXT), self.expected)
        self.assertIsNotNone(waiting.poll(), "the waiting process ran the call")
        settle(self.subject)
        self.assertEqual(len(spawned), 1, "only the refill started a process")
        self.assertIs(self.subject._idle, spawned[0])
        self.assertIsNone(spawned[0].poll())

    def test_a_dead_waiting_process_is_replaced_once(self) -> None:
        self.subject._idle.kill()
        self.subject._idle.wait()
        spawned = counting(self.subject)
        self.assertEqual(self.subject.scan(TEXT), self.expected)
        settle(self.subject)
        self.assertEqual(len(spawned), 2, "one retry on the spot plus the refill")

    def test_a_second_failure_raises(self) -> None:
        # Every process exits at once with an error: the waiting one and the retry both fail.
        self.subject.close()
        self.subject._closed = False
        self.subject.command = [sys.executable, "-c", "import sys; sys.exit(3)"]
        self.subject._refill()
        self.subject._idle.wait()
        spawned = counting(self.subject)
        with self.assertRaises(RuntimeError):
            self.subject.scan(TEXT)
        settle(self.subject)
        self.assertEqual(len(spawned), 2, "one retry on the spot plus the refill, no more")

    def test_a_call_does_not_wait_for_a_busy_waiting_process(self) -> None:
        held = self.subject._take()  # as if another call had it
        self.assertIsNotNone(held)
        try:
            started = time.monotonic()
            self.assertEqual(self.subject.scan(TEXT), self.expected)
            self.assertLess(time.monotonic() - started, 5)
        finally:
            _discard(held)

    def test_concurrent_calls_agree_and_leave_one_waiting(self) -> None:
        spawned = counting(self.subject)
        first = self.subject._idle
        results: list[object] = []

        def call() -> None:
            try:
                results.append(self.subject.scan(TEXT))
            except Exception as exc:  # pragma: no cover - reported below
                results.append(exc)

        threads = [threading.Thread(target=call) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(results, [self.expected] * 4)
        settle(self.subject)
        waiting = [p for p in [first, *spawned] if p.poll() is None]
        self.assertEqual(waiting, [self.subject._idle], "exactly one process is left waiting")


@unittest.skipUnless(AVAILABLE, "gitleaks binary not found (set PG_GITLEAKS_BIN)")
class Timeout(unittest.TestCase):
    def test_the_wait_is_not_counted(self) -> None:
        subject = adapter("on", timeout_seconds=1.0)
        try:
            time.sleep(1.5)
            self.assertTrue(subject.scan(TEXT))
        finally:
            subject.close()

    def test_a_slow_scan_still_times_out_and_is_killed(self) -> None:
        subject = adapter("on", timeout_seconds=0.5)
        try:
            subject.close()
            subject._closed = False
            subject.command = [sys.executable, "-c", "import sys, time; sys.stdin.read(); time.sleep(30)"]
            subject._refill()
            slow = subject._idle
            with self.assertRaises(subprocess.TimeoutExpired):
                subject.scan(TEXT)
            self.assertTrue(gone(slow.pid, 5))
        finally:
            subject.close()


CHILD = """
import sys, time
sys.path.insert(0, {src!r})
from pgdetector.adapters.gitleaks import GitleaksAdapter
from pathlib import Path
a = GitleaksAdapter("gitleaks", {{"binary": {binary!r}}}, Path({src!r}))
print(a._idle.pid, flush=True)
mode = sys.argv[1]
if mode == "raise":
    raise RuntimeError("synthetic failure")
if mode == "wait":
    time.sleep(120)
"""


@unittest.skipUnless(AVAILABLE, "gitleaks binary not found (set PG_GITLEAKS_BIN)")
class Cleanup(unittest.TestCase):
    def run_child(self, mode: str) -> int:
        script = CHILD.format(src=str(CONFIG_DIR), binary=BINARY)
        env = {**os.environ, "PG_GITLEAKS_PRESPAWN": "on"}
        child = subprocess.Popen([sys.executable, "-c", script, mode], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, text=True)
        pid = int(child.stdout.readline())
        self.assertTrue(alive(pid))
        if mode == "wait":
            child.kill()  # TerminateProcess on Windows, SIGKILL elsewhere: no atexit runs
        child.wait(30)
        child.stdout.close()
        return pid

    def test_normal_exit(self) -> None:
        self.assertTrue(gone(self.run_child("exit")))

    def test_exception(self) -> None:
        self.assertTrue(gone(self.run_child("raise")))

    def test_hard_kill(self) -> None:
        self.assertTrue(gone(self.run_child("wait")))


@unittest.skipUnless(AVAILABLE, "gitleaks binary not found (set PG_GITLEAKS_BIN)")
class SameFindings(unittest.TestCase):
    """on and off: every adapter finding and every detector result are identical."""

    @classmethod
    def setUpClass(cls) -> None:
        groups: list[list[str]] = [[t for t, _ in size_sweep.make_texts(size_sweep.SEED, size)] for size in size_sweep.SIZES_KB]
        fixtures = [p.read_text(encoding="utf-8") for kind in ("positive", "negative") for p in sorted((ROOT / "fixtures" / kind).iterdir())]
        cases = json.loads((ROOT / "tests" / "detector" / "shell_aware_cases.json").read_text(encoding="utf-8"))["cases"]
        groups += [fixtures, [case["text"] for case in cases]]
        cls.groups = groups
        cls.detectors = {}
        for state in ("on", "off"):
            with mock.patch.dict(os.environ, {"PG_GITLEAKS_PRESPAWN": state, "PG_GITLEAKS_BIN": shutil.which(BINARY)}):
                cls.detectors[state] = load_detector()

    @classmethod
    def tearDownClass(cls) -> None:
        for detector in cls.detectors.values():
            for each in detector.adapters:
                if isinstance(each, GitleaksAdapter):
                    each.close()

    def gitleaks(self, state: str) -> GitleaksAdapter:
        found = [a for a in self.detectors[state].adapters if isinstance(a, GitleaksAdapter)]
        self.assertEqual(len(found), 1, "gitleaks is one of the default adapters")
        self.assertEqual(found[0].prespawn, state == "on")
        return found[0]

    def test_adapter_findings_match(self) -> None:
        on, off = self.gitleaks("on"), self.gitleaks("off")
        for texts in self.groups:
            self.assertEqual(on.scan_many(texts), off.scan_many(texts))
        # One text per call too, so later calls take the process started after the previous one.
        for texts in self.groups:
            for text in texts[:3]:
                self.assertEqual(on.scan(text), off.scan(text))

    def test_detector_results_match(self) -> None:
        def untimed(results):
            # Only how long the scan took may differ (that is the point); every other field must be equal.
            return [{key: value for key, value in result.items() if not key.endswith("_ms")} for result in results]

        compared = 0
        for texts in self.groups:
            items = [(text, "fixture") for text in texts]
            on, off = self.detectors["on"].scan_many(items), self.detectors["off"].scan_many(items)
            self.assertEqual(untimed(on), untimed(off))
            self.assertTrue(all(result["ok"] for result in on + off))
            compared += sum(len(result["findings"]) for result in on)
        self.assertGreater(compared, 100, "the texts hold findings to compare")


if __name__ == "__main__":
    unittest.main()
