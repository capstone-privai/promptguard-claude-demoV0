"""Weights saved in shards (model.safetensors.index.json + model-0000x-of-0000y.safetensors, as save_pretrained writes
7B and 14B models) are weights: ml-span and the verifier go on to load them. A shard that is a Git LFS pointer (never
pulled) still counts as missing. A stand-in privai_model package records the load; no torch, no real weights.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "detector"))

from pgdetector.adapter import AdapterUnavailable  # noqa: E402
from pgdetector.adapters.span_models import MLSpanAdapter  # noqa: E402
from pgdetector.verifier import VerifierStage  # noqa: E402

POINTER = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "0" * 64 + "\nsize 123456789\n"
RUNTIME_SPAN = """
LOADED = []
class MLSpanDetector:
    def __init__(self, checkpoint, device="cpu"):
        LOADED.append(str(checkpoint))
    def scan_text(self, text, threshold=None):
        return []
"""
RUNTIME_VERIFIER = """
LOADED = []
class CandidateVerifier:
    threshold = 0.5
    model_version = "stand-in"
    def __init__(self, bundle, device="cpu", recall_target=None, context_lines=3):
        LOADED.append(str(bundle))
    def score(self, text, source, rows):
        return [0.0 for _ in rows]
"""


def forget_stand_in() -> None:
    for name in [name for name in sys.modules if name == "privai_model" or name.startswith("privai_model.")]:
        del sys.modules[name]


class Sharded(unittest.TestCase):
    def setUp(self) -> None:
        forget_stand_in()
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "promptguard-model"
        package = self.repo / "src" / "privai_model"
        for sub, code in (("ml_span", RUNTIME_SPAN), ("verifier", RUNTIME_VERIFIER)):
            (package / sub).mkdir(parents=True)
            (package / sub / "__init__.py").write_text("", encoding="utf-8")
            (package / sub / "runtime.py").write_text(code, encoding="utf-8")
        (package / "__init__.py").write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        forget_stand_in()
        if str(self.repo / "src") in sys.path:
            sys.path.remove(str(self.repo / "src"))
        self.tmp.cleanup()

    def bundle(self, name: str, pointer_shard: bool = False, prefix: str = "model", extra: dict | None = None) -> Path:
        folder = self.repo / "models" / name
        folder.mkdir(parents=True)
        shards = [f"{prefix}-0000{i}-of-00002.safetensors" for i in (1, 2)]
        index = {"metadata": {"total_size": 4096}, "weight_map": {"layer.0.weight": shards[0], "layer.1.weight": shards[1], "layer.1.bias": shards[1]}}
        (folder / f"{prefix}.safetensors.index.json").write_text(json.dumps(index), encoding="utf-8")
        (folder / shards[0]).write_bytes(b"\0" * 2048)
        if pointer_shard:
            (folder / shards[1]).write_text(POINTER, encoding="utf-8")
        else:
            (folder / shards[1]).write_bytes(b"\0" * 2048)
        for file, text in (extra or {}).items():
            (folder / file).write_text(text, encoding="utf-8")
        return folder

    def span(self, name: str) -> MLSpanAdapter:
        return MLSpanAdapter("ml-span", {"repository": str(self.repo), "checkpoint": f"models/{name}"}, ROOT)

    def test_ml_span_loads_a_two_shard_bundle(self) -> None:
        folder = self.bundle("span-sharded")
        adapter = self.span("span-sharded")
        from privai_model.ml_span.runtime import LOADED
        self.assertEqual(LOADED, [str(folder)])
        self.assertEqual(adapter.checkpoint_name, "span-sharded")

    def test_ml_span_leaves_out_a_bundle_with_an_lfs_pointer_shard(self) -> None:
        self.bundle("span-pointer", pointer_shard=True)
        with self.assertRaises(AdapterUnavailable) as caught:
            self.span("span-pointer")
        self.assertIn("weights missing", str(caught.exception))

    def test_ml_span_leaves_out_a_bundle_whose_shard_is_missing(self) -> None:
        folder = self.bundle("span-missing")
        (folder / "model-00002-of-00002.safetensors").unlink()
        with self.assertRaises(AdapterUnavailable):
            self.span("span-missing")

    def test_ml_span_single_file_still_works(self) -> None:
        folder = self.repo / "models" / "span-single"
        folder.mkdir(parents=True)
        (folder / "model.safetensors").write_bytes(b"\0" * 2048)
        self.span("span-single")
        from privai_model.ml_span.runtime import LOADED
        self.assertEqual(LOADED, [str(folder)])

    def verifier(self, name: str) -> VerifierStage:
        return VerifierStage({"repository": str(self.repo), "bundle": f"models/{name}"}, ROOT)

    def test_verifier_loads_a_two_shard_bundle(self) -> None:
        folder = self.bundle("verifier-sharded", extra={"bundle.json": "{}"})
        self.verifier("verifier-sharded")
        from privai_model.verifier.runtime import LOADED
        self.assertEqual(LOADED, [str(folder)])

    def test_verifier_leaves_out_a_bundle_with_an_lfs_pointer_shard(self) -> None:
        self.bundle("verifier-pointer", pointer_shard=True, extra={"bundle.json": "{}"})
        with self.assertRaises(AdapterUnavailable) as caught:
            self.verifier("verifier-pointer")
        self.assertIn("no weights", str(caught.exception))

    def test_verifier_lora_adapter_shards(self) -> None:
        folder = self.bundle("verifier-lora", prefix="adapter_model", extra={"bundle.json": "{}"})
        self.verifier("verifier-lora")
        from privai_model.verifier.runtime import LOADED
        self.assertEqual(LOADED, [str(folder)])


if __name__ == "__main__":
    unittest.main()
