"""scripts/metric2/dump_guard_hits.py on a synthetic transcript: hits, hits on non-secret files, nothing printed."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "metric2"))

import dump_guard_hits  # noqa: E402

NOTICE = "[PROMPTGUARD: 비밀 파일을 변형해 출력한 결과라 가렸습니다. 값은 placeholder로 다루고, 속성은 값을 출력하지 않는 명령으로 확인하세요]"


def turn(tool_id: str, command: str, result: str) -> list[dict]:
    return [{"message": {"content": [{"type": "tool_use", "id": tool_id, "name": "Bash", "input": {"command": command}}]}},
            {"message": {"content": [{"type": "tool_result", "tool_use_id": tool_id, "content": [{"type": "text", "text": result}]}]}}]


class Hits(unittest.TestCase):
    def test_counts(self) -> None:
        rows = (turn("a", "od -c secrets/db_password.txt", NOTICE) + turn("b", "xxd src/tokenizer.py", NOTICE)
                + turn("c", "cat secrets/db_password.txt", "[PASSWORD_1]") + turn("d", "od -c README.md", "0000000 R e"))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "run" / "session.jsonl"
            path.parent.mkdir()
            path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            result = dump_guard_hits.count(Path(folder), ["secrets/db_password.txt"])
            out = io.StringIO()
            with redirect_stdout(out):
                dump_guard_hits.main(["--transcripts", folder, "--secret-file", "secrets/db_password.txt"])
        self.assertEqual((result["bash_calls"], result["hits"], result["hits_on_secret"], result["hits_on_other"]), (4, 2, 1, 1))
        self.assertEqual(result["by_tool"], {"od": 1, "xxd": 1})
        self.assertNotIn("db_password", out.getvalue())
        self.assertNotIn("tokenizer", out.getvalue())


if __name__ == "__main__":
    unittest.main()
