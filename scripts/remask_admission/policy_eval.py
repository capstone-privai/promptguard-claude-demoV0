"""Run promptguard-data's metric-detection scorer with the Mod's PG_REMASK_POLICY=admitted re-mask rule.

The scorer replays the Mod in Python (evaluation/adapters/promptguard_adapter.py, ModSession). This script does not
change that repository: it loads it, swaps in a ModSession that admits values to the re-mask list the way
register.mjs does, and runs the scorer's own command line. `--policy all` runs the scorer unchanged.

The scorer never restores tool_input (the model's command). A value the Mod restored before a command is admitted
whatever its shape, so here a known value that appears in a later tool_input item is admitted: in recorded sessions
the agent typed the value the Mod would have restored.

    python scripts/remask_admission/policy_eval.py --data-root ../promptguard-data --policy admitted -- \\
        run --system promptguard --system-root . --sessions metric-detection/data_test/sessions_from_CredData.jsonl \\
        --out metric-detection/results/remask_admitted
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import shapes  # noqa: E402


def install_admitted(module: Any) -> None:
    rules = shapes.high_confidence_rules()
    base = module.ModSession
    current: dict[str, Any] = {}

    class AdmittedModSession(base):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            super().__init__()
            self.raw_of: dict[str, str] = {}
            current["session"] = self

        def placeholder(self, finding: dict[str, Any], raw: str) -> str:
            had = raw in self.reverse
            value = super().placeholder(finding, raw)
            self.raw_of.setdefault(value, raw)
            admitted = shapes.is_high_confidence(rules, finding.get("detectors") or [], finding.get("rule_id", "")) \
                or shapes.value_shape(raw) == "secret_like"
            if not had and raw in self.reverse and not admitted:
                del self.reverse[raw]  # super() added it; admitted keeps it off the re-mask list
            elif admitted:
                self.reverse.setdefault(raw, value)
            return value

        def restored(self, text: str) -> None:
            for value, raw in self.raw_of.items():
                if raw in text:
                    self.reverse.setdefault(raw, value)

    passthrough = module.passthrough

    def passing(item_id: int, text: str) -> Any:
        session = current.get("session")
        if session is not None:
            session.restored(text)
        return passthrough(item_id, text)

    module.ModSession = AdmittedModSession
    module.passthrough = passing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-root", type=Path, required=True, help="promptguard-data checkout")
    parser.add_argument("--policy", choices=("all", "admitted"), required=True)
    parser.add_argument("scorer_args", nargs=argparse.REMAINDER, help="-- then the scorer's arguments (run ...)")
    args = parser.parse_args(argv)
    scorer_args = args.scorer_args[1:] if args.scorer_args[:1] == ["--"] else args.scorer_args
    root = args.data_root.resolve()
    os.chdir(root)  # the scorer's defaults are relative to the repository root
    sys.path.insert(0, str(root / "metric-detection"))
    from evaluation import cli
    from evaluation.adapters import promptguard_adapter

    if args.policy == "admitted":
        install_admitted(promptguard_adapter)
    return cli.main(scorer_args)


if __name__ == "__main__":
    raise SystemExit(main())
