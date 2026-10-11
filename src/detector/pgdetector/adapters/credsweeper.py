"""CredSweeper (open source, Samsung) as one ensemble voter."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Mapping

from credsweeper import CredSweeper, StringContentProvider, __version__ as CREDSWEEPER_VERSION

from ..adapter import DetectorAdapter, RawFinding
from ..core import BENIGN_VARIABLES, assigned_variable, line_table, type_for


def confidence_value(candidate: Any) -> str:
    value = getattr(getattr(candidate, "confidence", None), "value", None)
    return str(value or "moderate")


class CredSweeperAdapter(DetectorAdapter):
    version = CREDSWEEPER_VERSION

    def __init__(self, name: str, options: Mapping[str, Any], config_dir: Path) -> None:
        super().__init__(name, options, config_dir)
        # scan() is used directly and post_processing()/MlValidator are never invoked.
        common = dict(
            pool_count=1,
            severity=options.get("severity", "medium"),
            confidence=options.get("confidence", "moderate"),
            use_filters=True,
            ml_threshold=0,
            log_level="ERROR",
        )
        self.scanners = [CredSweeper(**common)] + [
            CredSweeper(rule_path=config_dir / rule_path, **common)
            for rule_path in options.get("extra_rules", [])
        ]
        # CredSweeper keeps candidates on the instance, so scans must not interleave.
        self.lock = threading.Lock()

    def scan(self, text: str) -> list[RawFinding]:
        lines, starts = line_table(text)
        candidates = []
        with self.lock:
            for scanner in self.scanners:
                scanner.credential_manager.clear_credentials()
                provider = StringContentProvider(lines, file_path="memory.txt", file_type=".txt")
                scanner.scan([provider], None)
                candidates.extend(list(scanner.credential_manager.candidates))

        findings: list[RawFinding] = []
        for candidate in candidates:
            for line_data in candidate.line_data_list:
                variable = str(getattr(line_data, "variable", "") or "").strip().lower()
                line_index = max(0, int(line_data.line_num) - 1)
                if line_index >= len(starts):
                    # Out-of-range line: the ensemble rejects the span and fails closed.
                    findings.append(RawFinding(-1, -1, "CREDENTIAL", str(candidate.rule_name), confidence_value(candidate)))
                    continue
                cp_start = starts[line_index] + int(line_data.value_start)
                cp_end = starts[line_index] + int(line_data.value_end)
                inferred_variable = assigned_variable(text, starts[line_index], cp_start)
                if variable in BENIGN_VARIABLES or inferred_variable in BENIGN_VARIABLES:
                    continue
                finding_type = type_for(candidate.rule_name, variable or inferred_variable)
                # CredSweeper's broad fallback "Credential" rules are useful for
                # discovery but too noisy for an enforcement boundary. Demo V0
                # only enforces value-oriented, classifiable candidate families.
                if finding_type == "CREDENTIAL":
                    continue
                findings.append(RawFinding(cp_start, cp_end, finding_type, str(candidate.rule_name), confidence_value(candidate)))
        return findings
