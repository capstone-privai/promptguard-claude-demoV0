"""How many adapters must agree before a span is treated as a credential."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .adapter import RawFinding


@dataclass(frozen=True)
class ConsensusPolicy:
    """``any`` | ``majority`` | ``unanimous`` | ``at_least`` with ``n``."""

    mode: str
    n: int = 1

    MODES = ("any", "majority", "unanimous", "at_least")

    def __post_init__(self) -> None:
        if self.mode not in self.MODES:
            raise ValueError(f"unknown consensus mode {self.mode!r}; expected one of {', '.join(self.MODES)}")
        if self.mode == "at_least" and self.n < 1:
            raise ValueError("consensus at_least needs n >= 1")

    @classmethod
    def parse(cls, spec: Any) -> ConsensusPolicy:
        """Accept ``{"mode": "at_least", "n": 2}``, ``"at_least:2"``, ``"2"``, ``2`` or a bare mode."""
        if isinstance(spec, ConsensusPolicy):
            return spec
        if isinstance(spec, Mapping):
            return cls(str(spec.get("mode", "")), int(spec.get("n", 1)))
        if isinstance(spec, int) and not isinstance(spec, bool):
            return cls("at_least", spec)
        if isinstance(spec, str):
            value = spec.strip().lower()
            if value.isdigit():
                return cls("at_least", int(value))
            mode, _, n = value.partition(":")
            if n:
                if not n.strip().isdigit():
                    raise ValueError(f"invalid consensus {spec!r}")
                return cls(mode.strip(), int(n))
            return cls(mode)
        raise ValueError(f"invalid consensus {spec!r}")

    def required_votes(self, voters: int) -> int:
        """Votes a span needs when ``voters`` adapters are active.

        Refuses a threshold no span could ever reach: such a config would
        silently stop redacting everything.
        """
        if voters < 1:
            raise ValueError("consensus needs at least one active adapter")
        required = {"any": 1, "majority": voters // 2 + 1, "unanimous": voters}.get(self.mode, self.n)
        if required > voters:
            raise ValueError(f"consensus {self} needs {required} votes but only {voters} adapter(s) are active")
        return required

    def __str__(self) -> str:
        return f"at_least:{self.n}" if self.mode == "at_least" else self.mode


def vote(ballots: Mapping[str, Sequence[RawFinding]], required_votes: int) -> list[tuple[str, RawFinding]]:
    """Keep every finding whose region enough distinct adapters flagged.

    Tools rarely agree on exact offsets (one reports ``key=value``, another just
    the value), so any overlap counts as agreeing on that region. Accepted
    findings keep their own spans and normalize() unions the overlaps, so the
    redacted region is never narrower than what any supporter reported.
    """
    flat = sorted(
        ((name, finding) for name, findings in ballots.items() for finding in findings),
        key=lambda item: item[1].start,
    )
    supporters = [{name} for name, _ in flat]
    # Sorted by start, so each overlapping pair is met once, from its earlier member.
    for index, (name, finding) in enumerate(flat):
        for later in range(index + 1, len(flat)):
            other, peer = flat[later]
            if peer.start >= finding.end:
                break
            supporters[index].add(other)
            supporters[later].add(name)
    return [item for item, voters in zip(flat, supporters) if len(voters) >= required_votes]
