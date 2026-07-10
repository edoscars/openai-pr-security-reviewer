"""Narrow, explicit policy for deciding whether CI blocks a merge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from pr_security_reviewer.grounding import GroundedFinding


BLOCKING_MINIMUM_SEVERITY = "high"
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class GateDecision:
    blocks_merge: bool
    blocking_findings: tuple[GroundedFinding, ...]

    @property
    def exit_code(self) -> int:
        return 1 if self.blocks_merge else 0


def decide_gate(
    findings: Sequence[GroundedFinding], *, minimum_severity: str = BLOCKING_MINIMUM_SEVERITY
) -> GateDecision:
    """Block only corroborated findings at or above the stated severity threshold."""
    if minimum_severity not in _SEVERITY_RANK:
        raise ValueError(f"unsupported severity threshold: {minimum_severity}")
    minimum_rank = _SEVERITY_RANK[minimum_severity]
    blocking = tuple(
        grounded
        for grounded in findings
        if grounded.finding.confidence == "confirmed"
        and _SEVERITY_RANK[grounded.finding.severity] >= minimum_rank
    )
    return GateDecision(bool(blocking), blocking)
