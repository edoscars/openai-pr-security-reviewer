import pytest

from pr_security_reviewer.gate import BLOCKING_MINIMUM_SEVERITY, decide_gate
from pr_security_reviewer.grounding import GroundedFinding, REFERENCES
from pr_security_reviewer.reconciler import ReconciledFinding


def finding(*, severity="high", confidence="confirmed") -> GroundedFinding:
    reconciled = ReconciledFinding(
        "src/login.py", 10, "CWE-89", "SQL injection", severity, confidence,
        ("model", "sast"), "Input reaches SQL.", "Use parameters."
    )
    return GroundedFinding(reconciled, REFERENCES["CWE-89"])


def test_blocks_only_confirmed_high_or_critical_findings() -> None:
    decision = decide_gate([finding(severity="critical"), finding(severity="high")])

    assert decision.blocks_merge is True
    assert decision.exit_code == 1
    assert len(decision.blocking_findings) == 2
    assert BLOCKING_MINIMUM_SEVERITY == "high"


@pytest.mark.parametrize("severity, confidence", [("medium", "confirmed"), ("critical", "model-only"), ("high", "sast-only")])
def test_leaves_all_nonblocking_signals_advisory(severity: str, confidence: str) -> None:
    decision = decide_gate([finding(severity=severity, confidence=confidence)])

    assert decision.blocks_merge is False
    assert decision.exit_code == 0


def test_allows_an_explicit_policy_override_and_rejects_invalid_one() -> None:
    assert decide_gate([finding(severity="medium")], minimum_severity="medium").blocks_merge
    with pytest.raises(ValueError, match="unsupported"):
        decide_gate([], minimum_severity="urgent")
