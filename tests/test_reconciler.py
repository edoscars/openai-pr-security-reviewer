from pr_security_reviewer.reconciler import ADJACENCY_WINDOW, reconcile
from pr_security_reviewer.reviewer import ModelFinding
from pr_security_reviewer.sast import SastFinding


def model(*, line=10, cwe="CWE-89", severity="high") -> ModelFinding:
    return ModelFinding(
        "src/login.py",
        line,
        cwe,
        "SQL query uses string interpolation",
        severity,
        "high",
        "Untrusted input reaches the query.",
        "Use query parameters.",
    )


def sast(*, line=10, cwe="CWE-89", severity="high") -> SastFinding:
    return SastFinding(
        "src/login.py", line, cwe, "Possible SQL injection", severity, "Static rule matched."
    )


def test_marks_nearby_same_cwe_findings_as_confirmed() -> None:
    finding = reconcile([model(line=10)], [sast(line=10 + ADJACENCY_WINDOW, severity="critical")])[0]

    assert finding.confidence == "confirmed"
    assert finding.sources == ("model", "sast")
    assert finding.severity == "critical"
    assert finding.suggested_fix == "Use query parameters."


def test_preserves_unconfirmed_findings_without_overstating_them() -> None:
    findings = reconcile([model()], [sast(cwe="CWE-78")])

    assert {(finding.cwe, finding.confidence, finding.sources) for finding in findings} == {
        ("CWE-89", "model-only", ("model",)),
        ("CWE-78", "sast-only", ("sast",)),
    }


def test_does_not_confirm_distant_findings() -> None:
    findings = reconcile([model()], [sast(line=10 + ADJACENCY_WINDOW + 1)])

    assert [finding.confidence for finding in findings] == ["model-only", "sast-only"]


def test_deduplicates_repeated_model_hypotheses() -> None:
    findings = reconcile([model(), model()], [])

    assert len(findings) == 1
    assert findings[0].confidence == "model-only"
