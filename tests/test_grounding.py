from pr_security_reviewer.grounding import REFERENCES, ground
from pr_security_reviewer.reconciler import ReconciledFinding


def finding(cwe="CWE-89") -> ReconciledFinding:
    return ReconciledFinding(
        "src/login.py",
        10,
        cwe,
        "SQL query uses string interpolation",
        "high",
        "confirmed",
        ("model", "sast"),
        "Untrusted input reaches the query.",
        "Use query parameters.",
    )


def test_attaches_curated_cwe_and_owasp_reference() -> None:
    grounded = ground([finding()])

    assert grounded[0].finding == finding()
    assert grounded[0].reference == REFERENCES["CWE-89"]
    assert grounded[0].reference.url == "https://cwe.mitre.org/data/definitions/89.html"


def test_does_not_report_uncurated_cwe_identifiers_as_authoritative() -> None:
    assert ground([finding("CWE-999999")]) == []
