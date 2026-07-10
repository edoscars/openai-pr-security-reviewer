"""Attach curated CWE and OWASP references to review findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from pr_security_reviewer.reconciler import ReconciledFinding


@dataclass(frozen=True)
class SecurityReference:
    cwe: str
    description: str
    url: str
    owasp: str


@dataclass(frozen=True)
class GroundedFinding:
    finding: ReconciledFinding
    reference: SecurityReference


REFERENCES = {
    "CWE-22": SecurityReference("CWE-22", "Path Traversal", "https://cwe.mitre.org/data/definitions/22.html", "A01: Broken Access Control"),
    "CWE-78": SecurityReference("CWE-78", "OS Command Injection", "https://cwe.mitre.org/data/definitions/78.html", "A03: Injection"),
    "CWE-79": SecurityReference("CWE-79", "Cross-site Scripting", "https://cwe.mitre.org/data/definitions/79.html", "A03: Injection"),
    "CWE-89": SecurityReference("CWE-89", "SQL Injection", "https://cwe.mitre.org/data/definitions/89.html", "A03: Injection"),
    "CWE-287": SecurityReference("CWE-287", "Improper Authentication", "https://cwe.mitre.org/data/definitions/287.html", "A07: Identification and Authentication Failures"),
    "CWE-327": SecurityReference("CWE-327", "Broken or Risky Cryptographic Algorithm", "https://cwe.mitre.org/data/definitions/327.html", "A02: Cryptographic Failures"),
    "CWE-352": SecurityReference("CWE-352", "Cross-Site Request Forgery", "https://cwe.mitre.org/data/definitions/352.html", "A01: Broken Access Control"),
    "CWE-434": SecurityReference("CWE-434", "Unrestricted Upload of File", "https://cwe.mitre.org/data/definitions/434.html", "A05: Security Misconfiguration"),
    "CWE-502": SecurityReference("CWE-502", "Deserialization of Untrusted Data", "https://cwe.mitre.org/data/definitions/502.html", "A08: Software and Data Integrity Failures"),
    "CWE-798": SecurityReference("CWE-798", "Use of Hard-coded Credentials", "https://cwe.mitre.org/data/definitions/798.html", "A07: Identification and Authentication Failures"),
    "CWE-918": SecurityReference("CWE-918", "Server-Side Request Forgery", "https://cwe.mitre.org/data/definitions/918.html", "A10: Server-Side Request Forgery"),
}


def ground(findings: Sequence[ReconciledFinding]) -> list[GroundedFinding]:
    """Return only findings with a curated, authoritative reference."""
    return [GroundedFinding(finding, REFERENCES[finding.cwe]) for finding in findings if finding.cwe in REFERENCES]
