import json
from types import SimpleNamespace

import pytest

from pr_security_reviewer.diff_extractor import parse_unified_diff
from pr_security_reviewer.sast import SastScanError, run_semgrep


PATCH = """diff --git a/src/login.py b/src/login.py
--- a/src/login.py
+++ b/src/login.py
@@ -1 +1,2 @@
 def login(username):
+    return db.execute(\"SELECT * FROM users WHERE name = '%s'\" % username)
"""


def semgrep_result(*, line=2, path="src/login.py", cwe="CWE-89", severity="ERROR"):
    return {
        "path": path,
        "start": {"line": line},
        "extra": {
            "message": "Detected a possible SQL injection.",
            "severity": severity,
            "metadata": {"cwe": [cwe]},
        },
    }


def test_runs_semgrep_without_a_shell_and_normalizes_finding() -> None:
    calls = []

    def fake_runner(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"results": [semgrep_result()]}), stderr="")

    findings = run_semgrep(parse_unified_diff(PATCH), runner=fake_runner)

    assert [(finding.file, finding.line, finding.cwe, finding.severity) for finding in findings] == [
        ("src/login.py", 2, "CWE-89", "high")
    ]
    assert calls == [
        (
            (["semgrep", "scan", "--json", "--quiet", "--config", "p/security-audit", "src/login.py"],),
            {"check": False, "capture_output": True, "text": True},
        )
    ]


def test_excludes_findings_not_on_added_lines_or_without_cwe() -> None:
    output = {
        "results": [
            semgrep_result(line=1),
            semgrep_result(cwe="not-a-cwe"),
            semgrep_result(path="src/other.py"),
        ]
    }

    findings = run_semgrep(
        parse_unified_diff(PATCH),
        runner=lambda *_, **__: SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr=""),
    )

    assert findings == []


def test_prefers_semgrep_explicit_severity_over_rule_metadata_impact() -> None:
    output = {"results": [semgrep_result(severity="ERROR")]}
    output["results"][0]["extra"]["metadata"]["impact"] = "LOW"

    findings = run_semgrep(
        parse_unified_diff(PATCH),
        runner=lambda *_, **__: SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr=""),
    )

    assert findings[0].severity == "high"


def test_does_not_start_semgrep_when_there_are_no_files() -> None:
    assert run_semgrep([], runner=lambda **_: pytest.fail("runner should not be called")) == []


def test_reports_scan_failure_and_invalid_json() -> None:
    failed = lambda *_, **__: SimpleNamespace(returncode=2, stdout="", stderr="bad ruleset")
    invalid = lambda *_, **__: SimpleNamespace(returncode=0, stdout="not json", stderr="")

    with pytest.raises(SastScanError, match="bad ruleset"):
        run_semgrep(parse_unified_diff(PATCH), runner=failed)
    with pytest.raises(SastScanError, match="invalid JSON"):
        run_semgrep(parse_unified_diff(PATCH), runner=invalid)
