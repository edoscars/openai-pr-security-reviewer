import json
from types import SimpleNamespace

import pytest

from pr_security_reviewer.diff_extractor import parse_unified_diff
from pr_security_reviewer.reviewer import (
    DEFAULT_MODEL,
    FINDING_SCHEMA,
    ReviewerOutputError,
    review_changed_file,
)


PATCH = """diff --git a/src/login.py b/src/login.py
--- a/src/login.py
+++ b/src/login.py
@@ -1 +1,2 @@
 def login(username):
+    return db.execute(\"SELECT * FROM users WHERE name = '%s'\" % username)
"""

VALID_FINDING = {
    "file": "src/login.py",
    "line": 2,
    "cwe": "CWE-89",
    "title": "SQL query uses string interpolation",
    "severity": "high",
    "model_confidence": "high",
    "rationale": "The username reaches the SQL string without parameter binding.",
    "suggested_fix": "Use a parameterized query.",
}


class FakeResponses:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(output_text=json.dumps(outcome))


class FakeClient:
    def __init__(self, outcomes):
        self.responses = FakeResponses(outcomes)


def changed_file():
    return parse_unified_diff(PATCH)[0]


def test_sends_only_one_file_patch_and_requires_strict_schema() -> None:
    client = FakeClient([{"findings": [VALID_FINDING]}])

    findings = review_changed_file(client, changed_file())

    assert findings[0].cwe == "CWE-89"
    request = client.responses.calls[0]
    assert request["model"] == DEFAULT_MODEL
    assert request["input"] == changed_file().patch
    assert request["store"] is False
    assert request["text"]["format"]["strict"] is True
    assert request["text"]["format"]["schema"] == FINDING_SCHEMA


def test_discards_findings_outside_added_pr_lines() -> None:
    outside_diff = VALID_FINDING | {"line": 99}
    wrong_file = VALID_FINDING | {"file": "src/other.py"}
    client = FakeClient([{"findings": [VALID_FINDING, outside_diff, wrong_file]}])

    findings = review_changed_file(client, changed_file())

    assert [finding.line for finding in findings] == [2]


def test_retries_only_after_transient_failure() -> None:
    client = FakeClient([TimeoutError(), {"findings": [VALID_FINDING]}])
    waits = []

    findings = review_changed_file(client, changed_file(), sleep=waits.append)

    assert len(findings) == 1
    assert waits == [1]
    assert len(client.responses.calls) == 2


def test_rejects_non_json_output() -> None:
    client = FakeClient(["not a JSON object"])

    with pytest.raises(ReviewerOutputError, match="findings object"):
        review_changed_file(client, changed_file())


def test_rejects_zero_retry_attempts() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        review_changed_file(FakeClient([]), changed_file(), max_attempts=0)
