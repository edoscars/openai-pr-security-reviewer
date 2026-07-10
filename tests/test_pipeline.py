import json
from types import SimpleNamespace

from pr_security_reviewer.__main__ import run_pipeline
from pr_security_reviewer.reporter import MARKER


PATCH = """diff --git a/src/login.py b/src/login.py
--- a/src/login.py
+++ b/src/login.py
@@ -1 +1,2 @@
 def login(username):
+    return db.execute(\"SELECT * FROM users WHERE name = '%s'\" % username)
"""

MODEL_FINDING = {
    "file": "src/login.py", "line": 2, "cwe": "CWE-89", "title": "SQL injection",
    "severity": "high", "model_confidence": "high", "rationale": "Input reaches SQL.",
    "suggested_fix": "Use parameters.",
}


class FakeClient:
    def __init__(self):
        self.responses = self

    def create(self, **_):
        return SimpleNamespace(output_text=json.dumps({"findings": [MODEL_FINDING]}))


class FakeGitHub:
    def __init__(self):
        self.review_payloads = []
        self.summary = ""

    def list_review_comments(self, *_): return []
    def list_issue_comments(self, *_): return []
    def delete_review_comment(self, *_): raise AssertionError("nothing to delete")
    def delete_issue_comment(self, *_): raise AssertionError("nothing to delete")
    def create_review_comment(self, _, __, payload): self.review_payloads.append(payload)
    def create_issue_comment(self, _, __, body): self.summary = body


def semgrep_runner(*_, **__):
    result = {
        "results": [{
            "path": "src/login.py", "start": {"line": 2},
            "extra": {"message": "Possible SQL injection", "severity": "ERROR", "metadata": {"cwe": ["CWE-89"]}},
        }]
    }
    return SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr="")


def test_pipeline_confirms_and_blocks_then_publishes_report() -> None:
    github = FakeGitHub()

    decision = run_pipeline(
        base_sha="base", head_sha="head", repo="acme/repo", pull_number=7,
        client=FakeClient(), github_api=github, diff_loader=lambda *_: PATCH, semgrep_runner=semgrep_runner,
    )

    assert decision.blocks_merge
    assert github.review_payloads[0]["line"] == 2
    assert MARKER in github.summary
    assert "Merge blocked" in github.summary


def test_pipeline_posts_advisory_summary_when_no_reviewable_files() -> None:
    github = FakeGitHub()

    decision = run_pipeline(
        base_sha="base", head_sha="head", repo="acme/repo", pull_number=7,
        client=FakeClient(), github_api=github, diff_loader=lambda *_: "", semgrep_runner=semgrep_runner,
    )

    assert decision.exit_code == 0
    assert github.review_payloads == []
    assert "Advisory only" in github.summary
