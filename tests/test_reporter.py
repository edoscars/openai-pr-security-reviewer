from pr_security_reviewer.grounding import GroundedFinding, REFERENCES
from pr_security_reviewer.reconciler import ReconciledFinding
from pr_security_reviewer.reporter import MARKER, format_finding, format_summary, publish_report


def grounded(confidence="confirmed") -> GroundedFinding:
    finding = ReconciledFinding(
        "src/login.py", 10, "CWE-89", "SQL injection", "high", confidence,
        ("model", "sast"), "Untrusted input reaches the query.", "Use parameters."
    )
    return GroundedFinding(finding, REFERENCES["CWE-89"])


class FakeApi:
    def __init__(self):
        self.calls = []

    def list_review_comments(self, *_): return [{"id": 1, "body": MARKER}, {"id": 2, "body": "human"}]
    def list_issue_comments(self, *_): return [{"id": 3, "body": MARKER}]
    def delete_review_comment(self, *args): self.calls.append(("delete_review", args))
    def delete_issue_comment(self, *args): self.calls.append(("delete_issue", args))
    def create_review_comment(self, *args): self.calls.append(("create_review", args))
    def create_issue_comment(self, *args): self.calls.append(("create_issue", args))


def test_model_only_comment_is_explicitly_a_human_review_request() -> None:
    body = format_finding(grounded("model-only"))

    assert MARKER in body
    assert "needs human review" in body
    assert REFERENCES["CWE-89"].url in body


def test_publish_replaces_only_marked_comments_and_posts_inline_and_summary() -> None:
    api = FakeApi()

    publish_report(api, "acme/repo", 7, "head-sha", [grounded()], blocks_merge=True)

    assert [name for name, _ in api.calls] == ["delete_review", "delete_issue", "create_review", "create_issue"]
    inline = api.calls[2][1][2]
    assert inline["path"] == "src/login.py"
    assert inline["line"] == 10
    assert inline["side"] == "RIGHT"
    assert "Merge blocked" in api.calls[3][1][2]


def test_summary_counts_confidence_and_advisory_decision() -> None:
    summary = format_summary([grounded("sast-only")], blocks_merge=False)

    assert "Advisory only" in summary
    assert "sast-only 1" in summary
