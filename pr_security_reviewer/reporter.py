"""Render and publish grounded findings as idempotent GitHub PR comments."""

from __future__ import annotations

from collections import Counter
import json
from typing import Protocol, Sequence
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from pr_security_reviewer.grounding import GroundedFinding


MARKER = "<!-- pr-security-reviewer -->"
API_URL = "https://api.github.com"


class GitHubApiError(RuntimeError):
    """GitHub rejected or could not process a reporter request."""


class CommentApi(Protocol):
    def list_review_comments(self, repo: str, pull_number: int) -> list[dict]: ...
    def list_issue_comments(self, repo: str, pull_number: int) -> list[dict]: ...
    def delete_review_comment(self, repo: str, comment_id: int) -> None: ...
    def delete_issue_comment(self, repo: str, comment_id: int) -> None: ...
    def create_review_comment(self, repo: str, pull_number: int, payload: dict) -> None: ...
    def create_issue_comment(self, repo: str, pull_number: int, body: str) -> None: ...


class GitHubApi:
    """Small GitHub REST client using only the Python standard library."""

    def __init__(self, token: str):
        self.token = token

    def list_review_comments(self, repo: str, pull_number: int) -> list[dict]:
        return self._request("GET", f"/repos/{repo}/pulls/{pull_number}/comments?per_page=100")

    def list_issue_comments(self, repo: str, pull_number: int) -> list[dict]:
        return self._request("GET", f"/repos/{repo}/issues/{pull_number}/comments?per_page=100")

    def delete_review_comment(self, repo: str, comment_id: int) -> None:
        self._request("DELETE", f"/repos/{repo}/pulls/comments/{comment_id}")

    def delete_issue_comment(self, repo: str, comment_id: int) -> None:
        self._request("DELETE", f"/repos/{repo}/issues/comments/{comment_id}")

    def create_review_comment(self, repo: str, pull_number: int, payload: dict) -> None:
        self._request("POST", f"/repos/{repo}/pulls/{pull_number}/comments", payload)

    def create_issue_comment(self, repo: str, pull_number: int, body: str) -> None:
        self._request("POST", f"/repos/{repo}/issues/{pull_number}/comments", {"body": body})

    def _request(self, method: str, path: str, payload: dict | None = None):
        request = Request(
            f"{API_URL}{path}",
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request) as response:
                body = response.read().decode()
        except HTTPError as error:
            raise GitHubApiError(f"GitHub API {method} {path} failed: {error.code}") from error
        return json.loads(body) if body else None


def publish_report(
    api: CommentApi,
    repo: str,
    pull_number: int,
    head_sha: str,
    findings: Sequence[GroundedFinding],
    *,
    blocks_merge: bool,
) -> None:
    """Replace this bot's prior comments, then publish inline findings and one summary."""
    _delete_prior_comments(api, repo, pull_number)
    for grounded in findings:
        finding = grounded.finding
        api.create_review_comment(
            repo,
            pull_number,
            {
                "body": format_finding(grounded),
                "commit_id": head_sha,
                "path": finding.file,
                "line": finding.line,
                "side": "RIGHT",
            },
        )
    api.create_issue_comment(repo, pull_number, format_summary(findings, blocks_merge))


def format_finding(grounded: GroundedFinding) -> str:
    finding, reference = grounded.finding, grounded.reference
    label = {
        "confirmed": "Confirmed by model + SAST",
        "model-only": "Model-only — needs human review",
        "sast-only": "SAST-only — static-analysis signal",
    }[finding.confidence]
    fix = f"\n\n**Suggested fix:** {finding.suggested_fix}" if finding.suggested_fix else ""
    return (
        f"{MARKER}\n**{finding.severity.upper()} · {label}**\n\n"
        f"**[{reference.cwe}: {reference.description}]({reference.url})** · {reference.owasp}\n\n"
        f"{finding.rationale}{fix}"
    )


def format_summary(findings: Sequence[GroundedFinding], blocks_merge: bool) -> str:
    confidences = Counter(grounded.finding.confidence for grounded in findings)
    severities = Counter(grounded.finding.severity for grounded in findings)
    decision = "**Merge blocked:** confirmed high/critical finding present." if blocks_merge else "**Advisory only:** no blocking finding present."
    return (
        f"{MARKER}\n## PR Security Reviewer\n\n{decision}\n\n"
        f"Findings: {len(findings)} · Severity: "
        f"critical {severities['critical']}, high {severities['high']}, medium {severities['medium']}, low {severities['low']}\n\n"
        f"Confidence: confirmed {confidences['confirmed']}, model-only {confidences['model-only']}, sast-only {confidences['sast-only']}"
    )


def _delete_prior_comments(api: CommentApi, repo: str, pull_number: int) -> None:
    for comment in api.list_review_comments(repo, pull_number):
        if MARKER in str(comment.get("body", "")):
            api.delete_review_comment(repo, int(comment["id"]))
    for comment in api.list_issue_comments(repo, pull_number):
        if MARKER in str(comment.get("body", "")):
            api.delete_issue_comment(repo, int(comment["id"]))
