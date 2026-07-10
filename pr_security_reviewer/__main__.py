"""CLI entry point for the pull-request security-review pipeline."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from typing import Callable

from openai import OpenAI

from pr_security_reviewer.diff_extractor import ChangedFile, filter_reviewable_files, get_git_diff, parse_unified_diff
from pr_security_reviewer.gate import GateDecision, decide_gate
from pr_security_reviewer.grounding import ground
from pr_security_reviewer.reconciler import reconcile
from pr_security_reviewer.reporter import CommentApi, GitHubApi, publish_report
from pr_security_reviewer.reviewer import DEFAULT_MODEL, ResponsesClient, review_changed_file
from pr_security_reviewer.sast import run_semgrep


def run_pipeline(
    *,
    base_sha: str,
    head_sha: str,
    repo: str,
    pull_number: int,
    client: ResponsesClient,
    github_api: CommentApi,
    model: str = DEFAULT_MODEL,
    diff_loader: Callable[[str, str], str] = get_git_diff,
    semgrep_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> GateDecision:
    """Run all review stages, publish their result, and return the CI gate decision."""
    files = filter_reviewable_files(parse_unified_diff(diff_loader(base_sha, head_sha)))
    model_findings = [finding for file in files for finding in review_changed_file(client, file, model=model)]
    sast_findings = run_semgrep(files, runner=semgrep_runner)
    findings = ground(reconcile(model_findings, sast_findings))
    decision = decide_gate(findings)
    publish_report(github_api, repo, pull_number, head_sha, findings, blocks_merge=decision.blocks_merge)
    return decision


def main() -> int:
    parser = argparse.ArgumentParser(description="Review a pull-request diff for security findings.")
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--repo", required=True, help="owner/repository")
    parser.add_argument("--pull-number", required=True, type=int)
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", DEFAULT_MODEL))
    args = parser.parse_args()

    try:
        token = os.environ["GITHUB_TOKEN"]
        client = OpenAI(timeout=30, max_retries=0)
        decision = run_pipeline(
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            repo=args.repo,
            pull_number=args.pull_number,
            client=client,
            github_api=GitHubApi(token),
            model=args.model,
        )
    except (KeyError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"PR security review failed: {error}", file=sys.stderr)
        return 2
    return decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
