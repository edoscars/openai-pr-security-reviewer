from pathlib import Path


def test_workflow_preserves_secret_and_token_safety_boundaries() -> None:
    workflow = Path(".github/workflows/pr-security-review.yml").read_text()

    assert "pull_request:" in workflow
    assert "\n  pull_request_target:" not in workflow
    assert "head.repo.fork == false" in workflow
    assert "contents: read" in workflow
    assert "pull-requests: write" in workflow
    assert "issues: write" in workflow


def test_workflow_runs_the_pipeline_on_pr_shas() -> None:
    workflow = Path(".github/workflows/pr-security-review.yml").read_text()

    assert "fetch-depth: 0" in workflow
    assert "OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}" in workflow
    assert "--base-sha \"${{ github.event.pull_request.base.sha }}\"" in workflow
    assert "--head-sha \"${{ github.event.pull_request.head.sha }}\"" in workflow
