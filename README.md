# PR Security Reviewer

An evidence-first security-review agent for GitHub pull requests. It sends only bounded Python diffs to an OpenAI reasoning model (default: GPT-5.5; GPT-5.6 Terra when provisioned), independently scans the same changed files with Semgrep, posts CWE/OWASP-cited comments, and blocks a merge only for corroborated high- or critical-severity findings.

Open [demo.html](demo.html) in a browser to explore the confidence and gate policy without credentials.

## Why this exists

This is a deliberately small deployment-oriented reference architecture. It demonstrates how to integrate an LLM into a real engineering workflow without treating its output as fact: the model proposes findings, a deterministic scanner offers an independent signal, and a narrow policy controls the only consequential side effect—the CI result.

## Architecture

```text
GitHub pull_request
  │
  ├─ Diff extractor ── bounded, added Python lines with PR-head line numbers
  │      ├─ GPT-5.6 Terra ── strict JSON candidate findings
  │      └─ Semgrep ──────── independent static-analysis findings
  │
  └─ Reconciler ──> Grounding ──> GitHub reporter ──> Merge gate
```

| Component | Responsibility | Safety/design decision |
| --- | --- | --- |
| Diff extractor | Gets `base...head`, parses unified hunks, filters reviewable Python changes. | Diff-only payloads are bounded; no PR code is executed. |
| LLM reviewer | Calls the Responses API with strict JSON Schema. | Model output outside added lines is discarded; diff instructions are untrusted data. |
| Semgrep | Scans the same changed paths and normalizes JSON results. | It is independent corroborating evidence, not ground truth. |
| Reconciler | Matches same-CWE issues within ±2 lines. | `confirmed`, `model-only`, and `sast-only` are never conflated. |
| Grounding | Uses a local curated CWE/OWASP map. | Unmapped CWE values are not presented as authoritative citations. |
| Reporter | Replaces only marked bot comments and posts inline findings plus a summary. | Comments state evidence level and keep humans in control. |
| Gate | Returns the Action exit code. | Only confirmed high/critical findings fail CI. |

## Confidence and gate policy

- **Confirmed**: the model and Semgrep agree on CWE and land within two changed lines. These are eligible to block.
- **Model-only**: a hypothesis, explicitly labelled “needs human review.” It never blocks.
- **SAST-only**: a deterministic static-analysis signal, still advisory until a human assesses it. It never blocks.

`BLOCKING_MINIMUM_SEVERITY = "high"` is the single named policy threshold. Its default minimizes alert fatigue: a team sees every grounded finding, but a merge is blocked only when independent signals corroborate serious risk.

## Security boundaries

- The workflow uses `pull_request`, never `pull_request_target`, and skips forked PRs because their untrusted context cannot safely receive write credentials or API secrets.
- GitHub permissions are scoped to `contents: read`, `pull-requests: write`, and `issues: write`—enough to read the repository and publish this tool’s comments.
- The OpenAI request is limited to one filtered file patch at a time, uses `store=False`, strict Structured Outputs, a token cap, timeout, and bounded retries.
- The reviewer never applies fixes or commits code. Its only effects are PR comments and an Action exit status.
- `.env` is ignored. The local loader never overrides values already supplied by CI.

## Setup

Requirements: Python 3.11+, Git, an OpenAI API key, and Semgrep. The default is `gpt-5.5`; set `OPENAI_MODEL=gpt-5.6-terra` after your API organization receives preview access.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e . semgrep pytest
Copy-Item .env.example .env
```

Set the two values in `.env` locally. Do not commit it:

```dotenv
OPENAI_API_KEY=...
GITHUB_TOKEN=...
OPENAI_MODEL=gpt-5.5
```

For a local PR-equivalent run, use SHAs from the checked-out repository:

```powershell
python -m pr_security_reviewer `
  --base-sha <base-sha> --head-sha <head-sha> `
  --repo owner/repository --pull-number 123
```

The command returns `0` for advisory output, `1` for the narrow blocking condition, and `2` for an operational error such as a missing secret, scan failure, or API failure. It fails visibly rather than silently passing the PR.

## GitHub Actions deployment

The checked-in [workflow](.github/workflows/pr-security-review.yml) runs on opened, reopened, and updated same-repository PRs. Add `OPENAI_API_KEY` to repository Actions secrets; GitHub provides `github.token` as `GITHUB_TOKEN` automatically. Optionally create a repository Actions variable named `OPENAI_MODEL` to override the default `gpt-5.5` with `gpt-5.6-terra` when available.

To make the gate effective, configure your protected branch to require the **PR Security Review** check. The workflow fetches the complete history so `git diff base...head` is reliable, and it pins the two third-party GitHub Actions by commit SHA.

## Testing and evaluation

Run the suite with:

```powershell
python -m pytest
```

The tests are part of the product contract, not an afterthought. They cover hunk line mapping, filtering and command safety, strict model schema boundaries, retry behavior, Semgrep normalization, reconciliation, CWE grounding, comment idempotency, the gate-policy matrix, complete pipeline composition, local-secret precedence, and the workflow’s credential boundaries.

For a portfolio evaluation, create a small PR corpus with intentionally vulnerable and safe Python changes. Record precision, recall, reviewer acceptance rate, API latency/cost, and how often each confidence category occurs. This turns the project from a demo into evidence of deployment judgment.

## Scope

The first release intentionally supports Python, diff-only review, a small curated CWE map, and comments/gating only. Natural next steps are a broader curated reference map, a version-pinned Semgrep rule policy, a representative evaluation corpus, metrics/structured logs, and support for additional languages—not automatic remediation.
