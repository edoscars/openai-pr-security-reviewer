"""Reconcile independent model and SAST findings without overstating confidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from pr_security_reviewer.reviewer import ModelFinding
from pr_security_reviewer.sast import SastFinding


ADJACENCY_WINDOW = 2
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class ReconciledFinding:
    file: str
    line: int
    cwe: str
    title: str
    severity: str
    confidence: str
    sources: tuple[str, ...]
    rationale: str
    suggested_fix: str | None


def reconcile(
    model_findings: Sequence[ModelFinding], sast_findings: Sequence[SastFinding]
) -> list[ReconciledFinding]:
    """Pair one-to-one matching signals, then retain the remaining hypotheses."""
    unmatched_sast = set(range(len(sast_findings)))
    merged: list[ReconciledFinding] = []

    for model in model_findings:
        match = _closest_match(model, sast_findings, unmatched_sast)
        if match is None:
            merged.append(_from_model(model))
            continue
        unmatched_sast.remove(match)
        merged.append(_confirmed(model, sast_findings[match]))

    merged.extend(_from_sast(sast_findings[index]) for index in sorted(unmatched_sast))
    return _deduplicate(merged)


def _closest_match(
    model: ModelFinding, sast_findings: Sequence[SastFinding], candidates: set[int]
) -> int | None:
    matches = [
        index
        for index in candidates
        if sast_findings[index].file == model.file
        and sast_findings[index].cwe == model.cwe
        and abs(sast_findings[index].line - model.line) <= ADJACENCY_WINDOW
    ]
    return min(matches, key=lambda index: abs(sast_findings[index].line - model.line), default=None)


def _confirmed(model: ModelFinding, sast: SastFinding) -> ReconciledFinding:
    return ReconciledFinding(
        file=model.file,
        line=model.line,
        cwe=model.cwe,
        title=model.title,
        severity=_highest_severity(model.severity, sast.severity),
        confidence="confirmed",
        sources=("model", "sast"),
        rationale=model.rationale,
        suggested_fix=model.suggested_fix,
    )


def _from_model(finding: ModelFinding) -> ReconciledFinding:
    return ReconciledFinding(
        finding.file,
        finding.line,
        finding.cwe,
        finding.title,
        finding.severity,
        "model-only",
        ("model",),
        finding.rationale,
        finding.suggested_fix,
    )


def _from_sast(finding: SastFinding) -> ReconciledFinding:
    return ReconciledFinding(
        finding.file,
        finding.line,
        finding.cwe,
        finding.title,
        finding.severity,
        "sast-only",
        ("sast",),
        finding.rationale,
        None,
    )


def _highest_severity(*severities: str) -> str:
    return max(severities, key=lambda severity: _SEVERITY_RANK[severity])


def _deduplicate(findings: list[ReconciledFinding]) -> list[ReconciledFinding]:
    deduplicated: dict[tuple[str, int, str, str], ReconciledFinding] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.cwe, finding.confidence)
        previous = deduplicated.get(key)
        if previous is None or _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[previous.severity]:
            deduplicated[key] = finding
    return sorted(deduplicated.values(), key=lambda finding: (finding.file, finding.line, finding.cwe))
