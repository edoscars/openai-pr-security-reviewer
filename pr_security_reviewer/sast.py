"""Run Semgrep independently and normalize findings on changed Python lines."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import subprocess
from typing import Callable, Sequence

from pr_security_reviewer.diff_extractor import ChangedFile


DEFAULT_RULESET = "p/security-audit"
_CWE_ID = re.compile(r"CWE-\d+")
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "ERROR": "high",
    "MEDIUM": "medium",
    "WARNING": "medium",
    "LOW": "low",
    "INFO": "low",
}


class SastScanError(RuntimeError):
    """Semgrep did not return usable JSON findings."""


@dataclass(frozen=True)
class SastFinding:
    file: str
    line: int
    cwe: str
    title: str
    severity: str
    rationale: str
    source: str = "sast"


def run_semgrep(
    files: Sequence[ChangedFile],
    *,
    ruleset: str = DEFAULT_RULESET,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> list[SastFinding]:
    """Scan changed files only, without a shell, and retain added-line findings only."""
    if not files:
        return []

    result = runner(
        ["semgrep", "scan", "--json", "--quiet", "--config", ruleset, *(file.path for file in files)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        raise SastScanError(result.stderr.strip() or "Semgrep scan failed")
    try:
        results = json.loads(result.stdout)["results"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise SastScanError("Semgrep returned invalid JSON") from error
    if not isinstance(results, list):
        raise SastScanError("Semgrep results must be a list")

    added_lines = {file.path: {line.number for line in file.added_lines} for file in files}
    return [finding for result in results if (finding := _normalize(result, added_lines))]


def _normalize(result: object, added_lines: dict[str, set[int]]) -> SastFinding | None:
    if not isinstance(result, dict):
        return None
    extra = result.get("extra")
    start = result.get("start")
    if not isinstance(extra, dict) or not isinstance(start, dict):
        return None
    path = str(result.get("path", "")).replace("\\", "/")
    line = start.get("line")
    if not isinstance(line, int) or line not in added_lines.get(path, set()):
        return None

    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    cwe = _first_cwe(metadata.get("cwe"))
    message = extra.get("message")
    if cwe is None or not isinstance(message, str) or not message.strip():
        return None
    severity = _severity(extra.get("severity") or metadata.get("impact"))
    return SastFinding(path, line, cwe, message, severity, message)


def _first_cwe(value: object) -> str | None:
    values = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    for item in values:
        if isinstance(item, str) and (match := _CWE_ID.search(item)):
            return match.group(0)
    return None


def _severity(value: object) -> str:
    return _SEVERITY_MAP.get(str(value).upper(), "medium")
