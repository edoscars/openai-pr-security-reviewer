"""Extract reviewable changed Python lines from a unified Git diff."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import subprocess


DEFAULT_MAX_PATCH_BYTES = 100_000
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_IGNORED_PARTS = {".git", ".venv", "venv", "vendor", "node_modules", "dist", "build"}
_IGNORED_FILENAMES = {"poetry.lock", "requirements.lock", "uv.lock", "pdm.lock"}


@dataclass(frozen=True)
class ChangedLine:
    """One added line and its line number in the pull request's head revision."""

    number: int
    text: str


@dataclass(frozen=True)
class ChangedFile:
    """One file patch and the added lines that can receive inline comments."""

    path: str
    patch: str
    added_lines: tuple[ChangedLine, ...]


def get_git_diff(base_sha: str, head_sha: str) -> str:
    """Return a deterministic local diff without executing repository code."""
    result = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--unified=3", f"{base_sha}...{head_sha}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def parse_unified_diff(diff: str) -> list[ChangedFile]:
    """Parse file patches and map each added line to its new-file line number."""
    sections = re.split(r"(?=^diff --git )", diff, flags=re.MULTILINE)
    files: list[ChangedFile] = []
    for section in sections:
        if not section.startswith("diff --git "):
            continue
        path = _new_path(section)
        if path is not None:
            files.append(ChangedFile(path, section, tuple(_added_lines(section))))
    return files


def filter_reviewable_files(
    files: list[ChangedFile], max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES
) -> list[ChangedFile]:
    """Keep bounded Python patches only; larger patches can be chunked by a later stage."""
    return [
        file
        for file in files
        if is_reviewable_path(file.path) and len(file.patch.encode()) <= max_patch_bytes
    ]


def is_reviewable_path(path: str) -> bool:
    """Apply the intentionally conservative first-language file policy."""
    parsed = PurePosixPath(path)
    name = parsed.name.lower()
    return (
        parsed.suffix == ".py"
        and not any(part.lower() in _IGNORED_PARTS for part in parsed.parts)
        and name not in _IGNORED_FILENAMES
        and "generated" not in name
        and not name.endswith("_pb2.py")
    )


def _new_path(section: str) -> str | None:
    for line in section.splitlines():
        if line.startswith("+++ b/"):
            return line[6:]
        if line == "+++ /dev/null":
            return None
    return None


def _added_lines(section: str) -> list[ChangedLine]:
    added: list[ChangedLine] = []
    new_line: int | None = None
    for line in section.splitlines():
        match = _HUNK_HEADER.match(line)
        if match:
            new_line = int(match.group(1))
            continue
        if new_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(ChangedLine(new_line, line[1:]))
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        elif line.startswith(" "):
            new_line += 1
    return added
