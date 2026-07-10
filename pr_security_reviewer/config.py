"""Minimal local environment loading without overriding CI configuration."""

from __future__ import annotations

import os
from pathlib import Path


def load_local_env(path: Path = Path(".env")) -> None:
    """Load simple KEY=VALUE entries only when the process does not already set them."""
    if not path.is_file():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.isidentifier():
            os.environ.setdefault(key, value.strip().strip('"').strip("'"))
