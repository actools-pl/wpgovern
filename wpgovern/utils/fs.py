"""Filesystem helpers for the WPGovern governance control plane."""

from __future__ import annotations

from pathlib import Path


def ensure_parent(path: Path | str) -> None:
    """Create the parent directory of ``path`` if it does not already exist.

    Equivalent to ``path.parent.mkdir(parents=True, exist_ok=True)``.
    Used by services to guarantee that a target's parent directory exists
    before any write attempt.
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
