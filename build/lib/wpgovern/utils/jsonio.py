"""JSON I/O helpers for the WPGovern governance control plane."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wpgovern.errors import ValidationError


def read_json(path: Path | str) -> Any:
    """Read and parse a JSON file.

    Raises:
        FileNotFoundError: if ``path`` does not exist.
        ValidationError: if the file contents are not valid JSON.
    """
    try:
        with Path(path).open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"Malformed JSON in {path}: {exc}"
        ) from exc
