"""
Tests for wpgovern.utils.fs, wpgovern.utils.jsonio, wpgovern.utils.time.

Coverage:
- ensure_parent creates missing parent directory
- ensure_parent is idempotent when parent already exists
- read_json parses a valid JSON file
- read_json raises ValidationError on malformed JSON
- read_json raises FileNotFoundError for missing file
- utc_now_iso returns an ISO-8601 string
- utc_now_iso output is parseable by datetime.fromisoformat
- utc_now_iso ends with 'Z' (UTC marker)
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from wpgovern.errors import ValidationError
from wpgovern.utils.fs import ensure_parent
from wpgovern.utils.jsonio import read_json
from wpgovern.utils.time import utc_now_iso


# ---------------------------------------------------------------------------
# ensure_parent
# ---------------------------------------------------------------------------


def test_ensure_parent_creates_missing_parent_directory(tmp_path: Path) -> None:
    target = tmp_path / "deep" / "nested" / "file.json"
    assert not target.parent.exists()
    ensure_parent(target)
    assert target.parent.exists()


def test_ensure_parent_is_idempotent_when_parent_exists(tmp_path: Path) -> None:
    target = tmp_path / "file.json"
    assert target.parent.exists()
    ensure_parent(target)  # must not raise
    assert target.parent.exists()


def test_ensure_parent_accepts_string_path(tmp_path: Path) -> None:
    target = str(tmp_path / "sub" / "file.json")
    ensure_parent(target)
    assert (tmp_path / "sub").exists()


# ---------------------------------------------------------------------------
# read_json
# ---------------------------------------------------------------------------


def test_read_json_returns_parsed_dict(tmp_path: Path) -> None:
    p = tmp_path / "data.json"
    p.write_text('{"key": "value", "n": 42}\n', encoding="utf-8")
    result = read_json(p)
    assert result == {"key": "value", "n": 42}


def test_read_json_returns_parsed_list(tmp_path: Path) -> None:
    p = tmp_path / "list.json"
    p.write_text("[1, 2, 3]\n", encoding="utf-8")
    result = read_json(p)
    assert result == [1, 2, 3]


def test_read_json_raises_validation_error_on_malformed_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ValidationError, match="Malformed JSON"):
        read_json(p)


def test_read_json_raises_file_not_found_for_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_json(tmp_path / "nonexistent.json")


# ---------------------------------------------------------------------------
# utc_now_iso
# ---------------------------------------------------------------------------


def test_utc_now_iso_returns_string() -> None:
    result = utc_now_iso()
    assert isinstance(result, str)


def test_utc_now_iso_ends_with_z() -> None:
    result = utc_now_iso()
    assert result.endswith("Z"), f"Expected Z suffix, got: {result!r}"


def test_utc_now_iso_is_parseable_by_fromisoformat() -> None:
    result = utc_now_iso()
    # Replace trailing Z with +00:00 for fromisoformat compatibility on 3.10
    parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    assert parsed.year >= 2024


def test_utc_now_iso_format_is_seconds_precision() -> None:
    result = utc_now_iso()
    # Must match YYYY-MM-DDTHH:MM:SSZ exactly (19 chars + Z = 20)
    assert len(result) == 20
    assert result[4] == "-" and result[7] == "-"
    assert result[10] == "T"
    assert result[13] == ":" and result[16] == ":"
