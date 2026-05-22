"""
Tests for wpgovern.core.actor — resolve_actor_context, _clean_optional.

Coverage:
- resolve_actor_context falls back to getpass.getuser() when actor_id is None
- resolve_actor_context trims whitespace from all fields
- resolve_actor_context rejects actor_id exceeding MAX_ACTOR_FIELD_LEN
- resolve_actor_context rejects non-printable characters in change_ticket
- resolve_actor_context accepts tab character in reason
- resolve_actor_context returns None for whitespace-only optional fields
- explicit actor_id is used without fallback
"""

from __future__ import annotations

import pytest

from wpgovern.core.actor import MAX_ACTOR_FIELD_LEN, resolve_actor_context
from wpgovern.errors import ValidationError


def test_resolve_actor_context_falls_back_to_getuser_when_actor_id_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "fallback-user")
    result = resolve_actor_context(None, None, None)
    assert result["actor_id"] == "fallback-user"


def test_resolve_actor_context_trims_whitespace_from_all_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "fallback-user")
    result = resolve_actor_context(None, "  routine change  ", " CHG-1 ")
    assert result["reason"] == "routine change"
    assert result["change_ticket"] == "CHG-1"


def test_resolve_actor_context_uses_explicit_actor_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "should-not-be-used")
    result = resolve_actor_context("alice", None, None)
    assert result["actor_id"] == "alice"


def test_resolve_actor_context_returns_none_for_whitespace_only_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    result = resolve_actor_context(None, "   ", "  ")
    assert result["reason"] is None
    assert result["change_ticket"] is None


def test_resolve_actor_context_rejects_actor_id_exceeding_max_length() -> None:
    long_id = "x" * (MAX_ACTOR_FIELD_LEN + 1)
    with pytest.raises(ValidationError, match="too long"):
        resolve_actor_context(long_id, None, None)


def test_resolve_actor_context_rejects_non_printable_in_change_ticket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    with pytest.raises(ValidationError, match="invalid characters"):
        resolve_actor_context(None, None, "CHG-\x01")


def test_resolve_actor_context_accepts_tab_in_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    result = resolve_actor_context(None, "reason\twith\ttabs", None)
    assert result["reason"] == "reason\twith\ttabs"


def test_resolve_actor_context_returns_complete_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("getpass.getuser", lambda: "fallback-user")
    result = resolve_actor_context("alice", "routine update", "CHG-1234")
    assert set(result.keys()) == {"actor_id", "reason", "change_ticket"}
    assert result["actor_id"] == "alice"
    assert result["reason"] == "routine update"
    assert result["change_ticket"] == "CHG-1234"
