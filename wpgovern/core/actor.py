"""
Actor context resolution for WPGovern CLI operations.

Every governance command records who performed the operation. ``resolve_actor_context``
normalizes and validates the actor_id, reason, and change_ticket fields before they
reach the audit log.
"""

from __future__ import annotations

from typing import Optional

from wpgovern.errors import ValidationError

MAX_ACTOR_FIELD_LEN = 256
"""Maximum allowed length for actor_id, reason, and change_ticket after trimming."""


def _clean_optional(value: Optional[str], field: str) -> Optional[str]:
    """Trim whitespace and validate a nullable string field.

    Returns None if the value is None or whitespace-only. Raises
    ``ValidationError`` if the trimmed value exceeds ``MAX_ACTOR_FIELD_LEN``
    or contains non-printable characters other than tab, newline, or CR.
    """
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > MAX_ACTOR_FIELD_LEN:
        raise ValidationError(f"{field} is too long")
    if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in cleaned):
        raise ValidationError(f"{field} contains invalid characters")
    return cleaned


def resolve_actor_context(
    actor_id: Optional[str] = None,
    reason: Optional[str] = None,
    change_ticket: Optional[str] = None,
) -> dict[str, Optional[str]]:
    """Resolve and validate the actor context for a governance operation.

    If ``actor_id`` is None or whitespace-only, falls back to
    ``getpass.getuser()``. Raises ``ValidationError`` if a resolved
    actor_id cannot be determined or any field fails validation.

    Returns a dict with keys ``actor_id``, ``reason``, ``change_ticket``.
    """
    import getpass

    resolved_actor = _clean_optional(actor_id, "actor_id")
    if resolved_actor is None:
        resolved_actor = getpass.getuser().strip()
    if not resolved_actor:
        raise ValidationError("actor_id is required")
    return {
        "actor_id": resolved_actor,
        "reason": _clean_optional(reason, "reason"),
        "change_ticket": _clean_optional(change_ticket, "change_ticket"),
    }
