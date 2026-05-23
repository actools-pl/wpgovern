"""Timestamp utilities for the WPGovern governance control plane."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string (seconds precision).

    Format: ``YYYY-MM-DDTHH:MM:SSZ``

    All governance timestamps use this format so that log entries and JSON
    payloads are consistently sortable and parseable across tools.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
