"""
WPGovern audit alerter — real-time notification on high-severity events.

``AuditAlerter`` sits alongside ``AuditLogger``. It does not replace or
modify the audit chain — it reads the emitted record AFTER the chain writes
it and decides whether to fire an alert.

Design principle: audit-hardened without alerting is not response-hardened.
The control plane records everything; this module fires notifications so
operators who are not reading logs daily still learn about critical events.

Trigger model
-------------
``BUILTIN_ALERT_TRIGGERS`` is the minimum safe set. It fires on exact
event_type match and cannot be reduced by configuration. Operators extend
it via ``alert_extra_triggers`` in the config — extra triggers are additive
only.

``BUILTIN_ALERT_PREFIXES`` covers any event_type starting with one of a
set of high-severity prefixes (e.g., any ``breakglass.*`` subtype).

Sink types
----------
``webhook`` — HTTP POST to a URL.
``file``    — append JSON line to a local file.
``syslog``  — local syslog at LOG_ALERT priority.
``stderr``  — write to stderr (default when no sinks configured).
``none``    — silent; used in tests.

Alert failures are best-effort: if delivery fails, the failure is logged
to stderr and the audit record is still written. Alerting must never block
governance operations.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in trigger set — the minimum safe set. Cannot be reduced.
# ---------------------------------------------------------------------------

BUILTIN_ALERT_TRIGGERS: frozenset[str] = frozenset({
    "recovery.refused",
    "recovery.stuck",
    "breakglass.approve",
    "breakglass.review",
    "breakglass.activate",
    "breakglass.start",
    "key-compromise-runtime",
    "key-compromise-release",
    "key-compromise-journal",
    "journal.key.revoked",
    "b4.cleared",
    "baseline.activate",
    "reconciliation.refused",
    "trust.backup.restored",
})

# Prefix patterns: any event_type starting with one of these triggers alerts.
BUILTIN_ALERT_PREFIXES: tuple[str, ...] = (
    "breakglass.",
    "key-compromise",
    "recovery.stuck",
    "recovery.refused",
)


def _should_alert(
    event_type: str, extra_triggers: list[str] | None = None
) -> bool:
    """Return True if this event_type warrants an alert.

    Checks built-in exact triggers, built-in prefixes, then any
    operator-configured extra triggers (exact match only).
    """
    if event_type in BUILTIN_ALERT_TRIGGERS:
        return True
    for prefix in BUILTIN_ALERT_PREFIXES:
        if event_type.startswith(prefix):
            return True
    if extra_triggers:
        for trigger in extra_triggers:
            if event_type == trigger:
                return True
    return False


# ---------------------------------------------------------------------------
# Alert payload builder
# ---------------------------------------------------------------------------


def _build_alert_payload(
    event_type: str,
    actor: str,
    outcome: str,
    details: dict[str, Any],
    self_hash: str,
    timestamp: str,
) -> dict[str, Any]:
    """Build the alert payload. Includes the audit record's self_hash so
    operators can cross-reference against the chain."""
    return {
        "alert": True,
        "event_type": event_type,
        "actor": actor,
        "outcome": outcome,
        "timestamp": timestamp,
        "audit_record_hash": self_hash,
        "summary": _human_summary(event_type, actor, outcome, details),
        "details": {
            k: v for k, v in details.items()
            if k in (
                "txn_id", "service", "reason", "b4_event",
                "intent_signature_key_id", "key_id", "domain",
            )
        },
    }


def _human_summary(
    event_type: str,
    actor: str,
    outcome: str,
    details: dict[str, Any],
) -> str:
    """One-line human-readable summary for the alert."""
    base = f"[{outcome.upper()}] {event_type} by {actor}"
    if event_type.startswith("recovery.refused"):
        reason = details.get("reason", "")
        txn = details.get("txn_id", "")
        return f"{base} \u2014 txn {txn}: {reason}"
    if event_type.startswith("recovery.stuck"):
        b4 = details.get("b4_event", {})
        phase = b4.get("phase", "") if isinstance(b4, dict) else ""
        return f"{base} \u2014 system halted at phase={phase}"
    if event_type.startswith("breakglass"):
        return f"{base} \u2014 BREAK-GLASS OPERATION"
    if "key" in event_type:
        key_id = details.get("key_id", "")
        return f"{base} \u2014 key={key_id}"
    if event_type == "baseline.activate":
        return f"{base} \u2014 baseline activated"
    return base


# ---------------------------------------------------------------------------
# Sink implementations
# ---------------------------------------------------------------------------


def _deliver_webhook(payload: dict, url: str, timeout: int = 5) -> None:
    """HTTP POST the alert payload to a webhook URL. Best-effort."""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            if status not in range(200, 300):
                logger.warning(
                    "Alert webhook returned status %d for %s",
                    status,
                    payload.get("event_type"),
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert webhook delivery failed: %s", exc)
        sys.stderr.write(
            f"[ALERT-WARN] webhook delivery failed for "
            f"{payload.get('event_type')}: {exc}\n"
        )


def _deliver_file(payload: dict, path: str) -> None:
    """Append the alert payload (one JSON line) to a local file."""
    try:
        alert_path = Path(path)
        alert_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
        with alert_path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        try:
            os.chmod(alert_path, 0o600)
        except OSError:
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Alert file delivery failed: %s", exc)
        sys.stderr.write(
            f"[ALERT-WARN] file delivery failed for "
            f"{payload.get('event_type')}: {exc}\n"
        )


def _deliver_syslog(payload: dict) -> None:
    """Emit the alert via local syslog at LOG_ALERT priority."""
    try:
        import syslog as _syslog  # type: ignore[import]
        msg = payload.get("summary", json.dumps(payload))
        _syslog.syslog(_syslog.LOG_ALERT, f"[wpgovern-alert] {msg}")
    except ImportError:
        sys.stderr.write(
            f"[wpgovern-alert] {payload.get('summary', 'alert')}\n"
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Syslog delivery failed: %s", exc)


def _deliver_stderr(payload: dict) -> None:
    """Write the alert to stderr."""
    sys.stderr.write(
        f"[wpgovern-alert] {payload.get('summary', payload.get('event_type'))}"
        f" (audit_hash={payload.get('audit_record_hash', '')[:12]}...)\n"
    )


# ---------------------------------------------------------------------------
# AuditAlerter
# ---------------------------------------------------------------------------


class AuditAlerter:
    """Fire notifications when high-severity audit events are emitted.

    Called by ``AuditLogger`` after a record is written to the chain.
    Inspects the event_type against the trigger set and dispatches to
    configured sinks.

    Args:
        sinks: list of sink configuration dicts. Supported types:
            ``{"type": "webhook", "url": "https://..."}``
            ``{"type": "file", "path": "/var/log/alerts.log"}``
            ``{"type": "syslog"}``
            ``{"type": "stderr"}``
            ``{"type": "none"}``
        extra_triggers: additional event_type strings to alert on
            (exact match only, additive to the built-in set).
    """

    def __init__(
        self,
        sinks: list[dict] | None = None,
        extra_triggers: list[str] | None = None,
    ) -> None:
        self.sinks: list[dict] = sinks or [{"type": "stderr"}]
        self.extra_triggers: list[str] = extra_triggers or []

    def maybe_alert(
        self,
        event_type: str,
        actor: str,
        outcome: str,
        details: dict[str, Any],
        self_hash: str,
        timestamp: str,
    ) -> None:
        """Called after an audit record is written. Fires alert if warranted.

        All delivery failures are absorbed — alerting must never block
        governance operations.
        """
        if not _should_alert(event_type, self.extra_triggers):
            return

        payload = _build_alert_payload(
            event_type, actor, outcome, details, self_hash, timestamp,
        )

        for sink in self.sinks:
            sink_type = sink.get("type", "stderr")
            try:
                if sink_type == "webhook":
                    _deliver_webhook(
                        payload, sink["url"], timeout=sink.get("timeout", 5)
                    )
                elif sink_type == "file":
                    _deliver_file(payload, sink["path"])
                elif sink_type == "syslog":
                    _deliver_syslog(payload)
                elif sink_type == "stderr":
                    _deliver_stderr(payload)
                elif sink_type == "none":
                    pass
                else:
                    logger.warning("Unknown alert sink type: %s", sink_type)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Alert sink %s failed: %s", sink_type, exc)


# ---------------------------------------------------------------------------
# Config integration helper
# ---------------------------------------------------------------------------


def alerter_from_config(config: Any) -> AuditAlerter:
    """Build an ``AuditAlerter`` from a ``WPGovernConfig`` object.

    Reads ``config.alert_sinks`` (list of sink dicts) and
    ``config.alert_extra_triggers`` (list of extra event_type strings).
    Falls back to the stderr default if neither is present.
    """
    sinks = getattr(config, "alert_sinks", None)
    extra = getattr(config, "alert_extra_triggers", None)
    return AuditAlerter(
        sinks=list(sinks) if sinks is not None else None,
        extra_triggers=list(extra) if extra is not None else None,
    )
