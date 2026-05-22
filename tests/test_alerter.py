"""
Tests for wpgovern.audit.alerter — AuditAlerter, BUILTIN_ALERT_TRIGGERS.

Coverage:
- BUILTIN_ALERT_TRIGGERS is a frozenset (immutable — cannot be reduced)
- All documented built-in triggers fire
- Non-trigger events do not fire
- Prefix matching fires on any breakglass.* subtype
- extra_triggers via config extends but does not reduce built-in set
- none sink produces no output
- file sink delivers alert with correct fields
- file sink appends multiple alerts on successive calls
- webhook failure does not raise (best-effort)
- alerter_from_config reads config.alert_sinks and alert_extra_triggers
- alert fires after chain write (AuditLogger integration)
- non-trigger event does not fire alert in integration test
- alerter failure does not break audit chain
- alert payload carries audit_record_hash
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wpgovern.audit.alerter import (
    BUILTIN_ALERT_PREFIXES,
    BUILTIN_ALERT_TRIGGERS,
    AuditAlerter,
    _build_alert_payload,
    _should_alert,
    alerter_from_config,
)
from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def config(tmp_path: Path) -> WPGovernConfig:
    root = tmp_path / "wpg"
    return WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )


# ---------------------------------------------------------------------------
# BUILTIN_ALERT_TRIGGERS is a frozenset (immutable)
# ---------------------------------------------------------------------------


def test_builtin_alert_triggers_is_frozenset() -> None:
    assert isinstance(BUILTIN_ALERT_TRIGGERS, frozenset)


def test_builtin_alert_triggers_cannot_be_reduced() -> None:
    # frozenset does not have discard/remove — attempting to reduce it via
    # set operations returns a new set, never mutating the original.
    reduced = BUILTIN_ALERT_TRIGGERS - {"recovery.refused"}
    assert "recovery.refused" in BUILTIN_ALERT_TRIGGERS  # original unchanged
    assert "recovery.refused" not in reduced


# ---------------------------------------------------------------------------
# _should_alert()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("event_type", sorted(BUILTIN_ALERT_TRIGGERS))
def test_builtin_triggers_always_fire(event_type: str) -> None:
    assert _should_alert(event_type) is True


@pytest.mark.parametrize("event_type", [
    "baseline.create",
    "baseline.submit",
    "trust.key.generated",
    "rollback.approve",
    "approval.revoked",
])
def test_non_trigger_events_do_not_fire(event_type: str) -> None:
    assert _should_alert(event_type) is False


def test_prefix_matching_fires_on_any_breakglass_subtype() -> None:
    assert _should_alert("breakglass.custom-subtype") is True
    assert _should_alert("breakglass.") is True


def test_extra_triggers_extend_built_in_set() -> None:
    assert _should_alert("custom.event") is False
    assert _should_alert("custom.event", extra_triggers=["custom.event"]) is True


def test_extra_triggers_do_not_suppress_built_in() -> None:
    # Extra triggers cannot reduce the built-in set — _should_alert always
    # checks built-ins first regardless of extra_triggers.
    assert _should_alert("recovery.refused", extra_triggers=[]) is True


# ---------------------------------------------------------------------------
# none sink
# ---------------------------------------------------------------------------


def test_none_sink_produces_no_output(tmp_path: Path) -> None:
    alerter = AuditAlerter(sinks=[{"type": "none"}])
    # Should not raise or write anything
    alerter.maybe_alert(
        "breakglass.activate", "ops", "success",
        {"incident_id": "INC-1"}, "a" * 64, "2026-01-01T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# file sink
# ---------------------------------------------------------------------------


def test_file_sink_delivers_alert_with_correct_fields(tmp_path: Path) -> None:
    alert_path = tmp_path / "alerts.log"
    alerter = AuditAlerter(sinks=[{"type": "file", "path": str(alert_path)}])
    alerter.maybe_alert(
        "breakglass.activate", "ops", "success",
        {"incident_id": "INC-1"}, "b" * 64, "2026-01-01T00:00:00Z",
    )

    assert alert_path.exists()
    payload = json.loads(alert_path.read_text().strip())
    assert payload["event_type"] == "breakglass.activate"
    assert payload["audit_record_hash"] == "b" * 64
    assert payload["alert"] is True


def test_file_sink_appends_multiple_alerts(tmp_path: Path) -> None:
    alert_path = tmp_path / "alerts.log"
    alerter = AuditAlerter(sinks=[{"type": "file", "path": str(alert_path)}])
    for _ in range(3):
        alerter.maybe_alert(
            "recovery.refused", "recovery", "failure",
            {}, "c" * 64, "2026-01-01T00:00:00Z",
        )
    lines = [l for l in alert_path.read_text().splitlines() if l.strip()]
    assert len(lines) == 3


# ---------------------------------------------------------------------------
# webhook failure does not raise
# ---------------------------------------------------------------------------


def test_webhook_failure_does_not_raise(config: WPGovernConfig) -> None:
    alerter = AuditAlerter(
        sinks=[{"type": "webhook", "url": "http://localhost:1/nonexistent"}]
    )
    # Must not raise even on connection failure
    alerter.maybe_alert(
        "recovery.refused", "recovery", "failure",
        {}, "d" * 64, "2026-01-01T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# alerter_from_config
# ---------------------------------------------------------------------------


def test_alerter_from_config_reads_sinks_and_extra_triggers(
    tmp_path: Path,
) -> None:
    root = tmp_path / "wpg"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/k.json",
        release_trust_store=root / "trust/release/public/k.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
        alert_extra_triggers=("custom.event",),
    )
    alerter = alerter_from_config(config)
    assert alerter.sinks == [{"type": "none"}]
    assert "custom.event" in alerter.extra_triggers


def test_alerter_from_config_defaults_to_stderr_when_no_sinks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "wpg"

    class _MinimalConfig:
        pass

    alerter = alerter_from_config(_MinimalConfig())
    assert alerter.sinks == [{"type": "stderr"}]


# ---------------------------------------------------------------------------
# Alert payload
# ---------------------------------------------------------------------------


def test_alert_payload_carries_audit_record_hash() -> None:
    payload = _build_alert_payload(
        "breakglass.activate", "ops", "success",
        {}, "e" * 64, "2026-01-01T00:00:00Z",
    )
    assert payload["audit_record_hash"] == "e" * 64
    assert "summary" in payload
    assert payload["alert"] is True


# ---------------------------------------------------------------------------
# AuditLogger integration
# ---------------------------------------------------------------------------


def test_alert_fires_after_chain_write_for_trigger_event(
    config: WPGovernConfig, tmp_path: Path
) -> None:
    alert_path = tmp_path / "alerts.log"
    alert_config = WPGovernConfig(
        root_dir=config.root_dir,
        install_dir=config.root_dir / "install",
        runtime_trust_store=config.runtime_trust_store,
        release_trust_store=config.release_trust_store,
        active_pointer=config.active_pointer,
        audit_log=config.audit_log,
        alert_sinks=({"type": "file", "path": str(alert_path)},),
    )
    logger = AuditLogger(config=alert_config)
    logger.emit(
        event_type="breakglass.activate",
        actor="ops",
        outcome="success",
        details={"incident_id": "INC-1"},
    )

    assert alert_path.exists()
    payload = json.loads(alert_path.read_text().strip())
    assert payload["event_type"] == "breakglass.activate"


def test_non_trigger_event_does_not_fire_alert(
    config: WPGovernConfig, tmp_path: Path
) -> None:
    alert_path = tmp_path / "alerts.log"
    alert_config = WPGovernConfig(
        root_dir=config.root_dir,
        install_dir=config.root_dir / "install",
        runtime_trust_store=config.runtime_trust_store,
        release_trust_store=config.release_trust_store,
        active_pointer=config.active_pointer,
        audit_log=config.audit_log,
        alert_sinks=({"type": "file", "path": str(alert_path)},),
    )
    logger = AuditLogger(config=alert_config)
    logger.emit(
        event_type="baseline.create",
        actor="alice",
        outcome="success",
        details={},
    )

    # audit log written
    assert config.audit_log.exists()
    # alert file NOT written
    assert not alert_path.exists()


def test_alerter_failure_does_not_break_audit_chain(
    config: WPGovernConfig,
) -> None:
    """If maybe_alert raises, the audit record must still be written."""
    alert_config = WPGovernConfig(
        root_dir=config.root_dir,
        install_dir=config.root_dir / "install",
        runtime_trust_store=config.runtime_trust_store,
        release_trust_store=config.release_trust_store,
        active_pointer=config.active_pointer,
        audit_log=config.audit_log,
        alert_sinks=({"type": "webhook", "url": "http://localhost:1/fail"},),
    )
    logger = AuditLogger(config=alert_config)
    # This fires an alert for a trigger event; the webhook will fail.
    logger.emit(
        event_type="recovery.refused",
        actor="recovery",
        outcome="failure",
        details={},
    )
    # Chain must still be written despite alert failure
    assert config.audit_log.exists()
    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == "recovery.refused"
