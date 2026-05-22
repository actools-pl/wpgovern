"""
Tests for wpgovern.audit.verifier — AuditVerifier.

Coverage:
- verify() passes on an intact chain
- verify() raises IntegrityError when a record's content is tampered
- verify() raises IntegrityError when seq is not contiguous
- verify() raises IntegrityError when prev_hash link is broken
- verify() raises IntegrityError on malformed JSON in any log line
- verify() raises NotFoundError when audit log is missing
- last_checkpoint() returns the most recent checkpoint record
- last_checkpoint() returns None when no checkpoint exists
- last_checkpoint() returns None when log does not exist
- review_window() covers full log when no checkpoint
- review_window() covers only records after the last checkpoint
- review_window() highlighted list contains highlight-type events
- review_window() chain_ok=True on clean window
- review_window() detects tampered record (self_hash mismatch) in window
- review_window() detects broken prev_hash link in window
- review_window() reports chain_ok=False on malformed JSON line
- review_window() returns empty window when log does not exist
- AUDIT_GENESIS_HASH is 64 zero hex chars
- REVIEW_HIGHLIGHT_EVENT_TYPES is a frozenset containing key event types
- governance-check exits 51 on malformed JSON (no review config)
- governance-check exits 51 on malformed JSON (review config set — not 50)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.audit.verifier import (
    AUDIT_GENESIS_HASH,
    REVIEW_HIGHLIGHT_EVENT_TYPES,
    AuditVerifier,
)
from wpgovern.config import WPGovernConfig
from wpgovern.errors import IntegrityError, NotFoundError


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


def _emit_n(config: WPGovernConfig, n: int) -> AuditLogger:
    logger = AuditLogger(config=config)
    for i in range(n):
        logger.emit(
            event_type="baseline.create",
            actor="alice",
            outcome="success",
            details={"seq_label": i},
        )
    return logger


def _emit_checkpoint(config: WPGovernConfig) -> None:
    logger = AuditLogger(config=config)
    logger.emit(
        event_type="audit.review.checkpoint",
        actor="operator",
        outcome="success",
        details={"reason": "periodic review"},
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_audit_genesis_hash_is_64_zero_chars() -> None:
    assert AUDIT_GENESIS_HASH == "0" * 64


def test_review_highlight_event_types_is_frozenset() -> None:
    assert isinstance(REVIEW_HIGHLIGHT_EVENT_TYPES, frozenset)


def test_review_highlight_includes_breakglass_and_recovery_events() -> None:
    assert "breakglass.activate" in REVIEW_HIGHLIGHT_EVENT_TYPES
    assert "recovery.refused" in REVIEW_HIGHLIGHT_EVENT_TYPES
    assert "baseline.activate" in REVIEW_HIGHLIGHT_EVENT_TYPES


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


def test_verify_passes_on_intact_chain(config: WPGovernConfig) -> None:
    _emit_n(config, 5)
    result = AuditVerifier(config=config).verify()
    assert result.ok is True
    assert result.entries == 5
    assert result.errors == []


def test_verify_raises_not_found_when_log_missing(config: WPGovernConfig) -> None:
    with pytest.raises(NotFoundError):
        AuditVerifier(config=config).verify()


def test_verify_raises_integrity_error_on_tampered_record(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    lines = config.audit_log.read_text().splitlines()
    record = json.loads(lines[1])  # tamper middle record
    record["actor"] = "mallory"
    lines[1] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    with pytest.raises(IntegrityError):
        AuditVerifier(config=config).verify()


def test_verify_raises_integrity_error_on_seq_gap(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    lines = config.audit_log.read_text().splitlines()
    record = json.loads(lines[1])
    record["seq"] = 99  # wrong seq
    # Recompute self_hash so only the seq is wrong
    without = dict(record)
    without.pop("self_hash", None)
    record["self_hash"] = hashlib.sha256(
        json.dumps(without, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lines[1] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    with pytest.raises(IntegrityError):
        AuditVerifier(config=config).verify()


def test_verify_raises_integrity_error_on_broken_prev_hash(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    lines = config.audit_log.read_text().splitlines()
    record = json.loads(lines[2])
    record["prev_hash"] = "a" * 64  # wrong
    without = dict(record)
    without.pop("self_hash", None)
    record["self_hash"] = hashlib.sha256(
        json.dumps(without, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lines[2] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    with pytest.raises(IntegrityError):
        AuditVerifier(config=config).verify()


# ---------------------------------------------------------------------------
# last_checkpoint()
# ---------------------------------------------------------------------------


def test_last_checkpoint_returns_none_when_log_absent(
    config: WPGovernConfig,
) -> None:
    assert AuditVerifier(config=config).last_checkpoint() is None


def test_last_checkpoint_returns_none_when_no_checkpoint_in_log(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    assert AuditVerifier(config=config).last_checkpoint() is None


def test_last_checkpoint_returns_most_recent_checkpoint(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 2)
    _emit_checkpoint(config)
    _emit_n(config, 2)
    _emit_checkpoint(config)
    _emit_n(config, 1)

    cp = AuditVerifier(config=config).last_checkpoint()
    assert cp is not None
    assert cp["event_type"] == "audit.review.checkpoint"
    # Should be the SECOND checkpoint (seq 5 counting from 1:
    # emit_n(2)=2 recs, checkpoint=1 rec (seq 3), emit_n(2)=2 recs, checkpoint (seq 6))
    assert cp["seq"] == 6


# ---------------------------------------------------------------------------
# review_window()
# ---------------------------------------------------------------------------


def test_review_window_covers_full_log_when_no_checkpoint(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 4)
    window = AuditVerifier(config=config).review_window()
    assert window.records_in_window == 4
    assert window.chain_ok is True


def test_review_window_covers_only_records_after_last_checkpoint(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    _emit_checkpoint(config)
    _emit_n(config, 2)

    window = AuditVerifier(config=config).review_window()
    assert window.records_in_window == 2


def test_review_window_returns_empty_when_log_absent(
    config: WPGovernConfig,
) -> None:
    window = AuditVerifier(config=config).review_window()
    assert window.records_in_window == 0
    assert window.start_hash == AUDIT_GENESIS_HASH


def test_review_window_highlighted_list_contains_highlight_events(
    config: WPGovernConfig,
) -> None:
    logger = AuditLogger(config=config)
    logger.emit(
        event_type="baseline.create", actor="alice",
        outcome="success", details={},
    )
    logger.emit(
        event_type="breakglass.activate", actor="ops",
        outcome="success", details={"incident_id": "INC-1"},
    )
    logger.emit(
        event_type="baseline.create", actor="alice",
        outcome="success", details={},
    )

    window = AuditVerifier(config=config).review_window()
    assert len(window.highlighted) == 1
    assert window.highlighted[0]["event_type"] == "breakglass.activate"


def test_review_window_detects_tampered_record_in_window(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    _emit_checkpoint(config)
    _emit_n(config, 2)

    lines = config.audit_log.read_text().splitlines()
    # Tamper the last record's actor field without updating self_hash
    record = json.loads(lines[-1])
    record["actor"] = "mallory"
    lines[-1] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    window = AuditVerifier(config=config).review_window()
    assert window.chain_ok is False
    assert any("self_hash mismatch" in e for e in window.chain_errors)


def test_review_window_detects_broken_prev_hash_in_window(
    config: WPGovernConfig,
) -> None:
    _emit_n(config, 3)
    _emit_checkpoint(config)
    _emit_n(config, 3)

    lines = config.audit_log.read_text().splitlines()
    # Break the second post-checkpoint record's prev_hash
    idx = 5  # 3 + 1 checkpoint + 2nd post-checkpoint
    record = json.loads(lines[idx])
    record["prev_hash"] = "f" * 64
    without = dict(record)
    without.pop("self_hash", None)
    record["self_hash"] = hashlib.sha256(
        json.dumps(without, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lines[idx] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    window = AuditVerifier(config=config).review_window()
    assert window.chain_ok is False
    assert any("prev_hash mismatch" in e for e in window.chain_errors)


# ---------------------------------------------------------------------------
# external review regression tests — malformed JSON corruption mode
# ---------------------------------------------------------------------------


def test_verify_raises_integrity_error_on_malformed_json_line(
    config: WPGovernConfig,
) -> None:
    """verify() must raise IntegrityError when any line in the audit log
    is not valid JSON. Pre-fix, JSONDecodeError propagated unhandled and
    fell through governance-check's bare except Exception, returning None
    (clean). The contract is unconditional: malformed JSON is a chain
    integrity failure."""
    logger = AuditLogger(config)
    logger.emit("baseline.create", "alice", "success")

    # Replace the log with a malformed line.
    config.audit_log.write_text("NOT VALID JSON AT ALL\n")

    with pytest.raises(IntegrityError, match="invalid JSON"):
        AuditVerifier(config=config).verify()


def test_governance_check_exits_51_on_malformed_json_no_review_config(
    config: WPGovernConfig,
) -> None:
    """governance-check must exit 51 (chain integrity failure) when the
    audit log contains malformed JSON — regardless of whether
    review_max_age_days is configured. Pre-fix, with no review config,
    the chain check was gated inside _evaluate_review_currency which
    returned None immediately, so the system reported exit 0 (clean)."""
    from wpgovern.status.checker import GovernanceChecker

    assert getattr(config, "review_max_age_days", None) is None
    logger = AuditLogger(config)
    logger.emit("baseline.create", "alice", "success")
    config.audit_log.write_text("NOT VALID JSON AT ALL\n")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 51
    assert "integrity" in result.reason


def test_governance_check_exits_51_not_50_when_review_also_configured(
    tmp_path: Path,
) -> None:
    """governance-check must exit 51, not 50, when the audit log is
    malformed AND review_max_age_days is configured. Pre-fix, the system
    reported exit 50 ('review overdue, no checkpoint') because the chain
    check sat inside the review-currency method which converted the
    JSONDecodeError to a 50 reason. Exit 51 must always take precedence
    over exit 50."""
    from wpgovern.status.checker import GovernanceChecker

    root = tmp_path / "root"
    cfg = WPGovernConfig(
        root_dir=root, install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
        review_max_age_days=30,
    )
    from wpgovern.core.trust import TrustService
    TrustService(config=cfg)
    AuditLogger(cfg).emit("baseline.create", "alice", "success")
    cfg.audit_log.write_text("NOT VALID JSON AT ALL\n")

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 51, (
        f"Expected exit 51 (chain integrity), got {result.exit_code} "
        f"(was 50='review overdue' before fix — the misleading case)"
    )
    assert "integrity" in result.reason


def test_review_window_chain_ok_false_on_malformed_json_line(
    config: WPGovernConfig,
) -> None:
    """review_window() must report chain_ok=False and populate chain_errors
    when any line in the audit log is not valid JSON. Pre-fix,
    JSONDecodeError was silently swallowed with 'continue', so the
    malformed line vanished and review_window reported chain_ok=True.
    A checkpoint could then be written over a corrupt window."""
    logger = AuditLogger(config)
    logger.emit("baseline.create", "alice", "success")
    config.audit_log.write_text("NOT VALID JSON AT ALL\n")

    window = AuditVerifier(config=config).review_window()
    assert window.chain_ok is False
    assert len(window.chain_errors) >= 1
    assert any("invalid JSON" in e for e in window.chain_errors)
