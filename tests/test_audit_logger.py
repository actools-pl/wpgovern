"""
Tests for wpgovern.audit.logger — AuditLogger, AuditRecord, sanitise_details,
AUDIT_ALLOWED_FIELDS, hash chain invariants, outcome validation.

Coverage:
- Hash chain: prev_hash of record N equals self_hash of record N-1
- self_hash is recomputable from without_self_hash()
- First record chains to AUDIT_GENESIS_HASH
- sanitise_details: preserves all allowed fields
- sanitise_details: strips unknown fields silently
- sanitise_details: rejects secret field NAMES (B-6 field-name check)
- sanitise_details: accepts reason text that mentions the word "password" (B-6 regression)
- sanitise_details: accepts "Per password rotation policy" in reason (external review B-6)
- sanitise_details: rejects PEM private-key material in values
- sanitise_details: rejects non-printable characters in values
- sanitise_details: rejects non-JSON-serializable types
- sanitise_details: rejects oversized payload
- service field regex validation
- failure outcome scope: allowed for recovery.*, rejected for others
- unknown outcome rejected
- emit with malformed details does not corrupt chain
- seq is monotonically increasing
- AuditRecord.as_dict() round-trips
- AUDIT_ALLOWED_FIELDS completeness pins
- LOCK_ORDER recovery-first pin
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from wpgovern.audit.logger import (
    AUDIT_ALLOWED_FIELDS,
    AUDIT_FAILURE_ALLOWED_EVENT_PREFIX,
    AUDIT_GENESIS_HASH,
    AUDIT_MAX_DETAILS_SIZE,
    AuditError,
    AuditLogger,
    AuditRecord,
    _SERVICE_LABEL_RE,
)
from wpgovern.config import WPGovernConfig
from wpgovern.errors import ValidationError
from wpgovern.utils.locking import LOCK_ORDER


# ---------------------------------------------------------------------------
# Fixtures
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


@pytest.fixture()
def logger(config: WPGovernConfig) -> AuditLogger:
    return AuditLogger(config=config)


# ---------------------------------------------------------------------------
# Hash chain invariants
# ---------------------------------------------------------------------------


def test_first_record_chains_to_genesis_hash(logger: AuditLogger) -> None:
    record = logger.emit("baseline.create", "alice", "success")
    assert record.prev_hash == AUDIT_GENESIS_HASH


def test_second_record_prev_hash_equals_first_self_hash(logger: AuditLogger) -> None:
    first = logger.emit("baseline.create", "alice", "success")
    second = logger.emit("baseline.submit", "alice", "success", {"baseline_id": "b-1"})
    assert second.prev_hash == first.self_hash


def test_self_hash_is_recomputable_from_without_self_hash(logger: AuditLogger) -> None:
    record = logger.emit("baseline.create", "alice", "success")
    canonical = json.dumps(record.without_self_hash(), sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert record.self_hash == expected


def test_chain_of_three_records_is_fully_linked(logger: AuditLogger) -> None:
    r1 = logger.emit("baseline.create", "alice", "success")
    r2 = logger.emit("baseline.submit", "alice", "success")
    r3 = logger.emit("baseline.approve", "alice", "success")
    assert r1.prev_hash == AUDIT_GENESIS_HASH
    assert r2.prev_hash == r1.self_hash
    assert r3.prev_hash == r2.self_hash


def test_seq_increments_monotonically(logger: AuditLogger) -> None:
    r1 = logger.emit("baseline.create", "alice", "success")
    r2 = logger.emit("baseline.submit", "alice", "success")
    r3 = logger.emit("baseline.approve", "alice", "success")
    assert r1.seq == 1
    assert r2.seq == 2
    assert r3.seq == 3


def test_records_written_to_log_file(logger: AuditLogger, config: WPGovernConfig) -> None:
    logger.emit("baseline.create", "alice", "success")
    logger.emit("baseline.submit", "alice", "success")
    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# AuditRecord
# ---------------------------------------------------------------------------


def test_audit_record_without_self_hash_excludes_self_hash(logger: AuditLogger) -> None:
    record = logger.emit("baseline.create", "alice", "success")
    d = record.without_self_hash()
    assert "self_hash" not in d
    assert "seq" in d and "prev_hash" in d


def test_audit_record_as_dict_includes_all_fields(logger: AuditLogger) -> None:
    record = logger.emit("baseline.create", "alice", "success")
    d = record.as_dict()
    for key in ("seq", "timestamp", "event_type", "actor", "outcome", "details", "prev_hash", "self_hash"):
        assert key in d


# ---------------------------------------------------------------------------
# sanitise_details — allowed fields
# ---------------------------------------------------------------------------


def test_sanitise_preserves_known_allowed_field(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"baseline_id": "b-1", "actor_id": "alice"})
    assert result["baseline_id"] == "b-1"
    assert result["actor_id"] == "alice"


def test_sanitise_strips_unknown_field_silently(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"baseline_id": "b-1", "totally_unknown": "value"})
    assert "totally_unknown" not in result
    assert "baseline_id" in result


# ---------------------------------------------------------------------------
# sanitise_details — B-6: field-name check (not value-content check)
# ---------------------------------------------------------------------------


def test_sanitise_rejects_field_named_password(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError), match="secret"):
        logger.sanitise_details({"password": "hunter2"})


def test_sanitise_rejects_field_named_secret(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError)):
        logger.sanitise_details({"secret": "s3cr3t"})


def test_sanitise_rejects_field_named_token(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError)):
        logger.sanitise_details({"token": "bearer-abc"})


def test_sanitise_rejects_field_named_private_key(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError)):
        logger.sanitise_details({"private_key": "-----BEGIN RSA PRIVATE KEY-----"})


def test_sanitise_accepts_reason_value_mentioning_password(logger: AuditLogger) -> None:
    """B-6 regression: reason text that contains the word 'password' must be accepted.
    Only field NAMES trigger the secret check, not field VALUES."""
    result = logger.sanitise_details({"reason": "contains password=abc123"})
    assert "reason" in result


def test_sanitise_accepts_per_password_rotation_policy_reason(logger: AuditLogger) -> None:
    """external review B-6 named regression: 'Per password rotation policy' must be accepted."""
    result = logger.sanitise_details({"reason": "Per password rotation policy"})
    assert result["reason"] == "Per password rotation policy"


def test_sanitise_accepts_reason_mentioning_token(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"reason": "revoked expired token as per SOP"})
    assert "reason" in result


# ---------------------------------------------------------------------------
# sanitise_details — PEM marker check (value content)
# ---------------------------------------------------------------------------


def test_sanitise_rejects_pem_private_key_in_value(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError), match="PEM key material"):
        logger.sanitise_details({"reason": "-----BEGIN PRIVATE KEY-----\nMIIEvg..."})


def test_sanitise_rejects_rsa_private_key_pem_in_value(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError), match="PEM key material"):
        logger.sanitise_details({"justification": "BEGIN RSA PRIVATE KEY found in log"})


# ---------------------------------------------------------------------------
# sanitise_details — non-printable characters
# ---------------------------------------------------------------------------


def test_sanitise_rejects_non_printable_character_in_value(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError), match="non-printable"):
        logger.sanitise_details({"reason": "bad\x01char"})


def test_sanitise_accepts_tab_in_value(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"reason": "tab\there"})
    assert "reason" in result


# ---------------------------------------------------------------------------
# sanitise_details — type validation
# ---------------------------------------------------------------------------


def test_sanitise_rejects_tuple_value(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError)):
        logger.sanitise_details({"reason": ("a", "b")})  # type: ignore[arg-type]


def test_sanitise_accepts_none_value(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"reason": None})
    assert result.get("reason") is None


def test_sanitise_accepts_int_value(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"ttl_minutes": 30})
    assert result["ttl_minutes"] == 30


def test_sanitise_accepts_bool_value(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"forced": True})
    assert result["forced"] is True


def test_sanitise_rejects_oversized_payload(logger: AuditLogger) -> None:
    with pytest.raises((AuditError, ValidationError), match="size limit"):
        logger.sanitise_details({"reason": "x" * 5000})


# ---------------------------------------------------------------------------
# sanitise_details — service field regex
# ---------------------------------------------------------------------------


def test_service_field_accepts_valid_dotted_label(logger: AuditLogger) -> None:
    result = logger.sanitise_details({"service": "BaselineService.activate"})
    assert result["service"] == "BaselineService.activate"


def test_service_field_rejects_label_with_spaces(logger: AuditLogger) -> None:
    with pytest.raises(AuditError, match=r"service.*\^"):
        logger.sanitise_details({"service": "Bad Service"})


def test_service_field_rejects_empty_string(logger: AuditLogger) -> None:
    with pytest.raises(AuditError):
        logger.sanitise_details({"service": ""})


def test_service_label_regex_accepts_valid_forms() -> None:
    for label in ("Foo", "foo_bar", "Foo.bar_42", "a", "A.B.C"):
        assert _SERVICE_LABEL_RE.match(label), f"Expected match: {label!r}"


def test_service_label_regex_rejects_hyphens() -> None:
    assert not _SERVICE_LABEL_RE.match("Service-hyphen")


def test_service_label_regex_rejects_slashes() -> None:
    assert not _SERVICE_LABEL_RE.match("Service/slash")


# ---------------------------------------------------------------------------
# Outcome validation
# ---------------------------------------------------------------------------


def test_failure_outcome_allowed_for_recovery_events(logger: AuditLogger) -> None:
    record = logger.emit(
        "recovery.refused", "recovery", "failure",
        {"txn_id": "txn-001", "service": "BaselineService.activate", "divergent_targets_count": 1},
    )
    assert record.outcome == "failure"


def test_failure_outcome_rejected_for_non_governance_events(logger: AuditLogger) -> None:
    """outcome='failure' is rejected for event types outside governance families."""
    with pytest.raises(AuditError, match="failure"):
        logger.emit("custom.internal.event", "alice", "failure", {"baseline_id": "b-1"})


def test_unknown_outcome_rejected(logger: AuditLogger) -> None:
    with pytest.raises(AuditError, match="Unknown audit outcome"):
        logger.emit("baseline.activate", "alice", "badoutcome")


def test_all_valid_non_failure_outcomes_accepted(logger: AuditLogger) -> None:
    for outcome in ("success", "warning", "info", "skipped"):
        record = logger.emit("baseline.create", "alice", outcome)
        assert record.outcome == outcome


# ---------------------------------------------------------------------------
# Emit resilience
# ---------------------------------------------------------------------------


def test_emit_with_malformed_details_does_not_corrupt_chain(logger: AuditLogger) -> None:
    """A failed emit due to bad details must not write a partial record."""
    logger.emit("baseline.create", "alice", "success")

    with pytest.raises((AuditError, ValidationError)):
        logger.emit("baseline.submit", "alice", "success", {"reason": "x" * 5000})

    # Chain must still be valid: only the first record exists.
    r3 = logger.emit("baseline.approve", "alice", "success")
    assert r3.seq == 2
    assert r3.prev_hash != AUDIT_GENESIS_HASH


# ---------------------------------------------------------------------------
# Allowlist completeness pins (from v21 test_v10_phase1_audit_allowlist)
# ---------------------------------------------------------------------------


def test_audit_allowlist_includes_txn_id() -> None:
    assert "txn_id" in AUDIT_ALLOWED_FIELDS


def test_audit_allowlist_includes_service() -> None:
    assert "service" in AUDIT_ALLOWED_FIELDS


def test_audit_allowlist_includes_recovery_count_fields() -> None:
    assert "targets_restored_count" in AUDIT_ALLOWED_FIELDS
    assert "targets_deleted_count" in AUDIT_ALLOWED_FIELDS
    assert "divergent_targets_count" in AUDIT_ALLOWED_FIELDS


def test_audit_allowlist_includes_recovery_report_fields() -> None:
    assert "recovery_report_id" in AUDIT_ALLOWED_FIELDS
    assert "recovery_report_hash" in AUDIT_ALLOWED_FIELDS


def test_audit_allowlist_includes_review_checkpoint_fields() -> None:
    for field in (
        "review_period_start", "review_period_end", "records_reviewed",
        "highlighted_count", "chain_start_hash", "chain_end_hash", "review_status",
    ):
        assert field in AUDIT_ALLOWED_FIELDS, f"Missing: {field}"


def test_audit_allowlist_includes_trust_backup_fields() -> None:
    for field in ("output_path", "size_bytes", "algorithm", "backup_source", "restored_to", "forced"):
        assert field in AUDIT_ALLOWED_FIELDS, f"Missing: {field}"


def test_audit_failure_prefix_constant_is_recovery_dot() -> None:
    assert AUDIT_FAILURE_ALLOWED_EVENT_PREFIX == "recovery."


# ---------------------------------------------------------------------------
# LOCK_ORDER pin
# ---------------------------------------------------------------------------


def test_recovery_lock_is_first_in_lock_order() -> None:
    assert LOCK_ORDER[0] == "recovery"
