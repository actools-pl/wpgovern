"""
Regression tests for v30 fixes.

H1  — Recovery pending-delete B4 → recovery.stuck + .last_b4_event.json
M-H1 — Audit token detection catches list elements
M1  — I-REL-1 catches path traversal even when artifact is absent
M3  — I-AUD-1 invariant for audit checkpoint signature presence
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from wpgovern.audit.logger import AuditLogger, AuditError
from wpgovern.audit.verifier import AuditVerifier
from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService


@pytest.fixture()
def env(tmp_path: Path):
    root = tmp_path / "root"
    cfg = WPGovernConfig(
        root_dir=root, install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    trust = TrustService(config=cfg)
    trust.generate_runtime_key("runtime-1")
    trust.activate_runtime_key("runtime-1")
    trust.generate_release_key("release-1")
    trust.activate_release_key("release-1")
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")
    return cfg, trust


# ---------------------------------------------------------------------------
# H1 — Recovery pending-delete B4 → recovery.stuck
# ---------------------------------------------------------------------------

def test_h1_recovery_pending_delete_b4_produces_stuck(env) -> None:
    """H1: B4 during recovery pending-delete must produce recovery.stuck,
    not recovery.refused, and must persist .last_b4_event.json.

    Pre-fix: bare except OSError → _refuse() with no B4 evidence.
    Post-fix: _classify_during_recovery → recovery.stuck + event file.
    """
    from wpgovern.utils.recovery import RecoveryService
    from wpgovern.utils.journal import (
        JournalWriter, IntentRecord, sign_intent_record,
        hash_file_bytes, IntentWrite,
    )
    from wpgovern.errors import DiskFullError

    cfg, trust = env

    # Create target file at new state (kill point 3: writes done, delete pending)
    target = cfg.root_dir / "state" / "target.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"status": "committed"}')

    # Gate file exists (delete didn't happen yet)
    gate = cfg.root_dir / "state" / "gate.txt"
    gate.write_text("pending")

    journal_dir = cfg.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)

    new_hash = hash_file_bytes(target)
    record = IntentRecord(
        txn_id="txn-h1-pending-delete-b4",
        started_at="2026-01-01T00:00:00Z",
        service="test.pending_delete_b4",
        actor_id="op",
        writes=[IntentWrite(
            target=str(target),
            staged=str(target),
            old_content_hash=None,
            new_content_hash=new_hash,
            mode=0o600,
        )],
        deletes=[str(gate)],
    )
    sign_intent_record(record, trust)
    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()
    writer.write_intent(record)

    # Simulate B4 during recovery's pending delete (ENOSPC)
    original_unlink = Path.unlink

    def fail_with_enospc(self, missing_ok=False):
        if self == gate:
            raise OSError(28, "No space left on device")
        original_unlink(self, missing_ok=missing_ok)

    with mock.patch.object(Path, "unlink", fail_with_enospc):
        result = RecoveryService(config=cfg).recover_with_diagnostics()

    # Must produce recovery.stuck, not recovery.refused
    stuck = [o for o in result.outcomes if o.event_type == "recovery.stuck"]
    refused = [o for o in result.outcomes if o.event_type == "recovery.refused"]
    assert stuck, (
        f"B4 ENOSPC during pending delete must produce recovery.stuck, "
        f"got: refused={len(refused)} stuck={len(stuck)}. "
        f"Outcomes: {[o.event_type for o in result.outcomes]}"
    )

    # B4 event file must be written with mode 0600
    b4_path = cfg.root_dir / "state" / ".last_b4_event.json"
    assert b4_path.exists(), (
        "recovery.stuck must write .last_b4_event.json so governance-check "
        "can surface the B4 condition."
    )
    assert oct(b4_path.stat().st_mode & 0o777) == "0o600"

    # Gate must still exist (not deleted — recovery was stuck)
    assert gate.exists(), "Gate must remain when recovery is stuck"


def test_h1_recovery_pending_delete_non_b4_still_refuses(env) -> None:
    """Non-B4 delete failures during recovery still produce recovery.refused.
    Only B4-classified conditions trigger recovery.stuck."""
    from wpgovern.utils.recovery import RecoveryService
    from wpgovern.utils.journal import (
        JournalWriter, IntentRecord, sign_intent_record,
        hash_file_bytes, IntentWrite,
    )

    cfg, trust = env
    target = cfg.root_dir / "state" / "target2.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"status": "ok"}')
    gate = cfg.root_dir / "state" / "gate2.txt"
    gate.write_text("pending")

    journal_dir = cfg.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)

    new_hash = hash_file_bytes(target)
    record = IntentRecord(
        txn_id="txn-h1-nonb4-delete",
        started_at="2026-01-01T00:00:00Z",
        service="test.nonb4_delete",
        actor_id="op",
        writes=[IntentWrite(
            target=str(target),
            staged=str(target),
            old_content_hash=None,
            new_content_hash=new_hash,
            mode=0o600,
        )],
        deletes=[str(gate)],
    )
    sign_intent_record(record, trust)
    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()
    writer.write_intent(record)

    # Non-B4 OSError (errno not in B4 set)
    original_unlink = Path.unlink

    def fail_non_b4(self, missing_ok=False):
        if self == gate:
            raise OSError(2, "No such file or directory")  # ENOENT — not B4
        original_unlink(self, missing_ok=missing_ok)

    with mock.patch.object(Path, "unlink", fail_non_b4):
        result = RecoveryService(config=cfg).recover_with_diagnostics()

    refused = [o for o in result.outcomes if o.event_type == "recovery.refused"]
    assert refused, (
        f"Non-B4 delete failure must produce recovery.refused, "
        f"got: {[o.event_type for o in result.outcomes]}"
    )


# ---------------------------------------------------------------------------
# M-H1 — Token detection for list elements
# ---------------------------------------------------------------------------

def test_mh1_token_in_nested_list_rejected(env) -> None:
    """Token-like values inside nested lists must be rejected.
    Pre-fix: only dict values were checked; list elements bypassed detection."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": ["sk-abcdefghijklmnopqrstuvwxyz12345"]})


def test_mh1_bearer_token_in_nested_list_rejected(env) -> None:
    """Bearer tokens inside lists must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": ["Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"]})


def test_mh1_aws_key_in_nested_list_rejected(env) -> None:
    """AWS access keys inside lists must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": ["AKIAIOSFODNN7EXAMPLE"]})


def test_mh1_authorization_header_in_list_rejected(env) -> None:
    """Authorization header strings inside lists must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": {"headers": ["Authorization: Bearer token123"]}})


def test_mh1_clean_list_accepted(env) -> None:
    """Clean string lists without token-like values are accepted."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success",
                details={"b4_event": {"phases": ["preflight", "intent_write", "complete"]}})


# ---------------------------------------------------------------------------
# M1 — I-REL-1 catches traversal when artifact is absent
# ---------------------------------------------------------------------------

def test_m1_irel1_catches_traversal_when_artifact_absent(env) -> None:
    """I-REL-1 must fire for path traversal in the manifest even if the
    artifact file does not exist. Pre-fix: existence check ran first."""
    from wpgovern.utils.invariants import check_all_invariants

    cfg, _ = env
    dist_dir = cfg.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    # Write a manifest with path traversal — artifact does NOT exist
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [
            {"path": "../outside.tar.gz", "sha256": "a" * 64}
        ],
    }))

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-REL-1" in ids, (
        "I-REL-1 must detect '../' path traversal even when the artifact file "
        "does not exist. The path string is invalid regardless."
    )


def test_m1_irel1_catches_absolute_path(env) -> None:
    """I-REL-1 must fire for absolute artifact paths."""
    from wpgovern.utils.invariants import check_all_invariants

    cfg, _ = env
    dist_dir = cfg.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [{"path": "/etc/passwd", "sha256": "a" * 64}],
    }))
    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-REL-1" in ids


# ---------------------------------------------------------------------------
# M3 — I-AUD-1 invariant for checkpoint signatures
# ---------------------------------------------------------------------------

def test_m3_iaud1_catches_unsigned_checkpoint(env) -> None:
    """I-AUD-1 must fire when a checkpoint has no signature companion."""
    from wpgovern.utils.invariants import check_all_invariants

    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success")

    # Emit a checkpoint WITHOUT the signature companion
    logger.emit(
        event_type="audit.review.checkpoint",
        actor="auditor",
        outcome="success",
        details={
            "checkpoint_id": "cp-test-no-sig",
            "review_period_start": "",
            "review_period_end": "",
            "records_reviewed": 1,
            "highlighted_count": 0,
            "chain_start_hash": "0" * 64,
            "chain_end_hash": "a" * 64,
            "review_status": "clean",
        },
    )
    # No audit.checkpoint.signature emitted

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-AUD-1" in ids, (
        "I-AUD-1 must fire when a checkpoint has no signature companion"
    )


def test_m3_iaud1_passes_for_signed_checkpoint(env) -> None:
    """I-AUD-1 must not fire when checkpoints are properly signed."""
    from wpgovern.utils.invariants import check_all_invariants
    from wpgovern.core.signing import SigningService
    from typer.testing import CliRunner
    from wpgovern.cli import app
    import wpgovern.cli._common as _common
    import wpgovern.cli.commands.audit as _audit_cmd

    cfg, _ = env
    _common._config = lambda: cfg
    _audit_cmd._config = lambda: cfg

    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success")

    runner = CliRunner()
    result = runner.invoke(app, [
        "audit-review", "--json", "--auto-confirm",
        "--actor-id", "auditor", "--reason", "iaud1 test",
    ])
    assert result.exit_code == 0

    violations = check_all_invariants(cfg)
    aud1_violations = [v for v in violations if v.invariant_id == "I-AUD-1"]
    assert not aud1_violations, (
        f"I-AUD-1 must not fire when checkpoint is properly signed. "
        f"Got violations: {aud1_violations}"
    )
