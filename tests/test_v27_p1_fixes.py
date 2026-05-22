"""
Regression tests for v27 P1 fixes (external review + external review round 9).

P1.1 — complete-write failure preserves intent, records B4, doesn't claim success
P1.2 — B4 preflight failures are persisted to .last_b4_event.json
P1.3 — pattern-based secret key detection catches compound names
P1.4 — checkpoint_id binding; no scan window limit
P2.2 — audit failure outcome allowed for governance event families
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from wpgovern.audit.logger import AuditLogger, AuditError
from wpgovern.audit.verifier import AuditVerifier
from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import DiskFullError


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
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")
    trust.generate_release_key("release-1")
    trust.activate_release_key("release-1")
    return cfg, trust


# ---------------------------------------------------------------------------
# P1.1 — complete-write failure preserves intent and records B4
# ---------------------------------------------------------------------------

def test_p11_complete_write_b4_preserves_intent(env) -> None:
    """If write_complete() fails with B4Error, the intent must be preserved
    on disk and .last_b4_event.json must be written. Pre-fix: the exception
    was swallowed and cleanup_completed() deleted the intent, erasing all
    evidence."""
    from wpgovern.utils.transaction import AtomicTransaction, TransactionError
    from wpgovern.utils.journal import JournalWriter

    cfg, trust = env
    staging_root = cfg.root_dir / "state" / ".transactions"
    staging_root.mkdir(parents=True, exist_ok=True)

    target = cfg.root_dir / "state" / "test_target.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    def raise_b4(*args, **kwargs):
        raise DiskFullError(
            path=cfg.root_dir / "state" / ".journal",
            phase="complete_write",
            errno_classified=28,
        )

    with mock.patch.object(JournalWriter, "write_complete", raise_b4):
        with pytest.raises(TransactionError, match="complete-record write failed"):
            with AtomicTransaction(
                staging_root,
                service_label="test.complete_write",
                actor_id="test-op",
                journal_root=cfg.root_dir,
                trust_service=trust,
            ) as txn:
                txn.stage_text(target, '{"status":"ok"}')
                txn.commit()

    # Intent must still exist (not deleted by cleanup_completed)
    journal_dir = cfg.root_dir / "state" / ".journal"
    intents = list(journal_dir.glob("*.intent"))
    assert intents, (
        "Intent was deleted after complete-write failure — "
        "recovery cannot proceed without the intent"
    )

    # B4 event must be recorded
    b4_path = cfg.root_dir / "state" / ".last_b4_event.json"
    assert b4_path.exists(), ".last_b4_event.json not written on complete-write B4"
    assert oct(b4_path.stat().st_mode & 0o777) == "0o600"

    # Target must be at new state (writes succeeded)
    assert target.exists()


def test_p11_complete_write_generic_exception_preserves_intent(env) -> None:
    """If write_complete() fails with a non-B4 exception, the intent is
    preserved and TransactionError is raised. Target stays at new state."""
    from wpgovern.utils.transaction import AtomicTransaction, TransactionError
    from wpgovern.utils.journal import JournalWriter

    cfg, trust = env
    staging_root = cfg.root_dir / "state" / ".transactions"
    staging_root.mkdir(parents=True, exist_ok=True)
    target = cfg.root_dir / "state" / "target2.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    def raise_generic(*args, **kwargs):
        raise OSError("disk write error")

    with mock.patch.object(JournalWriter, "write_complete", raise_generic):
        with pytest.raises(TransactionError, match="complete-record write failed"):
            with AtomicTransaction(
                staging_root,
                service_label="test.complete_write2",
                actor_id="op",
                journal_root=cfg.root_dir,
                trust_service=trust,
            ) as txn:
                txn.stage_text(target, '{"x":1}')
                txn.commit()

    journal_dir = cfg.root_dir / "state" / ".journal"
    assert list(journal_dir.glob("*.intent")), "Intent must be preserved for recovery"
    assert target.exists(), "Target must be at new state"


# ---------------------------------------------------------------------------
# P1.2 — B4 preflight failure persists .last_b4_event.json
# ---------------------------------------------------------------------------

def test_p12_preflight_b4_writes_event_file(env) -> None:
    """B4 during preflight must be written to .last_b4_event.json.
    Pre-fix: _b4_preflight() raised B4Error but _record_b4_event() was
    never called, so governance-check could not see the B4 state."""
    from wpgovern.utils.transaction import AtomicTransaction
    from wpgovern.errors import DiskFullError

    cfg, trust = env
    staging_root = cfg.root_dir / "state" / ".transactions"
    staging_root.mkdir(parents=True, exist_ok=True)

    def raise_b4_preflight(self):
        raise DiskFullError(
            path=cfg.root_dir / "state",
            phase="preflight",
            errno_classified=28,
        )

    with mock.patch.object(AtomicTransaction, "_b4_preflight", raise_b4_preflight):
        with pytest.raises(DiskFullError):
            with AtomicTransaction(
                staging_root,
                service_label="test.preflight",
                actor_id="op",
                journal_root=cfg.root_dir,
                trust_service=trust,
            ) as txn:
                txn.commit()

    b4_path = cfg.root_dir / "state" / ".last_b4_event.json"
    assert b4_path.exists(), (
        ".last_b4_event.json not written on preflight B4 — "
        "governance-check cannot surface this B4 condition"
    )
    assert oct(b4_path.stat().st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------
# P1.3 — Pattern-based secret detection
# ---------------------------------------------------------------------------

def test_p13_access_token_nested_rejected(env) -> None:
    """access_token nested inside an allowed field must be rejected.
    Pre-fix: only exact names in _SECRET_FIELD_NAMES were checked;
    compound names like access_token bypassed detection."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit(
            event_type="baseline.create",
            actor="alice",
            outcome="success",
            details={"b4_event": {"access_token": "secret-value"}},
        )


def test_p13_refresh_token_nested_rejected(env) -> None:
    """refresh_token nested inside a dict must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit(
            event_type="baseline.create",
            actor="alice",
            outcome="success",
            details={"b4_event": {"refresh_token": "tok-abc123"}},
        )


def test_p13_client_secret_nested_rejected(env) -> None:
    """client_secret nested inside a dict must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit(
            event_type="baseline.create",
            actor="alice",
            outcome="success",
            details={"b4_event": {"client_secret": "cs-xyz"}},
        )


def test_p13_clean_nested_dict_still_accepted(env) -> None:
    """Clean nested dicts with non-secret keys continue to work."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit(
        event_type="baseline.create",
        actor="alice",
        outcome="success",
        details={"b4_event": {"class": "DiskFullError", "path": "/opt/wpgovern"}},
    )


def test_p13_operator_reason_with_token_word_accepted(env) -> None:
    """Pattern matching applies to KEY NAMES only, not values.
    Operator reason text like 'rotating the token' must not be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit(
        event_type="baseline.create",
        actor="alice",
        outcome="success",
        details={"reason": "rotating the API token for quarterly refresh"},
    )


# ---------------------------------------------------------------------------
# P1.4 — checkpoint_id binding; full-chain scan
# ---------------------------------------------------------------------------

def test_p14_many_interleaved_records_still_resolve(env) -> None:
    """verify_checkpoint_signature must find the companion even with many
    interleaved records. Pre-fix: _SIGNATURE_SCAN_WINDOW=8 meant >8 records
    caused return False. Now uses checkpoint_id + full-chain scan."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success")

    from typer.testing import CliRunner
    from wpgovern.cli import app
    import wpgovern.cli._common as _common
    import wpgovern.cli.commands.audit as _audit_cmd
    _common._config = lambda: cfg
    _audit_cmd._config = lambda: cfg

    runner = CliRunner()
    result = runner.invoke(app, [
        "audit-review", "--json", "--auto-confirm",
        "--actor-id", "auditor", "--reason", "p14 test",
    ])
    assert result.exit_code == 0

    # Emit 20 records AFTER the checkpoint (well beyond the old window of 8)
    for i in range(20):
        logger.emit("baseline.create", f"alice-{i}", "success")

    # Read the checkpoint record
    verifier = AuditVerifier(cfg)
    cp = verifier.last_checkpoint()
    assert cp is not None

    # Must still find the signature despite 20 interleaved records
    result = verifier.verify_checkpoint_signature(cp)
    assert result is True, (
        "verify_checkpoint_signature returned False with 20 interleaved records. "
        "checkpoint_id binding must scan the full chain, not a fixed window."
    )


def test_p14_checkpoint_id_in_both_records(env) -> None:
    """Both the checkpoint record and signature companion must carry
    checkpoint_id for explicit logical binding."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success")

    from typer.testing import CliRunner
    from wpgovern.cli import app
    import wpgovern.cli._common as _common
    import wpgovern.cli.commands.audit as _audit_cmd
    _common._config = lambda: cfg
    _audit_cmd._config = lambda: cfg

    runner = CliRunner()
    runner.invoke(app, [
        "audit-review", "--json", "--auto-confirm",
        "--actor-id", "auditor", "--reason", "id binding test",
    ])

    records = [
        json.loads(l) for l in cfg.audit_log.read_text().splitlines() if l.strip()
    ]
    cp = next(r for r in records if r.get("event_type") == "audit.review.checkpoint")
    sig = next(
        (r for r in records if r.get("event_type") == "audit.checkpoint.signature"),
        None,
    )
    assert sig is not None, "Signature companion record not found"
    assert "checkpoint_id" in cp.get("details", {}), "checkpoint_id missing from checkpoint"
    assert "checkpoint_id" in sig.get("details", {}), "checkpoint_id missing from signature"
    assert cp["details"]["checkpoint_id"] == sig["details"]["checkpoint_id"], (
        "checkpoint_id mismatch between checkpoint and signature companion"
    )


# ---------------------------------------------------------------------------
# P2.2 — Audit failure outcome for governance event families
# ---------------------------------------------------------------------------

def test_p22_failure_outcome_allowed_for_baseline_events(env) -> None:
    """outcome='failure' must be accepted for baseline.* events."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.approve", "alice", "failure",
                details={"baseline_id": "b-1", "reason": "insufficient evidence"})


def test_p22_failure_outcome_allowed_for_release_events(env) -> None:
    """outcome='failure' must be accepted for release.* events."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("release.sign", "operator", "failure",
                details={"reason": "missing manifest"})


def test_p22_failure_outcome_still_rejected_for_custom_events(env) -> None:
    """outcome='failure' must still be rejected for non-governance event types."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError, match="failure"):
        logger.emit("custom.internal.metric", "system", "failure")
