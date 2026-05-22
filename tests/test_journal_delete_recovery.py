"""
Regression tests for the journal delete-intent recovery fix (v25).

external review and external review identified that read_intent_record() was silently
dropping the `deletes` field from IntentRecord. Because signing_input()
includes `deletes`, recovery would reconstruct a different payload and
refuse valid delete-bearing intents with "intent_signature invalid".

This stranded production systems: a gate unlink failure during
ReconciliationService.complete() left the system with a completed
reconciliation record, a valid signed intent, and a gate file that
blocked all activations — but recovery could not resolve it.

Tests:
1. IntentRecord with deletes survives write/read roundtrip with signature intact.
2. Structural roundtrip invariant: any IntentRecord fields survive write→read.
3. Simulated gate unlink failure leaves a resolvable intent.
4. RecoveryService processes the intent, removes the gate, writes complete.
5. Backup directories are cleaned up (no orphan -del/ residue).
"""

from __future__ import annotations

import json
import tempfile
import unittest.mock as mock
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.utils.journal import (
    IntentRecord,
    IntentWrite,
    JournalWriter,
    read_intent_record,
    sign_intent_record,
    verify_intent_signature,
    VERIFY_OK,
)


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
    return cfg, trust


# ---------------------------------------------------------------------------
# Test 1: deletes field survives write/read roundtrip with signature intact
# ---------------------------------------------------------------------------

def test_intent_record_deletes_survive_write_read_roundtrip(env) -> None:
    """IntentRecord.deletes must survive write_intent → read_intent_record.

    Pre-fix: read_intent_record() did not pass deletes= to IntentRecord(),
    so the loaded record had deletes=[] even when the file had deletes=[...].
    This caused signing_input() to diverge and recovery to refuse the intent.
    """
    cfg, trust = env
    journal_dir = cfg.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)

    gate_path = cfg.root_dir / "state" / "reconciliation_required"
    gate_path.write_text("reconciliation-X")

    record = IntentRecord(
        txn_id="txn-test-roundtrip-001",
        started_at="2026-01-01T00:00:00Z",
        service="ReconciliationService.complete",
        actor_id="alice",
        writes=[],
        deletes=[str(gate_path)],
    )
    sign_intent_record(record, trust)

    intent_path = journal_dir / f"{record.txn_id}.intent"
    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()
    writer.write_intent(record)

    loaded = read_intent_record(intent_path)

    # deletes field must be preserved
    assert loaded.deletes == [str(gate_path)], (
        f"deletes dropped after read: expected {[str(gate_path)]!r}, "
        f"got {loaded.deletes!r}"
    )

    # signing_input must match
    assert loaded.signing_input() == record.signing_input(), (
        "signing_input() diverges after write/read — field dropped"
    )


# ---------------------------------------------------------------------------
# Test 2: Structural roundtrip invariant — signature verifies after read
# ---------------------------------------------------------------------------

def test_intent_record_signature_verifies_after_read_with_deletes(env) -> None:
    """verify_intent_signature() must return VERIFY_OK after read_intent_record()
    on a delete-bearing intent. Pre-fix this returned VERIFY_SIGNATURE_INVALID.

    This is the structural invariant external review asked for: any IntentRecord
    written to disk and read back must produce a signing_input() that matches
    the original, so the signature still verifies.
    """
    cfg, trust = env
    gate_path = cfg.root_dir / "state" / "gate"
    gate_path.parent.mkdir(parents=True, exist_ok=True)
    gate_path.write_text("pending")

    record = IntentRecord(
        txn_id="txn-sig-verify-roundtrip",
        started_at="2026-01-01T00:00:00Z",
        service="ReconciliationService.complete",
        actor_id="operator",
        writes=[],
        deletes=[str(gate_path)],
    )
    sign_intent_record(record, trust)

    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()
    writer.write_intent(record)

    intent_path = cfg.root_dir / "state" / ".journal" / f"{record.txn_id}.intent"
    assert intent_path.exists(), f"Intent file not written: {intent_path}"
    loaded = read_intent_record(intent_path)

    result = verify_intent_signature(loaded, trust)
    assert result == VERIFY_OK, (
        f"Signature verification failed after read: {result}. "
        "This means signing_input() diverged between write and read. "
        "Check that read_intent_record() passes all fields to IntentRecord()."
    )


# ---------------------------------------------------------------------------
# Test 3 + 4: Gate unlink failure leaves resolvable intent; recovery resolves
# ---------------------------------------------------------------------------

def test_gate_unlink_failure_leaves_recoverable_intent(env) -> None:
    """Simulated gate unlink failure during ReconciliationService.complete()
    must leave an intent record that RecoveryService can process.

    Pre-fix sequence (stranded system):
    1. complete() raised TransactionError (correctly — v24 fix held)
    2. Record was in 'completed' state on disk (written before the delete)
    3. Signed intent existed with deletes=[gate_path]
    4. Recovery read the intent, reconstructed it WITHOUT deletes
    5. Signature mismatch → recovery.refused
    6. Gate still present → activations blocked indefinitely

    Post-fix sequence:
    1-3: same
    4. Recovery reads intent WITH deletes=[gate_path]
    5. Signature matches → recovery proceeds
    6. Recovery deletes gate, writes complete record
    7. Gate gone → activations unblocked
    """
    from wpgovern.policy.reconciliation import ReconciliationService
    from wpgovern.utils.recovery import RecoveryService
    from wpgovern.paths import build_paths

    cfg, trust = env
    paths = build_paths(cfg)
    paths.state_reconciliation.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)

    # Create a valid reconciliation record
    rec_id = "reconciliation-test-001-aabbccdd"
    rec_path = paths.state_reconciliation / f"{rec_id}.json"
    payload = {
        "reconciliation_id": rec_id,
        "status": "pending",
        "created_at": "2026-01-01T00:00:00Z",
        "emergency_id": None,
        "review_id": None,
        "completed_at": None,
        "source": "manual",
    }
    rec_path.write_text(json.dumps(payload))
    signing = SigningService(config=cfg)
    signing.sign_runtime_artifact(rec_path)

    # Set the matching gate
    paths.reconciliation_required.parent.mkdir(parents=True, exist_ok=True)
    paths.reconciliation_required.write_text(rec_id)

    # Patch Path.unlink to fail for the gate file specifically
    original_unlink = Path.unlink

    def selective_fail_unlink(self, missing_ok=False):
        if self == paths.reconciliation_required:
            raise OSError("Simulated EACCES: permission denied")
        return original_unlink(self, missing_ok=missing_ok)

    svc = ReconciliationService(config=cfg)

    with mock.patch.object(Path, "unlink", selective_fail_unlink):
        with pytest.raises(Exception):
            svc.complete(rec_id)

    # Gate still present (expected — delete failed)
    assert paths.reconciliation_required.exists()

    # Intent record must exist in the journal
    journal_dir = cfg.root_dir / "state" / ".journal"
    intent_files = list(journal_dir.glob("*.intent"))
    assert intent_files, "No intent record written — recovery cannot proceed"

    # Load and verify the intent signature holds (post-fix: deletes are preserved)
    from wpgovern.utils.journal import verify_intent_signature, VERIFY_OK
    intent = read_intent_record(intent_files[0])
    sig_result = verify_intent_signature(intent, trust)
    assert sig_result == VERIFY_OK, (
        f"Intent signature invalid after read: {sig_result}. "
        f"deletes in intent: {intent.deletes!r}"
    )
    assert str(paths.reconciliation_required) in intent.deletes, (
        f"Gate path missing from intent.deletes: {intent.deletes!r}"
    )


def test_recovery_resolves_pending_gate_delete(env) -> None:
    """RecoveryService must execute pending deletes from the intent record,
    remove the gate, write the complete record, and clean up artifacts.

    This is the end-to-end test of the full kill-point-3 + pending-delete
    recovery path introduced in v24 and fixed in v25.
    """
    from wpgovern.policy.reconciliation import ReconciliationService
    from wpgovern.utils.recovery import RecoveryService
    from wpgovern.paths import build_paths

    cfg, trust = env
    paths = build_paths(cfg)
    paths.state_reconciliation.mkdir(parents=True, exist_ok=True)

    rec_id = "reconciliation-recovery-002-deadbeef"
    rec_path = paths.state_reconciliation / f"{rec_id}.json"
    payload = {
        "reconciliation_id": rec_id,
        "status": "pending",
        "created_at": "2026-01-01T00:00:00Z",
        "emergency_id": None,
        "review_id": None,
        "completed_at": None,
        "source": "manual",
    }
    rec_path.write_text(json.dumps(payload))
    signing = SigningService(config=cfg)
    signing.sign_runtime_artifact(rec_path)

    paths.reconciliation_required.parent.mkdir(parents=True, exist_ok=True)
    paths.reconciliation_required.write_text(rec_id)

    original_unlink = Path.unlink

    def selective_fail_unlink(self, missing_ok=False):
        if self == paths.reconciliation_required:
            raise OSError("Simulated gate deletion failure")
        return original_unlink(self, missing_ok=missing_ok)

    svc = ReconciliationService(config=cfg)
    with mock.patch.object(Path, "unlink", selective_fail_unlink):
        with pytest.raises(Exception):
            svc.complete(rec_id)

    # Confirm preconditions
    assert paths.reconciliation_required.exists(), "Gate should still exist"
    journal_dir = cfg.root_dir / "state" / ".journal"
    assert list(journal_dir.glob("*.intent")), "Intent must exist for recovery"

    # Run recovery
    recovery = RecoveryService(config=cfg)
    result = recovery.recover()

    # Gate must be gone after recovery
    assert not paths.reconciliation_required.exists(), (
        "Recovery did not delete the gate file — reconciliation is still blocked"
    )

    # No refused transactions
    refused = [o for o in result.outcomes if o.event_type == "recovery.refused"]
    assert not refused, (
        f"Recovery refused {len(refused)} transaction(s): "
        + "; ".join(o.txn_id for o in refused)
    )

    # Completed outcome expected
    completed = [o for o in result.outcomes if o.event_type == "recovery.completed"]
    assert completed, "Recovery should have completed the pending transaction"

    # No orphan backup directories
    backups_dir = journal_dir / "backups"
    if backups_dir.exists():
        orphan_del_dirs = list(backups_dir.glob("*-del"))
        assert not orphan_del_dirs, (
            f"Orphan delete backup directories found: {orphan_del_dirs}"
        )


# ---------------------------------------------------------------------------
# Test 5: Roundtrip invariant — no field drift between write and read
# ---------------------------------------------------------------------------

def test_intent_record_all_fields_survive_roundtrip(env) -> None:
    """Structural invariant: every field in IntentRecord must survive
    write_intent → read_intent_record with signing_input() unchanged.

    This test catches any future field added to IntentRecord that is not
    also added to read_intent_record(), before a recovery failure finds it.
    Equivalent to the Round-4 bidirectional emit-table scanner but for the
    journal write/read pair.
    """
    cfg, trust = env
    gate = cfg.root_dir / "state" / "test-gate"
    gate.parent.mkdir(parents=True, exist_ok=True)
    gate.write_text("pending")

    staged = cfg.root_dir / "staged_file.json"
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text('{"test": true}')

    record = IntentRecord(
        txn_id="txn-roundtrip-invariant-001",
        started_at="2026-01-01T12:00:00Z",
        service="TestService.operation",
        actor_id="test-operator",
        writes=[
            IntentWrite(
                target=str(cfg.root_dir / "target.json"),
                staged=str(staged),
                old_content_hash=None,
                new_content_hash="a" * 64,
                mode=0o600,
            )
        ],
        deletes=[str(gate)],
    )
    sign_intent_record(record, trust)

    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()
    writer.write_intent(record)

    intent_path = (
        cfg.root_dir / "state" / ".journal" / f"{record.txn_id}.intent"
    )
    loaded = read_intent_record(intent_path)

    assert loaded.signing_input() == record.signing_input(), (
        "signing_input() diverged after write/read roundtrip. "
        "A field is being dropped by read_intent_record(). "
        "Diff:\n"
        f"  original: {record.signing_input()[:200]!r}\n"
        f"  loaded:   {loaded.signing_input()[:200]!r}"
    )

    assert verify_intent_signature(loaded, trust) == VERIFY_OK
    assert loaded.deletes == record.deletes
    assert loaded.txn_id == record.txn_id
    assert loaded.service == record.service
    assert loaded.actor_id == record.actor_id
    assert len(loaded.writes) == len(record.writes)
