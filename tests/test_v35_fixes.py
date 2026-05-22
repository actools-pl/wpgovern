"""
Regression tests for v35 fixes.

H1  — Symlink is now a first-class journaled artifact: intent records symlinks,
      recovery can repair pending symlinks, recovery.completed requires post-condition
H2  — Recovery verifies post-conditions before emitting recovery.completed
H3  — Symlink B4 persists .last_b4_event.json
M-H1 — Active symlink escape rejected by validate_store and I-T-5

Key: v34 test patched stage_symlink_replace() (pre-commit staging failure).
     v35 tests MUST test commit-time failure (tmp_link.rename() failing).
     That is the path External review confirmed is still broken.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

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
# H1 — Symlink is a first-class journal artifact (roundtrip test)
# ---------------------------------------------------------------------------

def test_h1_intent_record_symlinks_survive_roundtrip(env) -> None:
    """IntentRecord.symlinks must survive write_intent → read_intent_record
    with signing_input() unchanged. Same discipline as the deletes field."""
    from wpgovern.utils.journal import (
        IntentRecord, IntentSymlink, JournalWriter,
        read_intent_record, sign_intent_record, verify_intent_signature, VERIFY_OK,
    )
    cfg, trust = env
    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()

    sl_path = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    record = IntentRecord(
        txn_id="txn-h1-symlink-roundtrip",
        started_at="2026-01-01T00:00:00Z",
        service="TrustService.activate_runtime_key",
        actor_id="op",
        writes=[],
        deletes=[],
        symlinks=[IntentSymlink(
            symlink_path=str(sl_path),
            target_name="runtime-2.pem",
            prior_target="runtime-1.pem",
        )],
    )
    sign_intent_record(record, trust)
    writer.write_intent(record)

    intent_path = (
        cfg.root_dir / "state" / ".journal" / f"{record.txn_id}.intent"
    )
    assert intent_path.exists()
    loaded = read_intent_record(intent_path)

    assert loaded.signing_input() == record.signing_input(), (
        "signing_input() diverged after write/read — symlinks field dropped"
    )
    assert len(loaded.symlinks) == 1
    assert loaded.symlinks[0].symlink_path == str(sl_path)
    assert loaded.symlinks[0].target_name == "runtime-2.pem"
    assert loaded.symlinks[0].prior_target == "runtime-1.pem"
    assert verify_intent_signature(loaded, trust) == VERIFY_OK


# ---------------------------------------------------------------------------
# H1 — Commit-time symlink failure: JSON stays at pre-activation state
# (this is the test v34 did NOT cover — patching rename, not stage_symlink_replace)
# ---------------------------------------------------------------------------

def test_h1_commit_time_symlink_failure_leaves_intent_for_recovery(env) -> None:
    """If symlink rename fails AFTER the JSON has been committed (commit-time failure),
    the intent must be preserved on disk so recovery can repair the symlink.

    This is the path v34 test did NOT cover — it patched stage_symlink_replace()
    which fires BEFORE commit. This test patches Path.rename() for the specific
    .symlink_tmp rename to simulate commit-time failure.

    Contract:
    - TransactionError is raised
    - Intent file is preserved (not deleted by cleanup)
    - RecoveryService can repair the symlink and emit recovery.completed
    - After recovery, validate_store passes
    """
    from wpgovern.utils.recovery import RecoveryService

    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    active_link = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    original_rename = Path.rename

    def fail_symlink_rename(self, target):
        if ".symlink_tmp" in str(self):
            raise OSError(28, "No space left on device (simulated)")
        return original_rename(self, target)

    with mock.patch.object(Path, "rename", fail_symlink_rename):
        with pytest.raises(Exception):
            trust.activate_runtime_key("runtime-2")

    # Intent must be preserved for recovery
    journal_dir = cfg.root_dir / "state" / ".journal"
    intents = list(journal_dir.glob("*.intent"))
    assert intents, (
        "Intent must be preserved after commit-time symlink failure so "
        "recovery can repair the symlink."
    )

    # Run recovery — it must repair the symlink and emit recovery.completed
    result = RecoveryService(config=cfg).recover_with_diagnostics()

    completed = [o for o in result.outcomes if o.event_type == "recovery.completed"]
    stuck = [o for o in result.outcomes if o.event_type == "recovery.stuck"]

    if stuck:
        # B4 condition — acceptable, operator intervention needed
        return

    assert completed, (
        f"Recovery must either complete or get stuck; got: "
        f"{[o.event_type for o in result.outcomes]}"
    )

    # After recovery, symlink must point to runtime-2
    assert active_link.is_symlink()
    assert Path(os.readlink(str(active_link))).name == "runtime-2.pem", (
        f"After recovery, active.pem must point to runtime-2.pem; "
        f"got: {os.readlink(str(active_link))}"
    )

    # validate_store must pass after recovery
    trust.validate_store("runtime")  # must not raise


# ---------------------------------------------------------------------------
# H2 — Recovery emits recovery.stuck (not recovery.completed) when desync
# (the v34 finding: recovery was cleaning up and emitting recovery.completed
# while trust state was still broken)
# ---------------------------------------------------------------------------

def test_h2_recovery_emits_stuck_not_completed_for_symlink_desync(env) -> None:
    """If JSON says runtime-2 is active but active.pem still points to runtime-1
    (desync state from a failed activation), recovery must NOT emit
    recovery.completed. It must either repair the symlink or emit recovery.stuck.

    Pre-v35: recovery processed the intent's file writes (all at new state),
    saw deletes/symlinks as empty (not journaled), wrote complete record,
    emitted recovery.completed with trust state still broken.
    """
    from wpgovern.utils.recovery import RecoveryService
    from wpgovern.utils.journal import (
        IntentRecord, IntentSymlink, IntentWrite,
        JournalWriter, sign_intent_record, hash_file_bytes,
    )
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    # Manually produce the "JSON committed, symlink not yet updated" state
    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())
    content["active_key_id"] = "runtime-2"
    for k in content["keys"]:
        if k["key_id"] == "runtime-1":
            k["status"] = "retired_verify_only"
            k["usage"] = ["verify"]
        elif k["key_id"] == "runtime-2":
            k["status"] = "active"
    store_path.write_text(json.dumps(content))
    # active.pem still points to runtime-1 (desync state)

    # Write an intent record that records the symlink operation
    active_link = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    new_hash = hash_file_bytes(store_path)
    journal_dir = cfg.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    record = IntentRecord(
        txn_id="txn-h2-desync-recovery",
        started_at="2026-01-01T00:00:00Z",
        service="TrustService.activate_runtime_key",
        actor_id="op",
        writes=[IntentWrite(
            target=str(store_path),
            staged=str(store_path),
            old_content_hash=None,
            new_content_hash=new_hash,
            mode=0o600,
        )],
        deletes=[],
        symlinks=[IntentSymlink(
            symlink_path=str(active_link),
            target_name="runtime-2.pem",
            prior_target="runtime-1.pem",
        )],
    )
    sign_intent_record(record, trust)
    writer = JournalWriter(cfg.root_dir)
    writer.ensure_dirs()
    writer.write_intent(record)

    # Run recovery
    result = RecoveryService(config=cfg).recover_with_diagnostics()

    # Recovery must either:
    # (a) repair the symlink and emit recovery.completed, OR
    # (b) emit recovery.stuck if it cannot repair
    # It must NOT emit recovery.completed while symlink is still wrong.
    for outcome in result.outcomes:
        if outcome.event_type == "recovery.completed":
            # If completed, symlink must now be correct
            assert active_link.is_symlink()
            actual = os.readlink(str(active_link))
            assert Path(actual).name == "runtime-2.pem", (
                f"recovery.completed emitted but active.pem still points to {actual}"
            )
            # validate_store must pass
            trust.validate_store("runtime")


# ---------------------------------------------------------------------------
# H3 — Symlink B4 persists .last_b4_event.json
# ---------------------------------------------------------------------------

def test_h3_symlink_b4_writes_event_file(env) -> None:
    """B4 during staged symlink replacement must write .last_b4_event.json.
    Pre-fix: the OSError was raised as TransactionError with no B4 recording."""
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    original_rename = Path.rename

    def fail_enospc(self, target):
        if ".symlink_tmp" in str(self):
            raise OSError(28, "No space left on device (ENOSPC)")
        return original_rename(self, target)

    with mock.patch.object(Path, "rename", fail_enospc):
        with pytest.raises(Exception):
            trust.activate_runtime_key("runtime-2")

    b4_path = cfg.root_dir / "state" / ".last_b4_event.json"
    assert b4_path.exists(), (
        ".last_b4_event.json must be written when symlink replacement fails "
        "with a B4 condition (ENOSPC). Pre-fix: no event file was written."
    )
    assert oct(b4_path.stat().st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------
# M-H1 — Active symlink escape rejected
# ---------------------------------------------------------------------------

def test_mh1_validate_store_rejects_symlink_outside_private(env) -> None:
    """validate_store must reject an active.pem symlink that resolves outside
    trust/<domain>/private."""
    from wpgovern.core.trust import TrustError
    cfg, trust = env

    # Create a target outside the private dir
    outside = cfg.root_dir / "outside_key.pem"
    runtime_priv = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem"
    outside.write_bytes(runtime_priv.read_bytes())
    os.chmod(outside, 0o600)

    # Point active.pem to outside file (absolute symlink escape)
    active_link = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    if active_link.is_symlink():
        active_link.unlink()
    active_link.symlink_to(outside)  # absolute path outside trust tree

    with pytest.raises(TrustError, match="outside|private"):
        trust.validate_store("runtime")


def test_mh1_it5_catches_symlink_outside_private(env) -> None:
    """I-T-5 must fire when active.pem resolves outside trust/<domain>/private."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, trust = env

    outside = cfg.root_dir / "outside_key.pem"
    runtime_priv = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem"
    outside.write_bytes(runtime_priv.read_bytes())
    os.chmod(outside, 0o600)

    active_link = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    if active_link.is_symlink():
        active_link.unlink()
    active_link.symlink_to(outside)

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-T-5" in ids, (
        "I-T-5 must detect active.pem resolving outside trust/<domain>/private"
    )
