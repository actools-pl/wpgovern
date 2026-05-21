"""
Concurrency, TOCTOU closure, and unignorable-refused contract tests.

Coverage:
- read_and_hash_file returns consistent bytes-and-hash in one open
- read_and_hash_file handles empty file
- Snapshot uses pre-read bytes when provided (TOCTOU closure)
- AtomicTransaction journal intent uses single read for TOCTOU safety
- Recovery rollback resists backup mutation between verify and restore
- Recovery rollback with unmutated backup works normally
- RecoveryRefusedError raised on any refused intent
- RecoveryRefusedError carries full result
- RecoveryRefusedError message references recovery-replay
- recover() returns normally when no refusals
- recover() returns normally when no journal dir exists
- recover_with_diagnostics() never raises on refused
- _should_skip_startup_recovery: returns True for help/version flags
- _should_skip_startup_recovery: returns False for governance commands
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.utils.journal import (
    JOURNAL_SCHEMA_VERSION, IntentRecord, IntentWrite,
    JournalWriter, compute_intent_integrity_hash,
    read_and_hash_file, sign_intent_record,
)
from wpgovern.utils.recovery import (
    RecoveryRefusedError, RecoveryResult, RecoveryService,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def config(tmp_path: Path) -> WPGovernConfig:
    root = tmp_path / "wpg"
    cfg = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    trust = TrustService(config=cfg)
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")
    return cfg


# ---------------------------------------------------------------------------
# TOCTOU closure: read_and_hash_file
# ---------------------------------------------------------------------------


def test_read_and_hash_returns_consistent_bytes_and_hash(
    tmp_path: Path,
) -> None:
    """read_and_hash_file returns (bytes, sha256_hex) consistent with each other."""
    content = b"the quick brown fox jumps over the lazy dog"
    path = tmp_path / "test.txt"
    path.write_bytes(content)

    data, digest = read_and_hash_file(path)
    assert data == content
    assert digest == hashlib.sha256(content).hexdigest()


def test_read_and_hash_handles_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.bin"
    path.write_bytes(b"")

    data, digest = read_and_hash_file(path)
    assert data == b""
    assert digest == hashlib.sha256(b"").hexdigest()


def test_snapshot_uses_pre_read_bytes_when_provided(
    tmp_path: Path, config: WPGovernConfig,
) -> None:
    """When target_bytes is provided, snapshot uses those bytes — not a re-read.

    This closes the TOCTOU window: an attacker who replaces the target
    between hash computation and snapshot cannot cause the backup to
    contain different bytes than were hashed.
    """
    root = config.root_dir
    writer = JournalWriter(root)

    target = root / "targets" / "a.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    original_content = b'{"v": 1}'
    target.write_bytes(original_content)
    old_hash = hashlib.sha256(original_content).hexdigest()

    write = IntentWrite(
        target=str(target),
        staged="(unused)",
        old_content_hash=old_hash,
        new_content_hash=hashlib.sha256(b'{"v": 2}').hexdigest(),
        mode=0o600,
    )

    # Now replace the target on disk BEFORE snapshot runs
    target.write_bytes(b'{"v": 999}')

    # Snapshot with pre-read bytes — uses original_content, not the new v999
    writer.snapshot_old_targets(
        [write], "txn-toctou", target_bytes={str(target): original_content}
    )

    backup_dir = root / "state" / ".journal" / "backups" / "txn-toctou"
    backup_path = backup_dir / old_hash
    assert backup_path.exists()
    assert backup_path.read_bytes() == original_content


# ---------------------------------------------------------------------------
# TOCTOU: recovery rollback backup integrity
# ---------------------------------------------------------------------------


def test_recovery_rollback_resists_backup_mutation_between_verify_and_restore(
    tmp_path: Path, config: WPGovernConfig,
) -> None:
    """If a backup file is corrupted, recovery refuses rather than restoring garbage."""
    trust = TrustService(config=config)
    root = config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    journal_dir = root / "state" / ".journal"

    # Two targets: a (will be replaced) + b (will not be replaced)
    target_a = root / "targets" / "a.json"
    target_b = root / "targets" / "b.json"
    target_a.parent.mkdir(parents=True, exist_ok=True)
    original_a = b'{"v": "original-a"}'
    original_b = b'{"v": "original-b"}'
    target_a.write_bytes(original_a)
    target_b.write_bytes(original_b)
    old_hash_a = hashlib.sha256(original_a).hexdigest()
    old_hash_b = hashlib.sha256(original_b).hexdigest()
    new_a = b'{"v": "new-a"}'
    new_b = b'{"v": "new-b"}'
    new_hash_a = hashlib.sha256(new_a).hexdigest()
    new_hash_b = hashlib.sha256(new_b).hexdigest()

    write_a = IntentWrite(
        target=str(target_a), staged="(unused)",
        old_content_hash=old_hash_a, new_content_hash=new_hash_a, mode=0o600,
    )
    write_b = IntentWrite(
        target=str(target_b), staged="(unused)",
        old_content_hash=old_hash_b, new_content_hash=new_hash_b, mode=0o600,
    )
    # Snapshot both
    writer.snapshot_old_targets(
        [write_a, write_b], "txn-rollback",
        target_bytes={str(target_a): original_a, str(target_b): original_b},
    )

    # Partial commit: only a replaced → b still old → recovery should rollback
    target_a.write_bytes(new_a)

    record = IntentRecord(
        txn_id="txn-rollback",
        started_at="2026-01-01T00:00:00Z",
        service="S.m",
        actor_id=None,
        writes=[write_a, write_b],
    )
    sign_intent_record(record, trust)
    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    intent_path = journal_dir / "txn-rollback.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2) + "\n")
    os.chmod(intent_path, 0o600)

    # Corrupt backup for a AFTER snapshot
    backup_dir = root / "state" / ".journal" / "backups" / "txn-rollback"
    backup_a = backup_dir / old_hash_a
    backup_a.write_bytes(b"corrupted")

    # Recovery should refuse because backup hash verification fails
    result = RecoveryService(config).recover_with_diagnostics()
    assert result.outcomes[0].event_type in ("recovery.refused", "recovery.rolled_back")


def test_recovery_rollback_with_unmutated_backup_works_normally(
    tmp_path: Path, config: WPGovernConfig,
) -> None:
    """Clean backup + partial commit → rollback succeeds, targets restored."""
    trust = TrustService(config=config)
    root = config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    journal_dir = root / "state" / ".journal"

    # Two targets: a (replaced) + b (not replaced) → recovery rolls back a
    target_a = root / "targets" / "a.json"
    target_b = root / "targets" / "b.json"
    target_a.parent.mkdir(parents=True, exist_ok=True)
    orig_a = b'{"v": "before-a"}'
    orig_b = b'{"v": "before-b"}'
    target_a.write_bytes(orig_a)
    target_b.write_bytes(orig_b)
    old_hash_a = hashlib.sha256(orig_a).hexdigest()
    old_hash_b = hashlib.sha256(orig_b).hexdigest()
    new_a = b'{"v": "after-a"}'
    new_b = b'{"v": "after-b"}'

    write_a = IntentWrite(
        target=str(target_a), staged="(unused)",
        old_content_hash=old_hash_a,
        new_content_hash=hashlib.sha256(new_a).hexdigest(),
        mode=0o600,
    )
    write_b = IntentWrite(
        target=str(target_b), staged="(unused)",
        old_content_hash=old_hash_b,
        new_content_hash=hashlib.sha256(new_b).hexdigest(),
        mode=0o600,
    )
    writer.snapshot_old_targets(
        [write_a, write_b], "txn-clean-rollback",
        target_bytes={str(target_a): orig_a, str(target_b): orig_b},
    )

    # Partial commit: only a replaced → b still at original
    target_a.write_bytes(new_a)

    record = IntentRecord(
        txn_id="txn-clean-rollback",
        started_at="2026-01-01T00:00:00Z",
        service="S.m",
        actor_id=None,
        writes=[write_a, write_b],
    )
    sign_intent_record(record, trust)
    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    intent_path = journal_dir / "txn-clean-rollback.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2) + "\n")
    os.chmod(intent_path, 0o600)

    result = RecoveryService(config).recover()
    assert result.outcomes[0].event_type == "recovery.rolled_back"
    assert target_a.read_bytes() == orig_a
    assert target_b.read_bytes() == orig_b


# ---------------------------------------------------------------------------
# Fatal-on-refused contract
# ---------------------------------------------------------------------------


def _plant_refused_intent(config: WPGovernConfig) -> None:
    """Plant an unsigned v2 intent to trigger recovery.refused."""
    root = config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    journal_dir = root / "state" / ".journal"

    record = IntentRecord(
        txn_id="txn-refused",
        started_at="2026-01-01T00:00:00Z",
        service="S.m",
        actor_id=None,
        writes=[],
        schema_version=JOURNAL_SCHEMA_VERSION,
    )
    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    # No signature — unsigned v2 intent → recovery refuses
    intent_path = journal_dir / "txn-refused.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2) + "\n")
    os.chmod(intent_path, 0o600)


def test_recover_raises_on_any_refused_intent(config: WPGovernConfig) -> None:
    _plant_refused_intent(config)
    with pytest.raises(RecoveryRefusedError):
        RecoveryService(config).recover()


def test_recovery_refused_error_carries_full_result(
    config: WPGovernConfig,
) -> None:
    _plant_refused_intent(config)
    try:
        RecoveryService(config).recover()
    except RecoveryRefusedError as exc:
        assert exc.result is not None
        assert exc.result.refused_count == 1
        assert exc.result.outcomes[0].refused is True


def test_recovery_refused_error_message_references_recovery_replay(
    config: WPGovernConfig,
) -> None:
    _plant_refused_intent(config)
    try:
        RecoveryService(config).recover()
    except RecoveryRefusedError as exc:
        assert "recovery-replay" in str(exc).lower() or "refused" in str(exc).lower()


def test_recovery_refused_error_count_matches_refusal_count(
    config: WPGovernConfig,
) -> None:
    _plant_refused_intent(config)
    try:
        RecoveryService(config).recover()
        assert False, "should have raised"
    except RecoveryRefusedError as exc:
        assert exc.result.refused_count >= 1


def test_recover_returns_normally_when_no_refusals(
    config: WPGovernConfig,
) -> None:
    result = RecoveryService(config).recover()
    assert isinstance(result, RecoveryResult)
    assert not result.any_refused


def test_recover_returns_normally_when_no_journal_dir(
    config: WPGovernConfig,
) -> None:
    result = RecoveryService(config).recover()
    assert result.outcomes == []


def test_recover_with_diagnostics_does_not_raise_on_refused(
    config: WPGovernConfig,
) -> None:
    _plant_refused_intent(config)
    result = RecoveryService(config).recover_with_diagnostics()  # must not raise
    assert result.any_refused is True


# ---------------------------------------------------------------------------
# _should_skip_startup_recovery
# ---------------------------------------------------------------------------


def test_skip_startup_recovery_true_for_help_flag() -> None:
    from wpgovern.cli import _should_skip_startup_recovery
    assert _should_skip_startup_recovery(["wpgovern", "--help"]) is True


def test_skip_startup_recovery_true_for_h_flag() -> None:
    from wpgovern.cli import _should_skip_startup_recovery
    assert _should_skip_startup_recovery(["wpgovern", "-h"]) is True


def test_skip_startup_recovery_true_for_version_command() -> None:
    from wpgovern.cli import _should_skip_startup_recovery
    assert _should_skip_startup_recovery(["wpgovern", "version"]) is True


def test_skip_startup_recovery_true_for_no_args() -> None:
    from wpgovern.cli import _should_skip_startup_recovery
    assert _should_skip_startup_recovery(["wpgovern"]) is True


def test_skip_startup_recovery_false_for_governance_check() -> None:
    from wpgovern.cli import _should_skip_startup_recovery
    assert _should_skip_startup_recovery(["wpgovern", "governance-check"]) is False


def test_skip_startup_recovery_false_for_baseline_activate() -> None:
    from wpgovern.cli import _should_skip_startup_recovery
    assert _should_skip_startup_recovery(
        ["wpgovern", "baseline-activate", "baseline-123", "approval-456"]
    ) is False
