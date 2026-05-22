"""
Tests for wpgovern.utils.journal — JournalWriter, record dataclasses,
integrity hash, backup store, signing helpers.

Coverage:
- Intent record written with all required fields and integrity hash
- Integrity hash is recomputable from the written record
- Integrity hash changes when any field changes
- Backup store: existing targets snapshotted correctly
- First-write targets (old_content_hash=None) get no backup
- Complete record format and fields
- Cleanup removes intent, complete, and backups
- Intent file mode 0o600, journal directory mode 0o700
- fsync count invariant (≥3 for two-target snapshot)
- Snapshot raises when target disappears
- write_intent rejects pre-set integrity hash mismatch
- AtomicTransaction writes journal when service_label provided
- AtomicTransaction writes no journal when service_label absent
- AtomicTransaction: intent survives partial commit (kill point 2)
- read_intent_record / read_complete_record round-trip
- Schema version preserved on round-trip
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from wpgovern.utils.journal import (
    JOURNAL_SCHEMA_VERSION,
    CompleteRecord,
    IntentRecord,
    IntentWrite,
    JournalError,
    JournalWriter,
    compute_intent_integrity_hash,
    hash_file_bytes,
    list_complete_records,
    list_intent_records,
    read_complete_record,
    read_intent_record,
    sign_intent_record,
)
from wpgovern.utils.locking import LockManager
from wpgovern.utils.transaction import AtomicTransaction, TransactionError


# ---------------------------------------------------------------------------
# Minimal test trust service — generates real ed25519 keys via openssl.
# Does not depend on Phase 5 (core.trust).
# ---------------------------------------------------------------------------


class _FakeTrustService:
    """Minimal TrustService duck-type for journal signing tests.

    Generates a real ed25519 key pair on construction. Used to test
    sign_intent_record / verify_intent_signature without TrustService.
    """

    def __init__(self, tmp_path: Path, key_id: str = "test-key") -> None:
        self.key_id = key_id
        self._private = tmp_path / f"{key_id}.pem"
        self._public = tmp_path / f"{key_id}_pub.pem"
        tmp_path.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self._private)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["openssl", "pkey", "-in", str(self._private), "-pubout", "-out", str(self._public)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.lock_manager = LockManager(locks_dir=tmp_path / "locks")
        self._status = "active"

    def verify_journal_trust(self) -> dict:
        return {}

    def active_private_key_path(self, domain: str) -> Path:
        return self._private

    def public_key_for_key_id(self, domain: str, key_id: str) -> Path:
        if key_id != self.key_id:
            from wpgovern.errors import IntegrityError
            raise IntegrityError(f"unknown key_id {key_id!r}")
        return self._public

    def key_status(self, domain: str, key_id: str) -> str:
        return self._status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_target(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hash_file_bytes(path)


def _make_intent_writes(
    tmp_path: Path,
    target_relpaths: list[str],
    *,
    first_write_indices: tuple[int, ...] = (),
) -> list[IntentWrite]:
    writes = []
    for i, rel in enumerate(target_relpaths):
        target = tmp_path / "targets" / rel
        staged = tmp_path / "state" / ".transactions" / "txn-fixture" / f"{i:04d}-{rel}"
        staged.parent.mkdir(parents=True, exist_ok=True)
        new_content = f"new-{rel}".encode()
        staged.write_bytes(new_content)
        new_hash = hash_file_bytes(staged)
        if i in first_write_indices:
            old_hash = None
        else:
            old_content = f"old-{rel}".encode()
            old_hash = _write_target(target, old_content)
        writes.append(IntentWrite(
            target=str(target),
            staged=str(staged),
            old_content_hash=old_hash,
            new_content_hash=new_hash,
            mode=0o600,
        ))
    return writes


# ---------------------------------------------------------------------------
# Intent record I/O
# ---------------------------------------------------------------------------


def test_journal_writes_intent_with_all_required_fields(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json", "b.json"])
    record = IntentRecord(
        txn_id="txn-001",
        started_at="2026-01-01T12:00:00Z",
        service="BaselineService.activate",
        actor_id="alice",
        writes=writes,
    )
    writer.write_intent(record)

    intent_path = tmp_path / "state" / ".journal" / "txn-001.intent"
    assert intent_path.exists()
    raw = json.loads(intent_path.read_text())
    assert raw["schema_version"] == JOURNAL_SCHEMA_VERSION
    assert raw["txn_id"] == "txn-001"
    assert raw["service"] == "BaselineService.activate"
    assert raw["actor_id"] == "alice"
    assert len(raw["writes"]) == 2
    assert all("old_content_hash" in w and "new_content_hash" in w for w in raw["writes"])
    assert "intent_integrity_hash" in raw


def test_intent_integrity_hash_is_recomputable_from_written_record(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json"])
    record = IntentRecord(
        txn_id="txn-hash",
        started_at="2026-01-01T12:00:00Z",
        service="S.m",
        actor_id="alice",
        writes=writes,
    )
    writer.write_intent(record)

    reloaded = read_intent_record(tmp_path / "state" / ".journal" / "txn-hash.intent")
    recomputed = compute_intent_integrity_hash(reloaded)
    assert recomputed == reloaded.intent_integrity_hash


def test_intent_integrity_hash_changes_when_txn_id_changes(tmp_path: Path) -> None:
    writes = _make_intent_writes(tmp_path, ["a.json"])
    r1 = IntentRecord(txn_id="txn-A", started_at="2026-01-01T12:00:00Z",
                      service="S.m", actor_id="alice", writes=writes)
    r2 = IntentRecord(txn_id="txn-B", started_at="2026-01-01T12:00:00Z",
                      service="S.m", actor_id="alice", writes=writes)
    assert compute_intent_integrity_hash(r1) != compute_intent_integrity_hash(r2)


def test_write_intent_rejects_preset_hash_mismatch(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json"])
    record = IntentRecord(
        txn_id="txn-bad-hash",
        started_at="2026-01-01T12:00:00Z",
        service="S.m",
        actor_id=None,
        writes=writes,
    )
    record.intent_integrity_hash = "a" * 64  # wrong hash
    with pytest.raises(JournalError, match="does not match"):
        writer.write_intent(record)


# ---------------------------------------------------------------------------
# Backup store
# ---------------------------------------------------------------------------


def test_snapshot_writes_backup_for_each_existing_target(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json", "b.json"])
    writer.snapshot_old_targets(writes, "txn-snap")

    backup_dir = tmp_path / "state" / ".journal" / "backups" / "txn-snap"
    assert backup_dir.exists()
    for w in writes:
        assert w.old_content_hash is not None
        backup_path = backup_dir / w.old_content_hash
        assert backup_path.exists()
        assert hash_file_bytes(backup_path) == w.old_content_hash


def test_snapshot_skips_first_write_targets(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json", "b.json"], first_write_indices=(0,))
    writer.snapshot_old_targets(writes, "txn-fw")

    backup_dir = tmp_path / "state" / ".journal" / "backups" / "txn-fw"
    assert backup_dir.exists()
    backup_files = list(backup_dir.iterdir())
    assert len(backup_files) == 1  # only b.json has a backup


def test_snapshot_raises_when_target_disappears(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json"])
    Path(writes[0].target).unlink()
    with pytest.raises(JournalError, match="missing despite recorded"):
        writer.snapshot_old_targets(writes, "txn-gone")


def test_snapshot_fsyncs_backup_files_and_directory(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json", "b.json"])

    fsync_count = {"n": 0}
    real_fsync = os.fsync

    def counting_fsync(fd: int) -> None:
        fsync_count["n"] += 1
        real_fsync(fd)

    with patch("wpgovern.utils.journal.os.fsync", side_effect=counting_fsync):
        writer.snapshot_old_targets(writes, "txn-fsync")

    # Lower bound: 2 backup-file fsyncs + 1 per-txn dir fsync = 3
    assert fsync_count["n"] >= 3


# ---------------------------------------------------------------------------
# Complete record
# ---------------------------------------------------------------------------


def test_complete_record_written_with_schema_version_and_txn_id(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writer.write_complete("txn-done")

    path = tmp_path / "state" / ".journal" / "txn-done.complete"
    assert path.exists()
    raw = json.loads(path.read_text())
    assert raw["schema_version"] == JOURNAL_SCHEMA_VERSION
    assert raw["txn_id"] == "txn-done"
    assert "completed_at" in raw


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def test_cleanup_removes_intent_complete_and_backups(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json"])
    record = IntentRecord(
        txn_id="txn-clean", started_at="2026-01-01T12:00:00Z",
        service="S.m", actor_id=None, writes=writes,
    )
    writer.snapshot_old_targets(writes, "txn-clean")
    writer.write_intent(record)
    writer.write_complete("txn-clean")

    journal_dir = tmp_path / "state" / ".journal"
    writer.cleanup_completed("txn-clean")
    assert not (journal_dir / "txn-clean.intent").exists()
    assert not (journal_dir / "txn-clean.complete").exists()
    assert not (journal_dir / "backups" / "txn-clean").exists()


# ---------------------------------------------------------------------------
# File permissions
# ---------------------------------------------------------------------------


def test_intent_file_is_mode_0o600(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json"])
    record = IntentRecord(
        txn_id="txn-mode", started_at="2026-01-01T12:00:00Z",
        service="S.m", actor_id=None, writes=writes,
    )
    intent_path = writer.write_intent(record)
    assert stat.S_IMODE(intent_path.stat().st_mode) == 0o600


def test_journal_directory_is_mode_0o700(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writer.ensure_dirs()
    journal_dir = tmp_path / "state" / ".journal"
    assert stat.S_IMODE(journal_dir.stat().st_mode) == 0o700


# ---------------------------------------------------------------------------
# Round-trip read
# ---------------------------------------------------------------------------


def test_read_intent_record_round_trips_all_fields(tmp_path: Path) -> None:
    writer = JournalWriter(tmp_path)
    writes = _make_intent_writes(tmp_path, ["a.json"])
    record = IntentRecord(
        txn_id="txn-rt", started_at="2026-01-01T12:00:00Z",
        service="S.activate", actor_id="bob", writes=writes,
    )
    writer.write_intent(record)

    reloaded = read_intent_record(tmp_path / "state" / ".journal" / "txn-rt.intent")
    assert reloaded.txn_id == "txn-rt"
    assert reloaded.service == "S.activate"
    assert reloaded.actor_id == "bob"
    assert reloaded.schema_version == JOURNAL_SCHEMA_VERSION
    assert len(reloaded.writes) == 1


def test_schema_version_1_raises_journal_schema_error(tmp_path: Path) -> None:
    """v1 records (schema_version=1) must raise JournalSchemaError.

    β-3: Previously, v1 records silently defaulted to the current version,
    causing confusing 'signature mismatch' errors downstream. The new contract
    explicitly rejects unsupported schema versions with a clear error message.
    """
    from wpgovern.errors import JournalSchemaError
    path = tmp_path / "state" / ".journal" / "txn-v1.intent"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "txn_id": "txn-v1",
        "started_at": "2026-05-08T12:00:00Z",
        "service": "S.m",
        "actor_id": None,
        "writes": [],
        "schema_version": 1,
        "intent_integrity_hash": "",
        "intent_signature": "",
        "intent_signature_key_id": "",
    }
    path.write_text(json.dumps(payload) + "\n")
    with pytest.raises(JournalSchemaError, match="schema_version"):
        read_intent_record(path)


# ---------------------------------------------------------------------------
# AtomicTransaction integration
# ---------------------------------------------------------------------------


def test_atomic_transaction_writes_journal_when_service_label_provided(
    tmp_path: Path,
) -> None:
    trust = _FakeTrustService(tmp_path / "trust")
    staging = tmp_path / "state" / ".transactions"
    target = tmp_path / "targets" / "a.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    with AtomicTransaction(
        staging,
        service_label="TestService.activate",
        actor_id="alice",
        journal_root=tmp_path,
        trust_service=trust,
    ) as txn:
        txn.stage_text(target, "new content\n")
        txn.commit()

    assert target.read_text() == "new content\n"
    journal_dir = tmp_path / "state" / ".journal"
    assert journal_dir.exists()
    assert list(journal_dir.glob("*.intent")) == []
    assert list(journal_dir.glob("*.complete")) == []


def test_atomic_transaction_no_journal_when_service_label_absent(tmp_path: Path) -> None:
    staging = tmp_path / "state" / ".transactions"
    target = tmp_path / "targets" / "a.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    with AtomicTransaction(staging) as txn:
        txn.stage_text(target, "new content\n")
        txn.commit()

    assert target.read_text() == "new content\n"
    journal_dir = tmp_path / "state" / ".journal"
    if journal_dir.exists():
        assert list(journal_dir.iterdir()) == []


def test_atomic_transaction_intent_survives_partial_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kill point 2: second target replace fails; intent + backups survive."""
    trust = _FakeTrustService(tmp_path / "trust")
    staging = tmp_path / "state" / ".transactions"
    targets_dir = tmp_path / "targets"
    target_a = targets_dir / "a.json"
    target_b = targets_dir / "b.json"
    targets_dir.mkdir(parents=True, exist_ok=True)
    target_a.write_text("old-a")
    target_b.write_text("old-b")

    real_replace = os.replace
    replace_count = {"n": 0}

    def flaky_replace(src: str, dst: str) -> None:
        if str(Path(dst)).startswith(str(targets_dir)):
            replace_count["n"] += 1
            if replace_count["n"] >= 2:
                raise OSError("simulated mid-commit failure")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(TransactionError, match="commit failed"):
        with AtomicTransaction(
            staging,
            service_label="TestService.activate",
            actor_id="alice",
            journal_root=tmp_path,
            trust_service=trust,
        ) as txn:
            txn.stage_text(target_a, "new-a")
            txn.stage_text(target_b, "new-b")
            txn.commit()

    intents = list_intent_records(tmp_path / "state" / ".journal")
    completes = list_complete_records(tmp_path / "state" / ".journal")
    assert len(intents) == 1, "intent must survive kill point 2"
    assert len(completes) == 0
    backups_root = tmp_path / "state" / ".journal" / "backups"
    assert backups_root.exists()
    assert target_a.read_text() == "new-a"
    assert target_b.read_text() == "old-b"
