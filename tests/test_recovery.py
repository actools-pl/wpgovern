"""
Tests for wpgovern.utils.recovery — RecoveryService, outcome paths,
RecoveryRefusedError, orphan sweeps, audit emit fallback.

Coverage:
- No-op when journal directory absent
- No-op when journal directory empty
- recovery.abandoned (kill point 1: nothing replaced)
- recovery.completed (complete record present and valid)
- recovery.completed (kill point 3: all replaced, no complete record)
- recovery.rolled_back (kill point 2: partial commit)
- recovery.refused (divergent target)
- recovery.refused (missing backup)
- recovery.refused (unknown schema_version)
- recovery.refused (tampered intent / signature invalid)
- recover() raises RecoveryRefusedError on any refusal
- recover_with_diagnostics() returns result without raising
- RecoveryRefusedError.result carries full result
- Orphan backup directory sweep
- Orphan complete file sweep
- Audit emit failure fallback writes to disk
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.utils.journal import (
    JOURNAL_SCHEMA_VERSION,
    CompleteRecord,
    IntentRecord,
    IntentWrite,
    JournalWriter,
    compute_intent_integrity_hash,
    hash_file_bytes,
    sign_complete_record,
    sign_intent_record,
)
from wpgovern.utils.locking import LockManager
from wpgovern.utils.recovery import (
    RecoveryRefusedError,
    RecoveryService,
)


# ---------------------------------------------------------------------------
# Minimal trust service for recovery tests
# ---------------------------------------------------------------------------


class _FakeTrustService:
    def __init__(self, tmp_path: Path, key_id: str = "journal-key") -> None:
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
# Fixtures and helpers
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
def trust(tmp_path: Path) -> _FakeTrustService:
    return _FakeTrustService(tmp_path / "trust-keys")


def _make_signed_intent(
    root: Path,
    trust: _FakeTrustService,
    txn_id: str = "txn-test",
    *,
    target_specs: list[tuple[str, bytes | None, bytes]] | None = None,
    landed: tuple[bool, ...] = (),
    write_complete: bool = False,
    schema_version: int = JOURNAL_SCHEMA_VERSION,
) -> list[Path]:
    """Create signed intent state on disk for recovery testing.

    Returns list of target Paths in order.
    """
    if target_specs is None:
        target_specs = [("a.json", b"old-a", b"new-a"), ("b.json", b"old-b", b"new-b")]
    if not landed:
        landed = (False,) * len(target_specs)

    journal_dir = root / "state" / ".journal"
    backups_dir = journal_dir / "backups" / txn_id
    journal_dir.mkdir(parents=True, exist_ok=True)
    backups_dir.mkdir(parents=True, exist_ok=True)

    target_paths: list[Path] = []
    writes: list[IntentWrite] = []

    for i, (relpath, old_bytes, new_bytes) in enumerate(target_specs):
        target_path = root / "targets" / relpath
        target_paths.append(target_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if old_bytes is None:
            old_hash = None
        else:
            old_hash = hashlib.sha256(old_bytes).hexdigest()
            backup_path = backups_dir / old_hash
            backup_path.write_bytes(old_bytes)

        new_hash = hashlib.sha256(new_bytes).hexdigest()

        if landed[i]:
            target_path.write_bytes(new_bytes)
        elif old_bytes is not None:
            target_path.write_bytes(old_bytes)

        writes.append(IntentWrite(
            target=str(target_path),
            staged=str(root / "state" / ".transactions" / txn_id / f"{i:04d}-{relpath}"),
            old_content_hash=old_hash,
            new_content_hash=new_hash,
            mode=0o600,
        ))

    record = IntentRecord(
        txn_id=txn_id,
        started_at="2026-01-01T12:00:00Z",
        service="TestService.activate",
        actor_id="alice",
        writes=writes,
        schema_version=schema_version,
    )

    if schema_version == JOURNAL_SCHEMA_VERSION:
        sign_intent_record(record, trust)

    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    intent_path = journal_dir / f"{txn_id}.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2, sort_keys=True) + "\n")
    os.chmod(intent_path, 0o600)

    if write_complete:
        complete = CompleteRecord(txn_id=txn_id, completed_at="2026-05-08T12:00:01Z")
        sign_complete_record(complete, trust)
        complete_path = journal_dir / f"{txn_id}.complete"
        complete_path.write_text(json.dumps(complete.as_dict(), indent=2, sort_keys=True) + "\n")

    return target_paths


def _make_recovery_service(config: WPGovernConfig, trust: _FakeTrustService) -> RecoveryService:
    svc = RecoveryService(config=config)
    svc._trust = trust  # inject fake trust service
    return svc


# ---------------------------------------------------------------------------
# No-op paths
# ---------------------------------------------------------------------------


def test_recovery_noop_when_journal_dir_absent(config: WPGovernConfig, trust: _FakeTrustService) -> None:
    svc = _make_recovery_service(config, trust)
    result = svc.recover()
    assert result.outcomes == []
    assert result.any_refused is False


def test_recovery_noop_when_journal_dir_empty(config: WPGovernConfig, trust: _FakeTrustService) -> None:
    root = Path(config.root_dir)
    (root / "state" / ".journal").mkdir(parents=True, exist_ok=True)
    svc = _make_recovery_service(config, trust)
    result = svc.recover()
    assert result.outcomes == []


# ---------------------------------------------------------------------------
# Happy-path outcomes
# ---------------------------------------------------------------------------


def test_recovery_abandoned_when_nothing_replaced(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """Kill point 1: intent written, no target replaced yet → abandoned."""
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, landed=(False, False))

    svc = _make_recovery_service(config, trust)
    result = svc.recover()

    assert len(result.outcomes) == 1
    assert result.outcomes[0].event_type == "recovery.abandoned"
    assert not result.any_refused


def test_recovery_completed_when_complete_record_present(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """Complete record present and valid → recovery.completed, artefacts cleaned."""
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, landed=(True, True), write_complete=True)

    svc = _make_recovery_service(config, trust)
    result = svc.recover()

    assert len(result.outcomes) == 1
    assert result.outcomes[0].event_type == "recovery.completed"
    journal_dir = root / "state" / ".journal"
    assert not list(journal_dir.glob("*.intent"))
    assert not list(journal_dir.glob("*.complete"))


def test_recovery_completed_when_all_replaced_but_no_complete_record(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """Kill point 3: all targets replaced, no complete record → recovery.completed."""
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, landed=(True, True), write_complete=False)

    svc = _make_recovery_service(config, trust)
    result = svc.recover()

    assert result.outcomes[0].event_type == "recovery.completed"


def test_recovery_rolled_back_on_partial_commit(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """Kill point 2: first target replaced, second still old → rolled_back."""
    root = Path(config.root_dir)
    targets = _make_signed_intent(root, trust, landed=(True, False))

    svc = _make_recovery_service(config, trust)
    result = svc.recover()

    assert result.outcomes[0].event_type == "recovery.rolled_back"
    # First target must be restored to old-a
    assert targets[0].read_bytes() == b"old-a"
    assert targets[1].read_bytes() == b"old-b"


# ---------------------------------------------------------------------------
# Refusal paths
# ---------------------------------------------------------------------------


def test_recovery_refused_on_divergent_target(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """Target content matches neither old nor new hash → divergent → refused."""
    root = Path(config.root_dir)
    targets = _make_signed_intent(root, trust, landed=(True, False))
    # Tamper the first target to a value matching neither hash
    targets[0].write_bytes(b"divergent-content-xyz")

    svc = _make_recovery_service(config, trust)
    result = svc.recover_with_diagnostics()

    assert result.outcomes[0].event_type == "recovery.refused"
    assert "diverged" in result.outcomes[0].reason


def test_recovery_refused_on_unknown_schema_version(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, schema_version=99)

    svc = _make_recovery_service(config, trust)
    result = svc.recover_with_diagnostics()

    assert result.outcomes[0].event_type == "recovery.refused"
    assert "schema_version" in result.outcomes[0].reason


def test_recovery_refused_on_tampered_intent(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """Tampering the intent after signing → signature invalid → refused."""
    root = Path(config.root_dir)
    _make_signed_intent(root, trust)
    intent_path = root / "state" / ".journal" / "txn-test.intent"
    raw = json.loads(intent_path.read_text())
    raw["actor_id"] = "mallory"  # tamper the payload
    intent_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")

    svc = _make_recovery_service(config, trust)
    result = svc.recover_with_diagnostics()

    assert result.outcomes[0].event_type == "recovery.refused"


def test_recovery_refused_on_v1_schema(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    """schema_version=1 records are refused during normal recovery."""
    root = Path(config.root_dir)
    journal_dir = root / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)

    record = IntentRecord(
        txn_id="txn-v1",
        started_at="2026-01-01T12:00:00Z",
        service="S.m",
        actor_id=None,
        writes=[],
        schema_version=1,
    )
    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    intent_path = journal_dir / "txn-v1.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2, sort_keys=True) + "\n")

    svc = _make_recovery_service(config, trust)
    result = svc.recover_with_diagnostics()

    assert result.outcomes[0].event_type == "recovery.refused"
    assert "schema_version" in result.outcomes[0].reason


# ---------------------------------------------------------------------------
# recover() raises RecoveryRefusedError
# ---------------------------------------------------------------------------


def test_recover_raises_recovery_refused_error_on_any_refusal(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, schema_version=99)

    svc = _make_recovery_service(config, trust)
    with pytest.raises(RecoveryRefusedError) as exc_info:
        svc.recover()

    assert exc_info.value.result.refused_count == 1


def test_recovery_refused_error_carries_full_result(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, schema_version=99)

    svc = _make_recovery_service(config, trust)
    try:
        svc.recover()
    except RecoveryRefusedError as exc:
        assert exc.result is not None
        assert exc.result.refused_count == 1
        assert exc.result.outcomes[0].refused is True


def test_recover_with_diagnostics_never_raises_on_refusal(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, schema_version=99)

    svc = _make_recovery_service(config, trust)
    result = svc.recover_with_diagnostics()  # must not raise

    assert result.any_refused is True


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------


def test_orphan_backup_dir_sweep_removes_dirs_without_intent(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    root = Path(config.root_dir)
    backups_dir = root / "state" / ".journal" / "backups"
    orphan = backups_dir / "txn-orphan"
    orphan.mkdir(parents=True, exist_ok=True)
    (orphan / "somefile").write_bytes(b"data")

    svc = _make_recovery_service(config, trust)
    result = svc.recover()

    assert result.orphan_backup_dirs_swept == 1
    assert not orphan.exists()


def test_orphan_complete_file_sweep_removes_files_without_intent(
    config: WPGovernConfig, trust: _FakeTrustService
) -> None:
    root = Path(config.root_dir)
    journal_dir = root / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    orphan_complete = journal_dir / "txn-orphan-complete.complete"
    orphan_complete.write_text('{"txn_id":"txn-orphan-complete"}\n')

    svc = _make_recovery_service(config, trust)
    result = svc.recover()

    assert result.orphan_complete_files_swept == 1
    assert not orphan_complete.exists()


# ---------------------------------------------------------------------------
# Audit emit failure fallback
# ---------------------------------------------------------------------------


def test_audit_emit_failure_writes_fallback_file(
    config: WPGovernConfig, trust: _FakeTrustService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When AuditLogger.emit raises, the payload is written to the fallback dir."""
    root = Path(config.root_dir)
    _make_signed_intent(root, trust, landed=(False, False))

    def fail_emit(*args, **kwargs):
        raise RuntimeError("simulated audit failure")

    svc = _make_recovery_service(config, trust)
    audit_logger = AuditLogger(config=config)
    monkeypatch.setattr(audit_logger, "emit", fail_emit)
    svc._audit_logger = audit_logger

    result = svc.recover_with_diagnostics()

    assert result.audit_emit_failures > 0
    fallback_dir = root / "state" / ".journal" / "audit-emit-failures"
    assert fallback_dir.exists()
    assert list(fallback_dir.glob("*.json"))
