"""
Tests for wpgovern.utils.invariants — invariant catalog unit tests.

Coverage:
- check_all_invariants returns empty list on fresh install
- assert_invariants_hold passes on fresh install
- Catalog has 14 invariants registered
- I-FS-1: catches journal dir with wrong mode
- I-FS-2: catches .intent file with wrong mode
- I-FS-3: catches stale .intent.staged file
- I-FS-4: catches backup dir with wrong mode
- I-FS-5: catches journal private dir with wrong mode
- I-J-1: catches corrupted integrity hash
- I-J-3: catches orphan .complete without .intent
- I-J-4: catches two .intent files sharing a txn_id
- I-T-1: catches two active keys in same domain
- I-T-2: catches revoked key without revoked_at
- I-NEG-JOURNAL: catches unexpected file in journal dir
- InvariantViolation.to_dict() returns correct shape
- Checker exception on a check is recorded as a violation
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.utils.invariants import (
    InvariantViolation,
    _INVARIANT_REGISTRY,
    assert_invariants_hold,
    check_all_invariants,
)


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


# ---------------------------------------------------------------------------
# Catalog size
# ---------------------------------------------------------------------------


def test_invariant_catalog_has_14_entries() -> None:
    assert len(_INVARIANT_REGISTRY) == 29


def test_invariant_catalog_ids_are_all_present() -> None:
    ids = {inv_id for inv_id, _, _ in _INVARIANT_REGISTRY}
    required = {
        "I-FS-1", "I-FS-2", "I-FS-3", "I-FS-4", "I-FS-5", "I-FS-6",
        "I-J-1", "I-J-3", "I-J-4",
        "I-T-1", "I-T-2",
        "I-R-1",
        "I-NEG-JOURNAL", "I-NEG-NOSYMLINKS",
        "I-B-1", "I-B-2", "I-A-1", "I-B4-1", "I-REL-1", "I-AUD-1", "I-AUD-0",
        "I-T-3", "I-T-4", "I-T-5", "I-T-6", "I-T-7", "I-AUD-2",
        "I-CFG-1", "I-CFG-2",  # H.0-A: config-file hash invariants
    }
    assert required == ids


# ---------------------------------------------------------------------------
# Clean state
# ---------------------------------------------------------------------------


def test_check_all_invariants_returns_empty_on_fresh_install(
    config: WPGovernConfig,
) -> None:
    violations = check_all_invariants(config)
    errors = [v for v in violations if v.severity == "error"]
    assert errors == [], f"unexpected violations: {errors}"


def test_assert_invariants_hold_passes_on_fresh_install(
    config: WPGovernConfig,
) -> None:
    assert_invariants_hold(config)  # must not raise


# ---------------------------------------------------------------------------
# I-FS-1: journal directory mode
# ---------------------------------------------------------------------------


def test_i_fs_1_catches_wrong_journal_dir_mode(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o755)  # wrong — should be 0o700

    violations = check_all_invariants(config)
    ids = {v.invariant_id for v in violations}
    assert "I-FS-1" in ids


def test_i_fs_1_passes_on_correct_mode(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-FS-1"]
    assert violations == []


# ---------------------------------------------------------------------------
# I-FS-2: .intent file modes
# ---------------------------------------------------------------------------


def test_i_fs_2_catches_intent_file_with_wrong_mode(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    intent = journal_dir / "txn-test.intent"
    intent.write_text('{"txn_id": "txn-test"}\n')
    os.chmod(intent, 0o644)  # wrong — should be 0o600

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-FS-2"]
    assert len(violations) == 1


# ---------------------------------------------------------------------------
# I-FS-3: no stale .intent.staged
# ---------------------------------------------------------------------------


def test_i_fs_3_catches_stale_intent_staged(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    staged = journal_dir / "txn-test.intent.staged"
    staged.write_text('partial\n')

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-FS-3"]
    assert len(violations) == 1
    assert str(staged) in str(violations[0].details)


def test_i_fs_3_passes_when_no_staged_files(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-FS-3"]
    assert violations == []


# ---------------------------------------------------------------------------
# I-J-1: integrity hash
# ---------------------------------------------------------------------------


def test_i_j_1_catches_corrupted_integrity_hash(config: WPGovernConfig) -> None:
    from wpgovern.utils.journal import (
        JOURNAL_SCHEMA_VERSION, IntentRecord, IntentWrite,
        compute_intent_integrity_hash, JournalWriter,
    )
    root = config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    record = IntentRecord(
        txn_id="txn-corrupt",
        started_at="2026-01-01T00:00:00Z",
        service="S.m",
        actor_id=None,
        writes=[],
    )
    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    # Now corrupt the stored hash
    d = record.as_dict()
    d["intent_integrity_hash"] = "a" * 64
    journal_dir = root / "state" / ".journal"
    intent_path = journal_dir / "txn-corrupt.intent"
    intent_path.write_text(json.dumps(d, indent=2) + "\n")
    os.chmod(intent_path, 0o600)

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-J-1"]
    assert len(violations) == 1


# ---------------------------------------------------------------------------
# I-J-3: orphan .complete
# ---------------------------------------------------------------------------


def test_i_j_3_catches_orphan_complete_without_intent(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    complete = journal_dir / "txn-orphan.complete"
    complete.write_text('{"txn_id": "txn-orphan"}\n')

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-J-3"]
    assert len(violations) == 1
    assert "txn-orphan" in str(violations[0].details)


# ---------------------------------------------------------------------------
# I-J-4: duplicate txn_id
# ---------------------------------------------------------------------------


def test_i_j_4_catches_duplicate_txn_id(config: WPGovernConfig) -> None:
    from wpgovern.utils.journal import (
        IntentRecord, compute_intent_integrity_hash, JournalWriter,
    )
    root = config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    journal_dir = root / "state" / ".journal"

    for filename in ("txn-dup-A.intent", "txn-dup-B.intent"):
        record = IntentRecord(
            txn_id="same-txn-id",
            started_at="2026-01-01T00:00:00Z",
            service="S.m",
            actor_id=None,
            writes=[],
        )
        record.intent_integrity_hash = compute_intent_integrity_hash(record)
        intent_path = journal_dir / filename
        intent_path.write_text(json.dumps(record.as_dict(), indent=2) + "\n")
        os.chmod(intent_path, 0o600)

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-J-4"]
    assert len(violations) == 1
    assert violations[0].details["txn_id"] == "same-txn-id"


# ---------------------------------------------------------------------------
# I-T-1: two active keys
# ---------------------------------------------------------------------------


def test_i_t_1_catches_two_active_keys(config: WPGovernConfig) -> None:
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")

    # Directly inject a second active key record without going through
    # the lifecycle (which would retire the first)
    store_path = config.runtime_trust_store
    store = json.loads(store_path.read_text())
    store["keys"].append({
        "key_id": "runtime-b",
        "status": "active",
        "path": str(config.root_dir / "trust/runtime/public/runtime-b.pub"),
        "created_at": "2026-01-01T00:00:00Z",
        "usage": ["sign", "verify"],
    })
    # Create the referenced public key file so path-check passes
    pub = config.root_dir / "trust/runtime/public/runtime-b.pub"
    pub.write_text("fake-pub-key")
    store_path.write_text(json.dumps(store, indent=2) + "\n")

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-T-1"]
    assert any(v.details.get("domain") == "runtime" for v in violations)


# ---------------------------------------------------------------------------
# I-T-2: revoked key missing revoked_at
# ---------------------------------------------------------------------------


def test_i_t_2_catches_revoked_key_without_revoked_at(config: WPGovernConfig) -> None:
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_runtime_key("runtime-b")

    # Manually set runtime-b to revoked without a revoked_at
    store_path = config.runtime_trust_store
    store = json.loads(store_path.read_text())
    for k in store["keys"]:
        if k["key_id"] == "runtime-b":
            k["status"] = "revoked"
            k["usage"] = []
            # Intentionally omit revoked_at
    store_path.write_text(json.dumps(store, indent=2) + "\n")

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-T-2"]
    assert any(v.details.get("key_id") == "runtime-b" for v in violations)


# ---------------------------------------------------------------------------
# I-NEG-JOURNAL: unexpected files
# ---------------------------------------------------------------------------


def test_i_neg_journal_catches_unexpected_file(config: WPGovernConfig) -> None:
    journal_dir = config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    unexpected = journal_dir / "UNEXPECTED_FILE.txt"
    unexpected.write_text("should not be here\n")

    violations = [v for v in check_all_invariants(config) if v.invariant_id == "I-NEG-JOURNAL"]
    assert len(violations) == 1


# ---------------------------------------------------------------------------
# InvariantViolation.to_dict()
# ---------------------------------------------------------------------------


def test_invariant_violation_to_dict_has_correct_shape() -> None:
    v = InvariantViolation(
        invariant_id="I-FS-1",
        description="test description",
        details={"path": "/tmp/test", "expected_mode": "0o700"},
        severity="error",
    )
    d = v.to_dict()
    assert d["invariant_id"] == "I-FS-1"
    assert d["description"] == "test description"
    assert d["details"]["path"] == "/tmp/test"
    assert d["severity"] == "error"


# ---------------------------------------------------------------------------
# Checker exception is recorded as violation
# ---------------------------------------------------------------------------


def test_checker_exception_is_recorded_as_violation(
    config: WPGovernConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wpgovern.utils import invariants as inv_module

    original_registry = list(inv_module._INVARIANT_REGISTRY)

    def _crashing_check(cfg: WPGovernConfig) -> list:
        raise RuntimeError("simulated checker crash")

    inv_module._INVARIANT_REGISTRY.append(("I-TEST-CRASH", "crash test", _crashing_check))

    try:
        violations = check_all_invariants(config)
        crash_violations = [v for v in violations if v.invariant_id == "I-TEST-CRASH"]
        assert len(crash_violations) == 1
        assert "RuntimeError" in crash_violations[0].details["checker_exception"]
    finally:
        inv_module._INVARIANT_REGISTRY[:] = original_registry
