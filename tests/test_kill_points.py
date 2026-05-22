"""
Kill-point harness and Hypothesis atomicity property tests.

The central B8 property: after ANY kill point during commit, followed
by recovery, the filesystem must be in a CONSISTENT STATE. Every
target is either ALL at old values (rolled back) or ALL at new values
(completed). No target may be in a hybrid state.

Kill positions:
  KP0  Before any I/O starts
  KP1  During journal intent write (inside os.replace of .intent.staged)
  KP2  After intent write, before first target replace
  KP3  Mid-target-replace (after N targets placed, before N+1..M)
  KP4  After all targets replaced, before complete record written

Additional coverage:
  - Hypothesis: kill at any position × any transaction shape
  - Recovery refuses unsigned v2 intent
  - Recovery refuses corrupted integrity hash
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.utils.invariants import assert_invariants_hold
from wpgovern.utils.journal import JournalWriter
from wpgovern.utils.recovery import RecoveryRefusedError, RecoveryService
from wpgovern.utils.transaction import AtomicTransaction, TransactionError


# ---------------------------------------------------------------------------
# Kill-point injector
# ---------------------------------------------------------------------------


class _KillPointInjector:
    """Raises OSError(EINTR) at the trigger_at-th call to the wrapped fn.

    EINTR is used because it is not in the B4 classification table, so
    it propagates as a plain OSError and triggers the AtomicTransaction
    abort path — accurately modelling a process kill during a syscall.
    """

    def __init__(self, trigger_at: int, original_fn) -> None:
        self.trigger_at = trigger_at
        self.original_fn = original_fn
        self.call_count = 0

    def __call__(self, *args, **kwargs):
        self.call_count += 1
        if self.call_count == self.trigger_at + 1:
            raise OSError(4, "Interrupted system call (simulated kill)")
        return self.original_fn(*args, **kwargs)


@contextmanager
def kill_at_replace(trigger_at: int):
    """Inject a kill at the trigger_at-th os.replace call."""
    injector = _KillPointInjector(trigger_at, os.replace)
    with mock.patch("os.replace", side_effect=injector):
        yield injector


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def kp_config(tmp_path: Path) -> WPGovernConfig:
    root = tmp_path / "opt" / "wpgovern"
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


def _setup_transaction(
    config: WPGovernConfig,
    names: list[str],
    old_contents: dict[str, str],
    new_contents: dict[str, str],
) -> tuple[AtomicTransaction, Path]:
    """Write old content to targets, stage new content. Returns uncommitted txn."""
    root = config.root_dir
    targets_dir = root / "targets"
    targets_dir.mkdir(parents=True, exist_ok=True)
    staging_root = root / "state" / ".transactions"
    staging_root.mkdir(parents=True, exist_ok=True)
    trust = TrustService(config=config)

    for name in names:
        (targets_dir / name).write_text(old_contents[name])

    txn = AtomicTransaction(
        staging_root,
        service_label="KillPointTest.commit",
        actor_id="test",
        journal_root=root,
        trust_service=trust,
    )
    txn.__enter__()
    for name in names:
        txn.stage_text(targets_dir / name, new_contents[name])
    return txn, targets_dir


def _assert_consistency(
    targets_dir: Path,
    names: list[str],
    old_contents: dict[str, str],
    new_contents: dict[str, str],
    label: str,
) -> None:
    """Assert every target is at either old or new content — no hybrid."""
    for name in names:
        path = targets_dir / name
        if not path.exists():
            continue
        actual = path.read_text()
        old = old_contents[name]
        new = new_contents[name]
        assert actual in (old, new), (
            f"[{label}] Target '{name}' is in HYBRID STATE: "
            f"not old ({old!r}) and not new ({new!r}). Actual: {actual!r}"
        )


# ---------------------------------------------------------------------------
# Deterministic kill-point tests
# ---------------------------------------------------------------------------


def test_kp1_kill_during_intent_write_leaves_targets_old(
    kp_config: WPGovernConfig,
) -> None:
    """KP1: kill during intent staged→final rename. No target touched."""
    names = ["a.json"]
    old = {"a.json": '{"v": 1}'}
    new = {"a.json": '{"v": 2}'}
    txn, targets_dir = _setup_transaction(kp_config, names, old, new)

    with kill_at_replace(0):
        try:
            txn.commit()
        except (TransactionError, OSError):
            pass
    txn.__exit__(None, None, None)

    for name in names:
        assert (targets_dir / name).read_text() == old[name], \
            "KP1: targets must be unchanged"

    RecoveryService(kp_config).recover()
    _assert_consistency(targets_dir, names, old, new, "KP1-post-recovery")
    assert_invariants_hold(kp_config)


def test_kp2_kill_before_first_target_replace_leaves_targets_old(
    kp_config: WPGovernConfig,
) -> None:
    """KP2: intent written; kill before first target replace → abandoned."""
    names = ["a.json", "b.json"]
    old = {"a.json": '{"v": 1}', "b.json": '{"w": 1}'}
    new = {"a.json": '{"v": 2}', "b.json": '{"w": 2}'}
    txn, targets_dir = _setup_transaction(kp_config, names, old, new)

    with kill_at_replace(1):
        try:
            txn.commit()
        except (TransactionError, OSError):
            pass
    txn.__exit__(None, None, None)

    journal_dir = kp_config.root_dir / "state" / ".journal"
    assert len(list(journal_dir.glob("*.intent"))) == 1, "Intent must survive KP2"
    for name in names:
        assert (targets_dir / name).read_text() == old[name]

    RecoveryService(kp_config).recover()
    _assert_consistency(targets_dir, names, old, new, "KP2-post-recovery")
    assert_invariants_hold(kp_config)


def test_kp3_kill_mid_replace_rolls_back_to_old(
    kp_config: WPGovernConfig,
) -> None:
    """KP3: the critical case. Kill after first target replace → rolled back."""
    names = ["a.json", "b.json"]
    old = {"a.json": '{"v": 1}', "b.json": '{"w": 1}'}
    new = {"a.json": '{"v": 2}', "b.json": '{"w": 2}'}
    txn, targets_dir = _setup_transaction(kp_config, names, old, new)

    with kill_at_replace(2):  # intent(0), a-replace(1), KILL before b-replace(2)
        try:
            txn.commit()
        except (TransactionError, OSError):
            pass
    txn.__exit__(None, None, None)

    assert (targets_dir / "a.json").read_text() == new["a.json"], "KP3 setup: a at new"
    assert (targets_dir / "b.json").read_text() == old["b.json"], "KP3 setup: b at old"

    RecoveryService(kp_config).recover()

    assert (targets_dir / "a.json").read_text() == old["a.json"], \
        "KP3: a must be rolled back to old"
    assert (targets_dir / "b.json").read_text() == old["b.json"], \
        "KP3: b must remain at old"

    _assert_consistency(targets_dir, names, old, new, "KP3-post-recovery")
    assert_invariants_hold(kp_config)


def test_kp4_kill_after_all_replaces_before_complete_stays_new(
    kp_config: WPGovernConfig,
) -> None:
    """KP4: all targets replaced, no complete record → recovery completes it."""
    names = ["a.json"]
    old = {"a.json": '{"v": 1}'}
    new = {"a.json": '{"v": 2}'}
    txn, targets_dir = _setup_transaction(kp_config, names, old, new)

    with kill_at_replace(2):  # intent(0), a-replace(1), KILL at complete(2)
        try:
            txn.commit()
        except (TransactionError, OSError):
            pass
    txn.__exit__(None, None, None)

    assert (targets_dir / "a.json").read_text() == new["a.json"], "KP4 setup: a at new"

    RecoveryService(kp_config).recover()

    assert (targets_dir / "a.json").read_text() == new["a.json"], \
        "KP4: target must stay at new (already_replaced → completed)"
    assert_invariants_hold(kp_config)


# ---------------------------------------------------------------------------
# Hypothesis: kill at any position × any transaction shape
# ---------------------------------------------------------------------------


def _make_fresh_kp_config(tmp_path_factory) -> WPGovernConfig:
    root = tmp_path_factory.mktemp("kp")
    cfg = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    TrustService(config=cfg).generate_journal_key("journal-1")
    TrustService(config=cfg).activate_journal_key("journal-1")
    return cfg


@given(
    n_writes=st.integers(min_value=2, max_value=3),
    kill_position=st.integers(min_value=0, max_value=8),
    version_suffix=st.integers(min_value=1, max_value=99),
)
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_kill_at_any_position_atomicity_holds(
    tmp_path_factory, n_writes: int, kill_position: int, version_suffix: int,
) -> None:
    """For any transaction shape and kill position, after recovery the
    filesystem is consistent: every target is at old OR new — no hybrid."""
    config = _make_fresh_kp_config(tmp_path_factory)
    targets_dir = config.root_dir / "targets"
    staging_root = config.root_dir / "state" / ".transactions"
    targets_dir.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)
    trust = TrustService(config=config)

    names = [f"target-{i}.json" for i in range(n_writes)]
    old = {n: f'{{"v": {version_suffix}}}' for n in names}
    new = {n: f'{{"v": {version_suffix + 1}}}' for n in names}

    for name in names:
        (targets_dir / name).write_text(old[name])

    txn = AtomicTransaction(
        staging_root,
        service_label="KillTest.commit",
        actor_id="hypothesis",
        journal_root=config.root_dir,
        trust_service=trust,
    )
    txn.__enter__()
    for name in names:
        txn.stage_text(targets_dir / name, new[name])

    # Total os.replace calls: 1 (intent) + n_writes (targets) + 1 (complete).
    max_kill = n_writes + 1
    effective_kill = kill_position % (max_kill + 1)

    with kill_at_replace(effective_kill):
        try:
            txn.commit()
        except (TransactionError, OSError, Exception):
            pass

    txn.__exit__(None, None, None)

    try:
        RecoveryService(config).recover()
    except RecoveryRefusedError:
        pass  # Refused is not a consistency violation

    _assert_consistency(targets_dir, names, old, new, f"kill-{effective_kill}/{max_kill}")
    assert_invariants_hold(config)


# ---------------------------------------------------------------------------
# Recovery: unsigned and corrupted intents
# ---------------------------------------------------------------------------


def test_recovery_refuses_unsigned_v2_intent(kp_config: WPGovernConfig) -> None:
    """An unsigned v2 intent is refused at step 3 of the recovery sequence."""
    from wpgovern.utils.journal import (
        JOURNAL_SCHEMA_VERSION, IntentRecord, IntentWrite,
        compute_intent_integrity_hash,
    )
    root = kp_config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    journal_dir = root / "state" / ".journal"

    target = root / "targets" / "a.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"legit-bytes")

    record = IntentRecord(
        txn_id="txn-forged",
        started_at="2026-01-01T00:00:00Z",
        service="FakeService.activate",
        actor_id="attacker",
        writes=[IntentWrite(
            target=str(target),
            staged="(unused)",
            old_content_hash=hashlib.sha256(b"attacker-chosen").hexdigest(),
            new_content_hash=hashlib.sha256(b"legit-bytes").hexdigest(),
            mode=0o600,
        )],
        schema_version=JOURNAL_SCHEMA_VERSION,
    )
    record.intent_integrity_hash = compute_intent_integrity_hash(record)
    # No signature — unsigned intent
    intent_path = journal_dir / "txn-forged.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2, sort_keys=True) + "\n")
    intent_path.chmod(0o600)

    assert target.read_bytes() == b"legit-bytes"

    result = RecoveryService(kp_config).recover_with_diagnostics()
    assert result.outcomes[0].event_type == "recovery.refused"
    assert target.read_bytes() == b"legit-bytes"


def test_recovery_refuses_corrupted_integrity_hash(
    kp_config: WPGovernConfig,
) -> None:
    """After signature passes, a corrupted integrity hash is refused at step 4."""
    from wpgovern.utils.journal import (
        IntentRecord, sign_intent_record,
        compute_intent_integrity_hash, JournalWriter,
    )
    root = kp_config.root_dir
    writer = JournalWriter(root)
    writer.ensure_dirs()
    journal_dir = root / "state" / ".journal"
    trust = TrustService(config=kp_config)

    record = IntentRecord(
        txn_id="txn-badhash",
        started_at="2026-01-01T00:00:00Z",
        service="S.m",
        actor_id=None,
        writes=[],
    )
    sign_intent_record(record, trust)
    record.intent_integrity_hash = "b" * 64  # corrupt the hash after signing

    intent_path = journal_dir / "txn-badhash.intent"
    intent_path.write_text(json.dumps(record.as_dict(), indent=2, sort_keys=True) + "\n")
    intent_path.chmod(0o600)

    result = RecoveryService(kp_config).recover_with_diagnostics()
    assert result.outcomes[0].event_type == "recovery.refused"
    assert "hash" in result.outcomes[0].reason.lower()
