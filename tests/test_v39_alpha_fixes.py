"""
Regression tests for v39 Phase α fixes.

α-1 — Public key precondition in activate_key (mirrors private key check)
α-2 — Pre-commit checks use is_file(), not exists()
α-3 — validate_store enforces cryptographic keypair match
α-4 — Journaled commit failure invokes in-process recovery
α-5 — I-AUD-2 chain-tail invariant
α-6 — No reviewer-name leakage (covered by test_ci_guards.py)
"""

from __future__ import annotations

import errno
import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService, TrustError


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
# α-1 — Public key precondition refuses before mutation
# ---------------------------------------------------------------------------

def test_alpha1_missing_public_key_refused_before_mutation(env) -> None:
    """activate_key must refuse before any state mutation when public key is missing.

    Pre-fix: only the private key was checked. A missing public key was caught
    by validate_store() AFTER the transaction committed — too late to roll back.
    """
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-2.pub"
    pub.unlink()

    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    pre = json.loads(store_path.read_text())

    with pytest.raises(TrustError, match="public key"):
        trust.activate_runtime_key("runtime-2")

    post = json.loads(store_path.read_text())
    assert pre == post, "JSON must not be mutated when public key precondition fails"


# ---------------------------------------------------------------------------
# α-2 — Pre-commit checks use is_file() (directory at .pem path refused)
# ---------------------------------------------------------------------------

def test_alpha2_directory_at_pem_path_refused(env) -> None:
    """activate_key must refuse if .pem path is a directory.

    Pre-fix: .exists() returns True for directories, so a directory at the
    .pem path passed the check and activation would proceed with a broken symlink.
    """
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    pem = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem"
    pem.unlink()
    pem.mkdir()  # directory at .pem path

    with pytest.raises(TrustError, match="private key"):
        trust.activate_runtime_key("runtime-2")


def test_alpha2_directory_at_pub_path_refused(env) -> None:
    """activate_key must refuse if .pub path is a directory."""
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-2.pub"
    pub.unlink()
    pub.mkdir()  # directory at .pub path

    with pytest.raises(TrustError, match="public key"):
        trust.activate_runtime_key("runtime-2")


# ---------------------------------------------------------------------------
# α-3 — validate_store enforces cryptographic keypair match
# ---------------------------------------------------------------------------

def test_alpha3_validate_store_rejects_keypair_mismatch(env, tmp_path) -> None:
    """validate_store must reject a mismatched keypair, same contract as I-T-4.

    Pre-fix: validate_store only checked path validity and file existence.
    A rogue public key (not derived from the private key) passed validation
    while I-T-4 would flag it — the strict-on-input/loose-on-state pattern.
    """
    cfg, trust = env

    # Generate a rogue keypair and replace runtime-1.pub with the rogue public key
    rogue_pem = tmp_path / "rogue.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(rogue_pem)],
        check=True, capture_output=True,
    )
    rogue_pub = subprocess.run(
        ["openssl", "pkey", "-pubout", "-in", str(rogue_pem)],
        check=True, capture_output=True,
    ).stdout

    pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-1.pub"
    pub.write_bytes(rogue_pub)

    with pytest.raises(TrustError, match="mismatch|keypair"):
        trust.validate_store("runtime")


def test_alpha3_validate_store_accepts_correct_keypair(env) -> None:
    """validate_store must not fire on a store with matching keypairs."""
    cfg, trust = env
    trust.validate_store("runtime")  # must not raise


def test_alpha3_i_t4_and_validate_store_same_contract(env, tmp_path) -> None:
    """I-T-4 and validate_store must both detect a keypair mismatch.
    They use the same shared helper so the contract is identical.
    """
    from wpgovern.utils.invariants import check_all_invariants
    cfg, trust = env

    rogue_pem = tmp_path / "rogue2.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(rogue_pem)],
        check=True, capture_output=True,
    )
    rogue_pub = subprocess.run(
        ["openssl", "pkey", "-pubout", "-in", str(rogue_pem)],
        check=True, capture_output=True,
    ).stdout

    pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-1.pub"
    pub.write_bytes(rogue_pub)

    # Both must detect it
    violations = check_all_invariants(cfg)
    assert any(v.invariant_id == "I-T-4" for v in violations), (
        "I-T-4 must detect keypair mismatch"
    )
    with pytest.raises(TrustError, match="mismatch|keypair"):
        trust.validate_store("runtime")


# ---------------------------------------------------------------------------
# α-4 — Journaled commit failure self-repairs
# ---------------------------------------------------------------------------

def test_alpha4_journaled_commit_failure_self_repairs(env) -> None:
    """Journaled transaction with delete failure must invoke in-process recovery
    before raising TransactionError, leaving a consistent state.

    Post-fix: either the delete completes (recovery finishes the operation) or
    the write is rolled back (recovery rolls back). Either way, consistent.
    """
    from wpgovern.utils.transaction import AtomicTransaction, TransactionError
    cfg, trust = env

    target = cfg.root_dir / "state" / "data.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"v": 1}')

    gate = cfg.root_dir / "state" / "gate.lock"
    gate.write_text("locked")

    staging = cfg.root_dir / "state" / ".staging"
    staging.mkdir(parents=True, exist_ok=True)

    real_unlink = Path.unlink
    fail_count = [0]

    def failing_unlink_once(self, *args, **kwargs):
        if str(self).endswith("gate.lock") and fail_count[0] == 0:
            fail_count[0] += 1
            raise OSError(errno.EACCES, "permission denied (simulated, first attempt only)")
        return real_unlink(self, *args, **kwargs)

    with mock.patch.object(Path, "unlink", failing_unlink_once):
        with pytest.raises(TransactionError):
            with AtomicTransaction(
                staging,
                service_label="test.alpha4",
                actor_id=None,
                journal_root=cfg.root_dir,
                trust_service=trust,
            ) as txn:
                txn.stage_text(target, '{"v": 2}')
                txn.stage_delete(gate)
                txn.commit()

    # State must be consistent: either recovery completed or recovery rolled back.
    # Not an intermediate state where write committed and delete didn't.
    state_is_complete = target.read_text() == '{"v": 2}' and not gate.exists()
    state_is_rolled_back = target.read_text() == '{"v": 1}' and gate.exists()
    assert state_is_complete or state_is_rolled_back, (
        f"Post-failure state must be consistent. "
        f"target={target.read_text()!r}, gate_exists={gate.exists()}"
    )


# ---------------------------------------------------------------------------
# α-5 — I-AUD-2 chain-tail invariant
# ---------------------------------------------------------------------------

def _emit_checkpoint(cfg, logger) -> None:
    """Emit an audit.review.checkpoint + audit.checkpoint.signature pair.
    Mirrors the CLI audit checkpoint command for test purposes.
    """
    import uuid
    from wpgovern.core.signing import SigningService
    checkpoint_id = f"cp-{uuid.uuid4().hex[:12]}"
    record = logger.emit(
        event_type="audit.review.checkpoint",
        actor="test-op",
        outcome="success",
        details={
            "checkpoint_id": checkpoint_id,
            "review_period_start": "2026-01-01T00:00:00Z",
            "review_period_end": "2026-01-01T00:01:00Z",
            "records_reviewed": 1,
            "review_status": "clean",
        },
    )
    signing = SigningService(config=cfg)
    sig = signing.sign_bytes(record.self_hash.encode("utf-8"), domain="runtime")
    logger.emit(
        event_type="audit.checkpoint.signature",
        actor="test-op",
        outcome="success",
        details={
            "checkpoint_id": checkpoint_id,
            "checkpoint_seq": record.seq,
            "checkpoint_hash": record.self_hash,
            "checkpoint_signature": sig,
        },
    )


def test_alpha5_long_uncovered_tail_fires_iaud2(env) -> None:
    """I-AUD-2 must fire when many records exist after the last checkpoint."""
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    logger = AuditLogger(config=cfg)
    logger.emit("setup.event", "op1", "success", details={})
    _emit_checkpoint(cfg, logger)

    for i in range(150):
        logger.emit("worker.event", "op1", "success", details={"i": i})

    violations = check_all_invariants(cfg)
    aud2 = [v for v in violations if v.invariant_id == "I-AUD-2"]
    assert aud2, "I-AUD-2 must fire when tail exceeds MAX_TAIL_WINDOW (100)"
    assert aud2[0].details["tail_size"] > 100


def test_alpha5_no_checkpoint_fires_iaud2_when_long(env) -> None:
    """I-AUD-2 must fire when NO checkpoint exists AND chain exceeds MAX_TAIL_WINDOW."""
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    logger = AuditLogger(config=cfg)
    # Emit more than MAX_TAIL_WINDOW (100) records with no checkpoint
    for i in range(110):
        logger.emit("event", "op1", "success", details={"i": i})

    violations = check_all_invariants(cfg)
    aud2 = [v for v in violations if v.invariant_id == "I-AUD-2"]
    assert aud2, "I-AUD-2 must fire when chain exceeds MAX_TAIL_WINDOW with no checkpoint"


def test_alpha5_iaud2_does_not_fire_on_small_uncheckpointed_chain(env) -> None:
    """Small audit chains without checkpoints are normal startup state, not violations.

    α-5-fix: the original I-AUD-2 fired on ANY chain without a checkpoint (even 1 record).
    kill_points tests emit 1-2 records and were broken by this. The corrected contract:
    only fire when the chain exceeds MAX_TAIL_WINDOW without a checkpoint.
    """
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    logger = AuditLogger(config=cfg)
    for i in range(5):
        logger.emit("event.x", "op", "success", details={"i": i})

    violations = check_all_invariants(cfg)
    aud2 = [v for v in violations if v.invariant_id == "I-AUD-2"]
    assert not aud2, f"I-AUD-2 must not fire on a 5-record chain without checkpoint: {aud2}"


def test_alpha5_within_window_no_violation(env) -> None:
    """I-AUD-2 must not fire when tail is within MAX_TAIL_WINDOW."""
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    logger = AuditLogger(config=cfg)
    for i in range(5):
        logger.emit("event", "op1", "success", details={"i": i})
    _emit_checkpoint(cfg, logger)
    for i in range(10):  # well within 100
        logger.emit("event", "op1", "success", details={"i": i})

    violations = check_all_invariants(cfg)
    aud2 = [v for v in violations if v.invariant_id == "I-AUD-2"]
    assert not aud2, f"I-AUD-2 must not fire within MAX_TAIL_WINDOW: {aud2}"
