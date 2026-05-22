"""
Regression tests for v36 fixes.

H1  — Bootstrap/no-journal trust activation rolls back JSON if symlink fails
M-H1 — B4 evidence written even for non-journaled (bootstrap) transactions

Contract: "In what conditions does this guard apply? In what conditions does it NOT apply?
For each condition where it doesn't apply, what is the equivalent guard?"
(Contract symmetry across enforcement sites, artifact types, and system conditions)
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
def bootstrap_env(tmp_path: Path):
    """Environment with NO active journal key — simulates initial bootstrap."""
    root = tmp_path / "root"
    cfg = WPGovernConfig(
        root_dir=root, install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    # Only generate keys, NO activation of journal key yet (bootstrap state)
    trust = TrustService(config=cfg)
    return cfg, trust


@pytest.fixture()
def full_env(tmp_path: Path):
    """Environment with journal key active — post-bootstrap state."""
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
# H1 — Bootstrap activation: JSON rolled back when symlink fails
# ---------------------------------------------------------------------------

def test_h1_bootstrap_runtime_activation_rolls_back_on_symlink_failure(
    bootstrap_env,
) -> None:
    """Initial runtime activation (no journal key): if symlink fails after JSON write,
    JSON must be rolled back to pre-activation state. System must be retry-safe.

    Pre-fix: no rollback mechanism existed; JSON stayed mutated with no intent,
    no B4 file, no recovery path, no way to retry.
    """
    cfg, trust = bootstrap_env
    trust.generate_runtime_key("runtime-1")

    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"

    original_rename = Path.rename

    def fail_symlink_rename(self, target):
        if ".symlink_tmp" in str(self):
            raise OSError(28, "No space left on device (simulated)")
        return original_rename(self, target)

    with mock.patch.object(Path, "rename", fail_symlink_rename):
        with pytest.raises(Exception):
            trust.activate_runtime_key("runtime-1")

    # JSON must be rolled back — store should look like pre-activation
    # (either the key file doesn't exist yet, or active_key_id is not runtime-1)
    if store_path.exists():
        content = json.loads(store_path.read_text())
        # If the store exists, active_key_id should be None (unset) or the
        # previously active key, NOT runtime-1 (which failed to fully activate)
        # The critical invariant: I-T-5 must not fire after recovery/rollback
        from wpgovern.utils.invariants import check_all_invariants
        violations = check_all_invariants(cfg)
        # If active_key_id is set, the symlink must match it (I-T-5)
        # A rolled-back state either has no active key or a consistent state
        it5_violations = [v for v in violations if v.invariant_id == "I-T-5"]
        # After rollback, no I-T-5 desync should be present
        assert not it5_violations, (
            f"After bootstrap rollback, I-T-5 must not fire (no desync). "
            f"Violations: {it5_violations}"
        )


def test_h1_bootstrap_activation_retry_succeeds(bootstrap_env) -> None:
    """After a failed bootstrap activation (symlink failure + rollback),
    retrying activate_runtime_key must succeed."""
    cfg, trust = bootstrap_env
    trust.generate_runtime_key("runtime-1")

    original_rename = Path.rename
    fail_count = [0]

    def fail_first_symlink_rename(self, target):
        if ".symlink_tmp" in str(self) and fail_count[0] == 0:
            fail_count[0] += 1
            raise OSError(28, "Simulated ENOSPC on first attempt")
        return original_rename(self, target)

    # First attempt fails
    with mock.patch.object(Path, "rename", fail_first_symlink_rename):
        with pytest.raises(Exception):
            trust.activate_runtime_key("runtime-1")

    # Retry must succeed
    trust.activate_runtime_key("runtime-1")  # must not raise

    # Verify the store is consistent
    trust.validate_store("runtime")
    from wpgovern.utils.invariants import check_all_invariants
    violations = check_all_invariants(cfg)
    assert not any(v.invariant_id in ("I-T-5",) for v in violations), (
        "After successful retry, no trust invariant violations expected"
    )


def test_h1_bootstrap_release_activation_rolls_back(bootstrap_env) -> None:
    """Initial release activation: symlink failure rolls back JSON."""
    cfg, trust = bootstrap_env
    trust.generate_runtime_key("runtime-1")
    trust.activate_runtime_key("runtime-1")
    trust.generate_release_key("release-1")

    store_path = cfg.root_dir / "trust" / "release" / "public" / "trusted-release-keys.json"
    original_rename = Path.rename

    def fail_symlink_rename(self, target):
        if ".symlink_tmp" in str(self):
            raise OSError(28, "Simulated ENOSPC")
        return original_rename(self, target)

    with mock.patch.object(Path, "rename", fail_symlink_rename):
        with pytest.raises(Exception):
            trust.activate_release_key("release-1")

    # Store should not have release-1 as active_key_id in a desynced state
    if store_path.exists():
        from wpgovern.utils.invariants import check_all_invariants
        violations = check_all_invariants(cfg)
        it5 = [v for v in violations if v.invariant_id == "I-T-5"]
        assert not it5, f"Release activation rollback must leave no I-T-5 desync: {it5}"


# ---------------------------------------------------------------------------
# M-H1 — B4 evidence for non-journaled transactions
# ---------------------------------------------------------------------------

def test_mh1_bootstrap_b4_writes_event_file(bootstrap_env) -> None:
    """B4 during bootstrap (no-journal) activation must write .last_b4_event.json.
    Pre-fix: _record_b4_event returned early when journal_root was None because
    service_label=None skipped journal setup, leaving state_root also unset.
    """
    cfg, trust = bootstrap_env
    trust.generate_runtime_key("runtime-1")

    original_rename = Path.rename

    def fail_enospc(self, target):
        if ".symlink_tmp" in str(self):
            raise OSError(28, "No space left on device")
        return original_rename(self, target)

    with mock.patch.object(Path, "rename", fail_enospc):
        with pytest.raises(Exception):
            trust.activate_runtime_key("runtime-1")

    b4_path = cfg.root_dir / "state" / ".last_b4_event.json"
    assert b4_path.exists(), (
        ".last_b4_event.json must be written during bootstrap B4. "
        "Pre-fix: journal_root was None for service_label=None transactions "
        "so _record_b4_event returned early without writing the file."
    )
    assert oct(b4_path.stat().st_mode & 0o777) == "0o600"


def test_mh1_non_journaled_b4_preflight_writes_event_file(full_env) -> None:
    """B4 during preflight of a non-journaled transaction writes event file."""
    from wpgovern.utils.transaction import AtomicTransaction
    from wpgovern.errors import DiskFullError

    cfg, _ = full_env
    staging_root = cfg.root_dir / "state" / ".transactions"
    staging_root.mkdir(parents=True, exist_ok=True)

    def raise_b4(self):
        raise DiskFullError(
            path=cfg.root_dir / "state",
            phase="preflight",
            errno_classified=28,
        )

    # Non-journaled transaction (service_label=None, no trust_service)
    with mock.patch.object(AtomicTransaction, "_b4_preflight", raise_b4):
        with pytest.raises(DiskFullError):
            with AtomicTransaction(
                staging_root,
                service_label=None,  # bootstrap / non-journaled
            ) as txn:
                txn.commit()

    b4_path = cfg.root_dir / "state" / ".last_b4_event.json"
    assert b4_path.exists(), (
        "Non-journaled transaction B4 preflight must write .last_b4_event.json. "
        "state_root must be derived from staging_root even when journal_root is None."
    )
