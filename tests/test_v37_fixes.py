"""
Regression tests for v37 fixes.

P1  — I-T-4 reports missing active/preactive private keys as violations
P2  — activate_key pre-commit check: missing private key raises TrustError BEFORE
      any mutation (precondition, not post-condition)
P3  — CI guards catch README drift and silent exception swallowing

Precondition vs postcondition placement rule: preconditions go BEFORE transactions;
post-conditions verify what the transaction did. Don't mix the two.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

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
# P1 — I-T-4 reports missing active private key
# ---------------------------------------------------------------------------

def test_it4_catches_missing_active_private_key(env) -> None:
    """I-T-4 must fire when the active private key is missing.
    Pre-fix: 'if not priv_pem.exists() or not pub_path_str: continue'
    silently skipped missing private keys — validate_store failed but
    check_all_invariants() reported no violation."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    # Delete the active private key
    priv = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem"
    priv.unlink()

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-T-4" in ids, (
        "I-T-4 must fire when active private key is missing. "
        "Pre-fix: missing priv key was silently skipped."
    )


def test_it4_catches_missing_preactive_private_key(env) -> None:
    """I-T-4 must fire when a preactive private key is missing.
    This is the deferred-failure path: restore accepts the backup,
    check_all_invariants passes, but activation later fails."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")  # preactive

    # Delete the preactive private key
    priv = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem"
    priv.unlink()

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-T-4" in ids, (
        "I-T-4 must fire when preactive private key is missing. "
        "This prevents silent deferred failure when the operator later "
        "tries to rotate to the preactive key."
    )


def test_it4_clean_state_no_violation(env) -> None:
    """I-T-4 must not fire on a healthy trust store."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    violations = check_all_invariants(cfg)
    t4 = [v for v in violations if v.invariant_id == "I-T-4"]
    assert not t4, f"I-T-4 must not fire on clean store: {t4}"


# ---------------------------------------------------------------------------
# P2 — Pre-commit check: missing private key raises BEFORE any mutation
# ---------------------------------------------------------------------------

def test_pre_commit_check_raises_before_any_mutation(env) -> None:
    """activate_key must raise TrustError BEFORE the transaction when the
    target key's private file is missing.

    external review's rule: preconditions go before transactions; post-conditions
    verify what the transaction did. The missing-private-key check belongs
    in (a) precondition, not (c) post-condition via validate_store.

    Pre-fix path: AtomicTransaction committed successfully, then validate_store
    raised TrustError, but the transaction was already committed — leaving
    active_key_id changed with no working private key.
    """
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")  # preactive

    # Delete the private key before activation
    priv = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem"
    priv.unlink()

    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content_before = json.loads(store_path.read_text())
    active_key_id_before = content_before.get("active_key_id")

    with pytest.raises(TrustError, match="private key.*missing|missing.*private key"):
        trust.activate_runtime_key("runtime-2")

    # JSON must be UNCHANGED — error raised before any transaction mutation
    content_after = json.loads(store_path.read_text())
    assert content_after.get("active_key_id") == active_key_id_before, (
        f"active_key_id must not change when pre-commit check fires. "
        f"Before: {active_key_id_before!r}, After: {content_after.get('active_key_id')!r}"
    )

    # runtime-1 must still be usable for signing
    trust.validate_store("runtime")  # must not raise


def test_pre_commit_check_allows_valid_activation(env) -> None:
    """Pre-commit check must not block valid activations where private key exists."""
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")
    # Private key should exist from generate_runtime_key — activation must succeed
    trust.activate_runtime_key("runtime-2")  # must not raise
    trust.validate_store("runtime")
