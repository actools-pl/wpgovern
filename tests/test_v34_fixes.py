"""
Regression tests for v34 fixes.

H1  — trust.activate_key() is now atomic across JSON + symlink
M-H1/M-H2 — validate_store and I-T-3 enforce path-inside-tree
M-H3 — I-T-4 reports corrupt private key errors
I-T-5 — active.pem/active_key_id desync invariant
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
# H1 — trust.activate_key() atomic across JSON + symlink
# ---------------------------------------------------------------------------

def test_h1_activate_key_symlink_failure_leaves_consistent_state(env) -> None:
    """If symlink update fails during activate_key, neither JSON nor symlink
    should be changed — the trust store must remain in the pre-activation state.

    Pre-fix: JSON was committed in one transaction, symlink updated separately.
    A symlink failure left JSON saying 'r2 is active' while active.pem pointed
    to r1, stranding the system.

    Post-fix: symlink is staged in the same AtomicTransaction as the JSON.
    If symlink staging fails, neither artifact is changed.
    """
    from wpgovern.utils.transaction import AtomicTransaction
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    # Simulate symlink update failure by patching stage_symlink_replace
    original_stage_symlink = AtomicTransaction.stage_symlink_replace

    def fail_symlink(self, symlink_path, target_name):
        raise OSError("Simulated symlink failure")

    with mock.patch.object(AtomicTransaction, "stage_symlink_replace", fail_symlink):
        with pytest.raises(Exception):
            trust.activate_runtime_key("runtime-2")

    # Trust store must remain in pre-activation state
    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())

    # active_key_id must still be runtime-1 (the old active key)
    assert content.get("active_key_id") == "runtime-1", (
        f"active_key_id should still be runtime-1 after failed activate, "
        f"got: {content.get('active_key_id')}"
    )

    # active.pem must still point to runtime-1
    symlink = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    assert symlink.is_symlink()
    assert "runtime-1" in os.readlink(str(symlink)), (
        "active.pem must still point to runtime-1 after failed activate"
    )

    # Validate store must pass (pre-activation state is valid)
    trust.validate_store("runtime")  # must not raise


def test_h1_successful_activate_is_consistent(env) -> None:
    """Successful activate_key produces consistent JSON + symlink state."""
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")
    trust.activate_runtime_key("runtime-2")

    content = json.loads(
        (cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json").read_text()
    )
    assert content.get("active_key_id") == "runtime-2"

    symlink = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    assert symlink.is_symlink()
    assert os.readlink(str(symlink)) == "runtime-2.pem"

    trust.validate_store("runtime")  # must not raise


# ---------------------------------------------------------------------------
# M-H1 / M-H2 — validate_store and I-T-3 enforce path-inside-tree
# ---------------------------------------------------------------------------

def test_mh1_validate_store_rejects_path_outside_tree(env) -> None:
    """validate_store must reject a key whose path resolves outside the
    governed trust directory."""
    cfg, trust = env
    # Write a public key outside the trust tree
    outside = cfg.root_dir / "outside.pub"
    runtime_pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-1.pub"
    outside.write_bytes(runtime_pub.read_bytes())

    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())
    for k in content["keys"]:
        if k.get("key_id") == content.get("active_key_id"):
            k["path"] = str(outside)
    store_path.write_text(json.dumps(content))

    from wpgovern.core.trust import TrustError
    with pytest.raises(TrustError, match="outside|governed"):
        trust.validate_store("runtime")


def test_mh2_it3_catches_path_outside_tree(env) -> None:
    """I-T-3 must fire when a key path resolves outside the governed trust tree."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, trust = env

    outside = cfg.root_dir / "outside.pub"
    runtime_pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-1.pub"
    outside.write_bytes(runtime_pub.read_bytes())

    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())
    for k in content["keys"]:
        k["path"] = str(outside)
    store_path.write_text(json.dumps(content))

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-T-3" in ids, (
        "I-T-3 must fire when key path resolves outside trust/<domain>/public/"
    )


# ---------------------------------------------------------------------------
# M-H3 — I-T-4 reports corrupt private key
# ---------------------------------------------------------------------------

def test_mh3_it4_catches_corrupt_private_key(env) -> None:
    """I-T-4 must fire when the active private key is corrupt/unreadable.
    Pre-fix: except Exception: pass silently swallowed the error."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    # Corrupt the active private key
    priv_key = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem"
    priv_key.write_bytes(b"not a valid private key")
    os.chmod(priv_key, 0o600)

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-T-4" in ids, (
        "I-T-4 must detect a corrupt/invalid active private key. "
        "Silent error swallowing produces false confidence."
    )


def test_mh3_it4_clean_state_passes(env) -> None:
    """I-T-4 must not fire on a healthy trust store."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    violations = check_all_invariants(cfg)
    t4 = [v for v in violations if v.invariant_id == "I-T-4"]
    assert not t4, f"I-T-4 fired on clean store: {t4}"


# ---------------------------------------------------------------------------
# I-T-5 — active.pem / active_key_id desync invariant
# ---------------------------------------------------------------------------

def test_it5_catches_desync_between_json_and_symlink(env) -> None:
    """I-T-5 must fire when the trust-store JSON says key A is active but
    active.pem points to key B. This is the H1 stranding state."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    # Manually mutate JSON to say runtime-2 is active without touching symlink
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
    # active.pem still points to runtime-1

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-T-5" in ids, (
        "I-T-5 must detect JSON/symlink desync (active_key_id=runtime-2 but "
        "active.pem points to runtime-1). This is the H1 stranding state."
    )


def test_it5_clean_state_passes(env) -> None:
    """I-T-5 must not fire when JSON and active.pem are consistent."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    violations = check_all_invariants(cfg)
    t5 = [v for v in violations if v.invariant_id == "I-T-5"]
    assert not t5, f"I-T-5 fired on clean state: {t5}"
