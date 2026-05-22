"""
Regression tests for Phase ε.1.

ε-1 — generate_key uses staging-directory pattern (no orphan key material on failure)
ε-2 — I-T-6 invariant: trust dirs contain only registered key files
"""

from __future__ import annotations

import os
from pathlib import Path

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
# ε-1 — staging-directory pattern
# ---------------------------------------------------------------------------

def test_epsilon1_chmod_failure_leaves_no_orphan(env, monkeypatch) -> None:
    """ε-1: chmod failure during generation must not leave orphan key material
    in the governed directories.

    Pre-fix: private key was generated directly into trust/runtime/private/.
    A chmod failure left an unregistered .pem file there.
    Post-fix: staging-dir pattern — keys go to a temp dir first, governed
    dirs only receive the files after the trust store registration succeeds.
    """
    cfg, trust = env

    real_chmod = os.chmod

    def failing_chmod(path, mode, *args, **kwargs):
        if "orphan-test" in str(path) and str(path).endswith(".pem"):
            raise PermissionError("simulated chmod failure")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", failing_chmod)

    with pytest.raises(PermissionError):
        trust.generate_runtime_key("orphan-test")

    governed_priv = cfg.root_dir / "trust" / "runtime" / "private"
    governed_pub = cfg.root_dir / "trust" / "runtime" / "public"

    assert not (governed_priv / "orphan-test.pem").exists(), (
        "Orphan private key must not exist in governed dir after chmod failure"
    )
    assert not (governed_pub / "orphan-test.pub").exists(), (
        "Orphan public key must not exist in governed dir after chmod failure"
    )
    store = trust.load_store("runtime")
    assert not any(r.key_id == "orphan-test" for r in store.keys), (
        "Trust store must have no entry for a key that failed generation"
    )


def test_epsilon1_pubout_failure_leaves_no_orphan(env) -> None:
    """ε-1: pubkey derivation failure must not leave orphan key material."""
    from unittest import mock
    cfg, trust = env

    real_run = trust._run_openssl

    def failing_pubout(args):
        if "-pubout" in args:
            raise RuntimeError("simulated pubout failure")
        return real_run(args)

    with mock.patch.object(trust, "_run_openssl", side_effect=failing_pubout):
        with pytest.raises(RuntimeError):
            trust.generate_runtime_key("orphan-test-2")

    governed_priv = cfg.root_dir / "trust" / "runtime" / "private"
    governed_pub = cfg.root_dir / "trust" / "runtime" / "public"
    assert not (governed_priv / "orphan-test-2.pem").exists()
    assert not (governed_pub / "orphan-test-2.pub").exists()


def test_epsilon1_happy_path_publishes_to_governed_dirs(env) -> None:
    """ε-1: successful generate_key publishes keypair and trust-store entry."""
    cfg, trust = env
    trust.generate_runtime_key("happy-key")

    governed_priv = cfg.root_dir / "trust" / "runtime" / "private" / "happy-key.pem"
    governed_pub = cfg.root_dir / "trust" / "runtime" / "public" / "happy-key.pub"

    assert governed_priv.is_file()
    assert governed_pub.is_file()
    assert oct(governed_priv.stat().st_mode & 0o777) == "0o600"

    store = trust.load_store("runtime")
    assert any(r.key_id == "happy-key" for r in store.keys)


def test_epsilon1_no_staging_dirs_left_after_success(env) -> None:
    """ε-1: success path cleans up the staging directory."""
    cfg, trust = env
    trust.generate_runtime_key("clean-key")

    runtime_root = cfg.root_dir / "trust" / "runtime"
    leftovers = [p for p in runtime_root.iterdir() if p.name.startswith(".keygen-")]
    assert not leftovers, f"Staging dirs leaked after successful generation: {leftovers}"


# ---------------------------------------------------------------------------
# ε-2 — I-T-6 invariant
# ---------------------------------------------------------------------------

def test_epsilon2_orphan_private_key_fires_it6(env) -> None:
    """I-T-6 must fire on an unregistered private key file in the governed dir."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    orphan = cfg.root_dir / "trust" / "runtime" / "private" / "smuggled.pem"
    orphan.write_text("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")
    os.chmod(orphan, 0o600)

    violations = check_all_invariants(cfg)
    it6 = [v for v in violations if v.invariant_id == "I-T-6"]
    assert it6, "I-T-6 must fire on orphan private key in governed dir"
    assert any("smuggled" in str(v.details) for v in it6)


def test_epsilon2_orphan_public_key_fires_it6(env) -> None:
    """I-T-6 must fire on an unregistered public key file."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    orphan = cfg.root_dir / "trust" / "runtime" / "public" / "smuggled.pub"
    orphan.write_text("ssh-fake AAAAFakePub\n")

    violations = check_all_invariants(cfg)
    it6 = [v for v in violations if v.invariant_id == "I-T-6"]
    assert it6, "I-T-6 must fire on orphan public key in governed dir"


def test_epsilon2_clean_store_has_no_it6_violations(env) -> None:
    """I-T-6 must not fire when all key files are registered."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, trust = env
    trust.generate_runtime_key("extra-key")  # second key, registered

    violations = check_all_invariants(cfg)
    it6 = [v for v in violations if v.invariant_id == "I-T-6"]
    assert not it6, f"I-T-6 false-positive on clean store: {it6}"


def test_epsilon2_active_symlink_does_not_fire_it6(env) -> None:
    """I-T-6 must skip the active.pem symlink (that's I-T-5's job)."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    active_link = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    assert active_link.is_symlink(), "Setup: active symlink should exist after activation"

    violations = check_all_invariants(cfg)
    it6_on_active = [
        v for v in violations
        if v.invariant_id == "I-T-6" and "active" in str(v.details)
    ]
    assert not it6_on_active, (
        f"I-T-6 must not fire on the active symlink (handled by I-T-5): {it6_on_active}"
    )
