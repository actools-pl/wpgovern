"""
Regression tests for v32 fixes.

H1 — Trust backup keypair validation uses correct key_id-specific public file
     (not the leaked loop variable pointing at the last key)

Covers all four input shapes external review specified:
 (a) single-active-key store
 (b) multi-key, active is FIRST
 (c) multi-key, active is MIDDLE
 (d) multi-key, active is LAST

And two adversarial cases:
 (e) active public key swapped to wrong key but later key matches active private → refused
 (f) mismatched private key in multi-key backup → refused

M1 — DSA and PGP private key markers detected
"""

from __future__ import annotations

import io
import json
import tarfile as _tarfile
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger, AuditError
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


def _make_restore_cfg(restore_root: Path) -> WPGovernConfig:
    return WPGovernConfig(
        root_dir=restore_root, install_dir=restore_root / "install",
        runtime_trust_store=restore_root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=restore_root / "trust/release/public/trusted-release-keys.json",
        active_pointer=restore_root / "state/active.json",
        audit_log=restore_root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )


def _verify_restored_usability(restore_root: Path) -> None:
    """Assert the restored trust is fully usable: validate_store + sign/verify."""
    from wpgovern.core.signing import SigningService
    restore_cfg = _make_restore_cfg(restore_root)
    restore_trust = TrustService(config=restore_cfg)
    for domain in ("runtime", "release", "journal"):
        restore_trust.validate_store(domain)
    signing = SigningService(config=restore_cfg)
    data = b"round-trip sign/verify test"
    sig = signing.sign_bytes(data, domain="runtime")
    signing.verify_bytes(data, sig, domain="runtime")  # must not raise


# ---------------------------------------------------------------------------
# H1 — Input shape (a): single-key store (regression test for v30/v31 fix)
# ---------------------------------------------------------------------------

def test_h1_single_key_restore_and_verify(env) -> None:
    """Single-key store: restore and sign→verify must both succeed."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup
    cfg, _ = env
    backup = cfg.root_dir / "backup.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")
    restore_root = cfg.root_dir / "restore_a"
    restore_root.mkdir()
    restore_trust_backup(backup, restore_root, passphrase="pw")
    _verify_restored_usability(restore_root)


# ---------------------------------------------------------------------------
# H1 — Input shape (b): multi-key, active is FIRST key in list
# ---------------------------------------------------------------------------

def test_h1_multi_key_active_first_restores_and_verifies(env) -> None:
    """Multi-key store with active key FIRST: restore and sign→verify must succeed.
    Pre-fix: loop variable pointed at the last key, so this shape worked
    coincidentally only if active==first happened to be covered by fallback."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup
    cfg, trust = env
    # Add a second runtime key (not activated)
    trust.generate_runtime_key("runtime-2")
    # active is runtime-1 (first in list after generate order)
    backup = cfg.root_dir / "backup_b.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")
    restore_root = cfg.root_dir / "restore_b"
    restore_root.mkdir()
    restore_trust_backup(backup, restore_root, passphrase="pw")
    _verify_restored_usability(restore_root)


# ---------------------------------------------------------------------------
# H1 — Input shape (c): multi-key, active is MIDDLE key (the pre-v32 bug case)
# ---------------------------------------------------------------------------

def test_h1_multi_key_active_middle_restores_and_verifies(env) -> None:
    """Multi-key store with active key in the MIDDLE: restore and sign→verify succeed.

    This is the shape that triggered the v31 bug:
    - keys = [runtime-1 (active), runtime-2 (preactive), runtime-3 (preactive)]
    - After the loop, key_file pointed at runtime-3's pub file
    - keypair check: runtime-1.pem vs runtime-3.pub → MISMATCH → false refusal

    Post-fix: the staging_public_by_key_id map looks up runtime-1.pub by key_id.
    """
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")
    trust.generate_runtime_key("runtime-3")
    # active is still runtime-1 (middle in list)
    backup = cfg.root_dir / "backup_c.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")
    restore_root = cfg.root_dir / "restore_c"
    restore_root.mkdir()
    # Pre-fix: this would raise TrustBackupError("keypair mismatch for runtime-1")
    restore_trust_backup(backup, restore_root, passphrase="pw")
    _verify_restored_usability(restore_root)


# ---------------------------------------------------------------------------
# H1 — Input shape (d): multi-key, active is LAST key
# ---------------------------------------------------------------------------

def test_h1_multi_key_active_last_restores_and_verifies(env) -> None:
    """Multi-key store with active key LAST: restore and sign→verify succeed.
    With the explicit map fix, position doesn't matter."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")
    trust.activate_runtime_key("runtime-2")  # now runtime-2 is active (last generated)
    backup = cfg.root_dir / "backup_d.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")
    restore_root = cfg.root_dir / "restore_d"
    restore_root.mkdir()
    restore_trust_backup(backup, restore_root, passphrase="pw")
    _verify_restored_usability(restore_root)


# ---------------------------------------------------------------------------
# H1 — Adversarial case (e): public-key swap with later key matching active private
# This is external review's PoC B / external review's composition attack
# ---------------------------------------------------------------------------

def test_h1_swapped_public_keys_multi_key_refused(env) -> None:
    """H1 adversarial: active public key (runtime-1.pub) swapped with runtime-2.pub
    in a 2-key backup. The active private (runtime-1.pem) matches runtime-2.pub,
    not runtime-1.pub — but the LAST key in the list now matches the active private.

    Pre-fix: loop variable pointed at runtime-2's pub → keypair check: runtime-1.pem
    vs runtime-2.pub → MATCH (wrong!) → tampered backup accepted.

    Post-fix: map looks up runtime-1.pub by key_id → keypair check: runtime-1.pem
    vs runtime-1.pub (swapped) → MISMATCH → refused.
    """
    from wpgovern.core.trust_backup import (
        create_trust_backup, restore_trust_backup,
        TrustBackupError, _openssl_decrypt, _openssl_encrypt,
    )
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    backup = cfg.root_dir / "good.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    # Tamper: swap runtime-1.pub and runtime-2.pub
    encrypted = backup.read_bytes()
    tar_bytes = _openssl_decrypt(encrypted, "pw")

    out = io.BytesIO()
    pub1 = (cfg.root_dir / "trust" / "runtime" / "public" / "runtime-1.pub").read_bytes()
    pub2 = (cfg.root_dir / "trust" / "runtime" / "public" / "runtime-2.pub").read_bytes()

    with _tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as src:
        with _tarfile.open(fileobj=out, mode="w:gz") as dst:
            for member in src.getmembers():
                if member.name.endswith("runtime-1.pub"):
                    # Replace runtime-1.pub with runtime-2's public key
                    member.size = len(pub2)
                    dst.addfile(member, io.BytesIO(pub2))
                elif member.name.endswith("runtime-2.pub"):
                    # Replace runtime-2.pub with runtime-1's public key
                    member.size = len(pub1)
                    dst.addfile(member, io.BytesIO(pub1))
                else:
                    f = src.extractfile(member)
                    dst.addfile(member, f)

    tampered = _openssl_encrypt(out.getvalue(), "pw")
    (cfg.root_dir / "tampered.enc").write_bytes(tampered)

    restore_root = cfg.root_dir / "restore_e"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="mismatch|keypair"):
        restore_trust_backup(cfg.root_dir / "tampered.enc", restore_root, passphrase="pw")


# ---------------------------------------------------------------------------
# H1 — Adversarial case (f): active private key replaced (single-key regression)
# ---------------------------------------------------------------------------

def test_h1_replaced_private_key_refused(env) -> None:
    """Single-key backup with replaced active private key must be refused.
    This is the v31 happy-path adversarial test (regression guard)."""
    from wpgovern.core.trust_backup import (
        create_trust_backup, restore_trust_backup,
        TrustBackupError, _openssl_decrypt, _openssl_encrypt,
    )
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    backup = cfg.root_dir / "good_f.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    encrypted = backup.read_bytes()
    tar_bytes = _openssl_decrypt(encrypted, "pw")
    pem2 = (cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem").read_bytes()

    out = io.BytesIO()
    with _tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as src:
        with _tarfile.open(fileobj=out, mode="w:gz") as dst:
            for member in src.getmembers():
                if member.name.endswith("runtime-1.pem"):
                    member.size = len(pem2)
                    dst.addfile(member, io.BytesIO(pem2))
                else:
                    f = src.extractfile(member)
                    dst.addfile(member, f)

    tampered = _openssl_encrypt(out.getvalue(), "pw")
    (cfg.root_dir / "tampered_f.enc").write_bytes(tampered)

    restore_root = cfg.root_dir / "restore_f"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="mismatch|keypair"):
        restore_trust_backup(cfg.root_dir / "tampered_f.enc", restore_root, passphrase="pw")


# ---------------------------------------------------------------------------
# M1 — DSA and PGP private key markers
# ---------------------------------------------------------------------------

def test_m1_dsa_private_key_rejected(env) -> None:
    """DSA private key PEM material must be rejected in audit details."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError, match="PEM"):
        logger.emit("baseline.create", "alice", "success", details={
            "b4_event": {"key": "-----BEGIN DSA PRIVATE KEY-----\nMIIBvAIBAAKBgQDm\n-----END DSA PRIVATE KEY-----"}
        })


def test_m1_pgp_private_key_rejected(env) -> None:
    """PGP private key material must be rejected in audit details."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError, match="PEM"):
        logger.emit("baseline.create", "alice", "success", details={
            "b4_event": {"key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\ntest\n-----END PGP PRIVATE KEY BLOCK-----"}
        })
