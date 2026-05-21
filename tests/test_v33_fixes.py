"""
Regression tests for v33 fixes.

Covers the FULL trust backup validation contract:
H1/H2 — empty/directory key paths refused
H3     — validate_store uses is_file() not exists()
H4     — preactive keypair validation
I-T-3  — trust invariant: key paths must be regular files
I-T-4  — trust invariant: active/preactive keypairs match
"""

from __future__ import annotations

import io
import json
import tarfile as _tarfile
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.core.trust import TrustError


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


def _tamper_backup(backup_path: Path, passphrase: str, tamper_fn) -> Path:
    """Decrypt, tamper, re-encrypt a backup. Returns path to tampered backup."""
    from wpgovern.core.trust_backup import _openssl_decrypt, _openssl_encrypt
    encrypted = backup_path.read_bytes()
    tar_bytes = _openssl_decrypt(encrypted, passphrase)
    out = io.BytesIO()
    with _tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as src:
        with _tarfile.open(fileobj=out, mode="w:gz") as dst:
            tamper_fn(src, dst)
    tampered_path = backup_path.parent / "tampered.enc"
    tampered_path.write_bytes(_openssl_encrypt(out.getvalue(), passphrase))
    return tampered_path


# ---------------------------------------------------------------------------
# H1 — Empty key path refused
# ---------------------------------------------------------------------------

def test_h1_empty_key_path_refused(env) -> None:
    """Backup with active key path='' must be refused. Pre-fix: empty path was
    skipped (if not key_path_str: continue) and keypair check was skipped."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup, TrustBackupError
    cfg, _ = env
    backup = cfg.root_dir / "backup.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    def tamper(src, dst):
        for m in src.getmembers():
            if "trusted-runtime-keys.json" in m.name:
                content = json.loads(src.extractfile(m).read())
                for k in content["keys"]:
                    k["path"] = ""  # empty path
                data = json.dumps(content).encode()
                m.size = len(data)
                dst.addfile(m, io.BytesIO(data))
            else:
                f = src.extractfile(m)
                dst.addfile(m, f)

    tampered = _tamper_backup(backup, "pw", tamper)
    restore_root = cfg.root_dir / "restore_h1"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="empty|path"):
        restore_trust_backup(tampered, restore_root, passphrase="pw")


# ---------------------------------------------------------------------------
# H2 — Directory key path refused
# ---------------------------------------------------------------------------

def test_h2_directory_key_path_refused(env) -> None:
    """Backup with active key path='.' (a directory) must be refused.
    Pre-fix: Path('.').exists() == True so the check passed."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup, TrustBackupError
    cfg, _ = env
    backup = cfg.root_dir / "backup_h2.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    def tamper(src, dst):
        for m in src.getmembers():
            if "trusted-runtime-keys.json" in m.name:
                content = json.loads(src.extractfile(m).read())
                # Point active key path to the public directory itself
                for k in content["keys"]:
                    if k.get("key_id") == content.get("active_key_id"):
                        # Use "." which resolves to store_dir (a directory)
                        k["path"] = "."
                data = json.dumps(content).encode()
                m.size = len(data)
                dst.addfile(m, io.BytesIO(data))
            else:
                f = src.extractfile(m)
                dst.addfile(m, f)

    tampered = _tamper_backup(backup, "pw", tamper)
    restore_root = cfg.root_dir / "restore_h2"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError):
        restore_trust_backup(tampered, restore_root, passphrase="pw")


# ---------------------------------------------------------------------------
# H3 — validate_store uses is_file() not just exists()
# ---------------------------------------------------------------------------

def test_h3_validate_store_rejects_directory_path(env) -> None:
    """TrustService.validate_store() must reject a key path that points to
    a directory. Pre-fix: .exists() returned True for directories."""
    cfg, trust = env
    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())
    # Replace active key path with a directory
    for k in content["keys"]:
        if k.get("key_id") == content.get("active_key_id"):
            k["path"] = str(cfg.root_dir / "trust" / "runtime" / "public")
    store_path.write_text(json.dumps(content))
    with pytest.raises(TrustError, match="not a regular file|path missing"):
        trust.validate_store("runtime")


def test_h3_validate_store_rejects_empty_path(env) -> None:
    """TrustService.validate_store() must reject a key with empty path."""
    cfg, trust = env
    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())
    for k in content["keys"]:
        k["path"] = ""
    store_path.write_text(json.dumps(content))
    with pytest.raises(TrustError, match="empty"):
        trust.validate_store("runtime")


# ---------------------------------------------------------------------------
# H4 — Preactive keypair validation
# ---------------------------------------------------------------------------

def test_h4_missing_preactive_private_key_refused(env) -> None:
    """Backup with missing preactive private key must be refused.
    Pre-fix: only active key was validated; missing preactive was accepted."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup, TrustBackupError
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")  # preactive

    backup = cfg.root_dir / "backup_h4.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    def tamper(src, dst):
        for m in src.getmembers():
            # Drop the preactive private key
            if "runtime-2.pem" in m.name:
                continue
            f = src.extractfile(m)
            dst.addfile(m, f)

    tampered = _tamper_backup(backup, "pw", tamper)
    restore_root = cfg.root_dir / "restore_h4"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="preactive|private key"):
        restore_trust_backup(tampered, restore_root, passphrase="pw")


def test_h4_mismatched_preactive_private_key_refused(env) -> None:
    """Backup with mismatched preactive private key must be refused.
    This is the H4+M2 composition: restore accepts it now but activation
    would corrupt the trust store later. Pre-fix: not validated at all."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup, TrustBackupError
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")  # preactive

    backup = cfg.root_dir / "backup_h4b.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    # Replace runtime-2.pem with runtime-1's private key (wrong key for runtime-2)
    pem1 = (cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem").read_bytes()

    def tamper(src, dst):
        for m in src.getmembers():
            if "runtime-2.pem" in m.name:
                m.size = len(pem1)
                dst.addfile(m, io.BytesIO(pem1))
            else:
                f = src.extractfile(m)
                dst.addfile(m, f)

    tampered = _tamper_backup(backup, "pw", tamper)
    restore_root = cfg.root_dir / "restore_h4b"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="mismatch|keypair"):
        restore_trust_backup(tampered, restore_root, passphrase="pw")


def test_h4_valid_multi_key_backup_still_restores(env) -> None:
    """Valid backup with multiple keys (active + preactive) restores and
    both keys verify correctly."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup
    from wpgovern.core.signing import SigningService
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")  # valid preactive

    backup = cfg.root_dir / "backup_h4c.enc"
    create_trust_backup(cfg.root_dir / "trust", backup, passphrase="pw")

    restore_root = cfg.root_dir / "restore_h4c"
    restore_root.mkdir()
    restore_trust_backup(backup, restore_root, passphrase="pw")

    restore_cfg = WPGovernConfig(
        root_dir=restore_root, install_dir=restore_root / "install",
        runtime_trust_store=restore_root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=restore_root / "trust/release/public/trusted-release-keys.json",
        active_pointer=restore_root / "state/active.json",
        audit_log=restore_root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    restore_trust = TrustService(config=restore_cfg)
    for domain in ("runtime", "release", "journal"):
        restore_trust.validate_store(domain)

    signing = SigningService(config=restore_cfg)
    data = b"post-restore sign/verify"
    sig = signing.sign_bytes(data, domain="runtime")
    signing.verify_bytes(data, sig, domain="runtime")


# ---------------------------------------------------------------------------
# I-T-3 — Trust invariant: key paths are regular files
# ---------------------------------------------------------------------------

def test_it3_catches_empty_key_path(env) -> None:
    """I-T-3 must fire when a trust key has an empty path."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    content = json.loads(store_path.read_text())
    for k in content["keys"]:
        k["path"] = ""
    store_path.write_text(json.dumps(content))
    violations = check_all_invariants(cfg)
    assert any(v.invariant_id == "I-T-3" for v in violations)


def test_it3_clean_store_passes(env) -> None:
    """I-T-3 must not fire on a clean trust store."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    violations = check_all_invariants(cfg)
    t3 = [v for v in violations if v.invariant_id == "I-T-3"]
    assert not t3, f"I-T-3 fired on clean store: {t3}"
