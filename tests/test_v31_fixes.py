"""
Regression tests for v31 fixes.

H1  — Trust backup with mismatched active private/public key is refused
M-H1 — I-AUD-0 audit chain integrity invariant
M1  — Authorization:Basic, Cookie, OpenSSH secret detection
"""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
import io
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger, AuditError
from wpgovern.audit.verifier import AuditVerifier
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
# H1 — Mismatched active private/public key is refused
# ---------------------------------------------------------------------------

def test_h1_mismatched_keypair_backup_refused(env) -> None:
    """H1: restore must refuse a backup where the active private key was
    swapped for a different valid private key — even though both keys are
    syntactically valid RSA/EC keys.

    Pre-fix: pub_file = Path(pub_path_str) used the rewritten FINAL path
    which didn't exist during staging, so pub_file.exists() == False and
    keypair comparison was silently skipped. A mismatched keypair backup
    was accepted and TrustService.validate_store() passed — but signing
    with the restored private key produced signatures that failed verification.
    """
    from wpgovern.core.trust_backup import (
        create_trust_backup, restore_trust_backup, TrustBackupError
    )

    cfg, trust = env

    # Step 1: Create a legitimate backup
    backup_file = cfg.root_dir / "good.backup"
    create_trust_backup(
        trust_dir=cfg.root_dir / "trust",
        output_path=backup_file,
        passphrase="test-passphrase",
    )

    # Step 2: Generate a SECOND runtime key (creates different key material)
    trust.generate_runtime_key("runtime-2")

    # Step 3: Tamper the backup — replace the active private key with the second key
    import tarfile as _tarfile
    from wpgovern.core.trust_backup import _openssl_decrypt, _openssl_encrypt

    encrypted = backup_file.read_bytes()
    tar_bytes = _openssl_decrypt(encrypted, "test-passphrase")

    out = io.BytesIO()
    with _tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as src:
        with _tarfile.open(fileobj=out, mode="w:gz") as dst:
            for member in src.getmembers():
                if member.name.endswith("runtime-1.pem"):
                    # Replace with runtime-2's private key
                    runtime2_pem = (
                        cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem"
                    )
                    data = runtime2_pem.read_bytes()
                    member.size = len(data)
                    dst.addfile(member, io.BytesIO(data))
                else:
                    f = src.extractfile(member)
                    dst.addfile(member, f)

    tampered = _openssl_encrypt(out.getvalue(), "test-passphrase")
    tampered_backup = cfg.root_dir / "tampered.backup"
    tampered_backup.write_bytes(tampered)

    # Step 4: Restore must be refused because keypair doesn't match
    restore_root = cfg.root_dir / "restored"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="mismatch|keypair|match"):
        restore_trust_backup(
            input_path=tampered_backup,
            target_root=restore_root,
            passphrase="test-passphrase",
        )

    # Step 5: The original trust tree must remain intact
    assert (cfg.root_dir / "trust").exists(), (
        "Original trust tree must be preserved when restore is refused"
    )


def test_h1_correct_keypair_backup_accepted_and_usable(env) -> None:
    """Happy path: a backup with matching keypair is accepted and the
    restored trust material is fully usable for signing and verification."""
    from wpgovern.core.trust_backup import create_trust_backup, restore_trust_backup
    from wpgovern.core.signing import SigningService

    cfg, _ = env
    backup_file = cfg.root_dir / "good.backup"
    create_trust_backup(
        trust_dir=cfg.root_dir / "trust",
        output_path=backup_file,
        passphrase="test-passphrase",
    )

    restore_root = cfg.root_dir / "restored"
    restore_root.mkdir()
    result = restore_trust_backup(
        input_path=backup_file,
        target_root=restore_root,
        passphrase="test-passphrase",
    )
    assert result["trust_dir_exists"]

    # Verify the restored material is actually usable
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

    restore_signing = SigningService(config=restore_cfg)
    data = b"test sign/verify after restore"
    sig = restore_signing.sign_bytes(data, domain="runtime")
    restore_signing.verify_bytes(data, sig, domain="runtime")  # must not raise


# ---------------------------------------------------------------------------
# M-H1 — I-AUD-0 audit chain integrity invariant
# ---------------------------------------------------------------------------

def test_mh1_iaud0_catches_tampered_record_details(env) -> None:
    """I-AUD-0 must catch a record whose details were tampered while
    self_hash was left unchanged. Pre-fix: I-AUD-1 checked signature presence
    but not chain integrity — a tampered checkpoint passed check_all_invariants."""
    from wpgovern.utils.invariants import check_all_invariants

    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success",
                details={"reason": "initial"})

    # Read and tamper a record's content while preserving self_hash
    log_path = cfg.root_dir / "audit" / "audit.log"
    lines = log_path.read_text().splitlines()
    records = [json.loads(l) for l in lines if l.strip()]

    # Tamper the first record's details
    records[0]["details"]["tampered"] = "injected"
    # Leave self_hash UNCHANGED (simulates hash-preservation attack)

    log_path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    violations = check_all_invariants(cfg)
    ids = {v.invariant_id for v in violations}
    assert "I-AUD-0" in ids, (
        "I-AUD-0 must detect that a record's self_hash no longer matches "
        "the record's actual content (tampered details, unchanged hash)"
    )


def test_mh1_iaud0_clean_chain_passes(env) -> None:
    """I-AUD-0 must not fire on a clean, untampered audit chain."""
    from wpgovern.utils.invariants import check_all_invariants

    cfg, _ = env
    logger = AuditLogger(config=cfg)
    logger.emit("baseline.create", "alice", "success")
    logger.emit("baseline.submit", "alice", "success")

    violations = check_all_invariants(cfg)
    aud0_violations = [v for v in violations if v.invariant_id == "I-AUD-0"]
    assert not aud0_violations, (
        f"I-AUD-0 must not fire on a clean chain. Got: {aud0_violations}"
    )


# ---------------------------------------------------------------------------
# M1 — Authorization:Basic, Cookie, OpenSSH detection
# ---------------------------------------------------------------------------

def test_m1_authorization_basic_in_list_rejected(env) -> None:
    """Authorization: Basic (any auth scheme, not just Bearer) must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": ["Authorization: Basic dXNlcjpwYXNz"]})


def test_m1_cookie_header_in_list_rejected(env) -> None:
    """Cookie: headers in nested lists must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": ["Cookie: sessionid=abc123secret"]})


def test_m1_openssh_private_key_rejected(env) -> None:
    """OpenSSH private key material must be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": {
                        "key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n"
                    }})


def test_m1_authorization_basic_in_dict_value_rejected(env) -> None:
    """Authorization: Basic in nested dict values must also be rejected."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    with pytest.raises(AuditError):
        logger.emit("baseline.create", "alice", "success",
                    details={"b4_event": {"auth_header": "Authorization: Basic dXNlcjpwYXNz"}})


def test_m1_clean_operator_text_accepted(env) -> None:
    """Operator prose mentioning authorization, cookies, etc. must not be blocked."""
    cfg, _ = env
    logger = AuditLogger(config=cfg)
    # This should NOT be rejected — it's operator prose describing a policy
    logger.emit("baseline.create", "alice", "success",
                details={"reason": "Updating authorization policy for cookie rotation"})
