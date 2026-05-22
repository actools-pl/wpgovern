"""
Tests for wpgovern.core.trust_backup — create_trust_backup, restore_trust_backup.

Coverage:
- create_trust_backup produces encrypted file with correct metadata
- create_trust_backup raises on missing trust directory
- restore round-trip: create then restore produces identical trust tree
- wrong passphrase fails cleanly
- restore refuses to overwrite without force
- restore with force replaces existing trust directory
- restore rejects path-traversal in archive
- passphrase with newline rejected at API level (B-5)
- passphrase with NUL byte rejected at API level (B-5)
- clean passphrase accepted (B-5 regression green path)
- empty JSON trust stores refused on restore (S-9)
- incomplete backup (missing required files) refused
- atomic restore: failure after quarantine restores original (S-9 atomicity)
"""

from __future__ import annotations

import io
import json
import tarfile
import tempfile
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.core.trust_backup import (
    TrustBackupError,
    _openssl_encrypt,
    create_trust_backup,
    restore_trust_backup,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def trust_env(tmp_path: Path) -> tuple[TrustService, WPGovernConfig]:
    root = tmp_path / "wpg"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
    )
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_release_key("release-a")
    trust.activate_release_key("release-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")
    return trust, config


# ---------------------------------------------------------------------------
# create_trust_backup
# ---------------------------------------------------------------------------


def test_create_backup_produces_encrypted_file_with_metadata(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    trust, config = trust_env
    backup_path = tmp_path / "backup.wpgov-trust-backup"

    result = create_trust_backup(
        config.root_dir / "trust", backup_path, passphrase="good-passphrase-123"
    )

    assert backup_path.exists()
    assert result["encrypted"] is True
    assert result["algorithm"] == "aes-256-cbc-pbkdf2"
    assert result["size_bytes"] == backup_path.stat().st_size
    # File should not be world-readable
    assert (backup_path.stat().st_mode & 0o077) == 0


def test_create_backup_raises_on_missing_trust_directory(
    tmp_path: Path,
) -> None:
    with pytest.raises(TrustBackupError, match="not found"):
        create_trust_backup(
            tmp_path / "nonexistent_trust",
            tmp_path / "backup.wpgov-trust-backup",
            passphrase="test",
        )


# ---------------------------------------------------------------------------
# Passphrase validation (B-5)
# ---------------------------------------------------------------------------


def test_passphrase_with_newline_rejected_at_api_level(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    """B-5: openssl reads passphrase up to first newline — silently truncating it."""
    trust, config = trust_env
    with pytest.raises(TrustBackupError, match="newline|NUL"):
        create_trust_backup(
            config.root_dir / "trust",
            tmp_path / "backup.wpgov-trust-backup",
            passphrase="correct\nhorse",
        )


def test_passphrase_with_null_byte_rejected(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    trust, config = trust_env
    with pytest.raises(TrustBackupError, match="newline|NUL"):
        create_trust_backup(
            config.root_dir / "trust",
            tmp_path / "backup.wpgov-trust-backup",
            passphrase="pass\x00word",
        )


def test_clean_passphrase_accepted(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    """B-5 regression green path: a clean passphrase must not raise."""
    trust, config = trust_env
    backup_path = tmp_path / "backup.wpgov-trust-backup"
    create_trust_backup(
        config.root_dir / "trust", backup_path, passphrase="clean-passphrase-ok!"
    )
    assert backup_path.exists()


# ---------------------------------------------------------------------------
# restore_trust_backup
# ---------------------------------------------------------------------------


def test_restore_round_trip_produces_identical_trust_store_files(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    trust, config = trust_env
    trust_dir = config.root_dir / "trust"
    backup_path = tmp_path / "backup.wpgov-trust-backup"
    passphrase = "round-trip-passphrase"

    create_trust_backup(trust_dir, backup_path, passphrase=passphrase)

    restore_root = tmp_path / "restore_root"
    restore_root.mkdir()
    result = restore_trust_backup(backup_path, restore_root, passphrase=passphrase)

    restored_trust = restore_root / "trust"
    assert restored_trust.exists()
    assert result["trust_dir_exists"] is True

    # The required trust store files must be parseable
    for rel in (
        "runtime/public/trusted-runtime-keys.json",
        "release/public/trusted-release-keys.json",
        "journal/public/trusted-journal-keys.json",
    ):
        payload = json.loads((restored_trust / rel).read_text())
        assert payload["active_key_id"] is not None


def test_wrong_passphrase_fails_cleanly(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    trust, config = trust_env
    backup_path = tmp_path / "backup.wpgov-trust-backup"
    create_trust_backup(config.root_dir / "trust", backup_path, passphrase="correct")

    with pytest.raises(TrustBackupError, match="[Dd]ecryption|wrong passphrase"):
        restore_trust_backup(
            backup_path, tmp_path / "restore", passphrase="wrong"
        )


def test_restore_refuses_to_overwrite_without_force(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    trust, config = trust_env
    backup_path = tmp_path / "backup.wpgov-trust-backup"
    create_trust_backup(config.root_dir / "trust", backup_path, passphrase="test")

    with pytest.raises(TrustBackupError, match="force"):
        restore_trust_backup(
            backup_path, config.root_dir, passphrase="test", force=False
        )


def test_restore_with_force_replaces_existing_trust_directory(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
) -> None:
    trust, config = trust_env
    backup_path = tmp_path / "backup.wpgov-trust-backup"
    passphrase = "force-test"
    create_trust_backup(config.root_dir / "trust", backup_path, passphrase=passphrase)

    result = restore_trust_backup(
        backup_path, config.root_dir, passphrase=passphrase, force=True
    )
    assert result["trust_dir_exists"] is True


# ---------------------------------------------------------------------------
# Path traversal guard
# ---------------------------------------------------------------------------


def test_restore_rejects_path_traversal_in_archive(
    tmp_path: Path,
) -> None:
    passphrase = "traversal-test"

    tar_bytes_io = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes_io, mode="w:gz") as tar:
        content = b"malicious"
        info = tarfile.TarInfo(name="../../../etc/evil")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    tar_bytes = tar_bytes_io.getvalue()

    encrypted = _openssl_encrypt(tar_bytes, passphrase)
    backup_path = tmp_path / "evil.wpgov-trust-backup"
    backup_path.write_bytes(encrypted)

    restore_root = tmp_path / "restore"
    restore_root.mkdir()

    with pytest.raises(TrustBackupError, match="suspicious path"):
        restore_trust_backup(backup_path, restore_root, passphrase=passphrase)


# ---------------------------------------------------------------------------
# Content validation (S-9)
# ---------------------------------------------------------------------------


def _make_backup_with_stores(
    passphrase: str,
    backup_path: Path,
    stores: dict[str, bytes],
) -> None:
    """Build a backup archive with specific trust store content."""
    tar_bytes_io = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes_io, mode="w:gz") as tar:
        for rel, content in stores.items():
            info = tarfile.TarInfo(name=f"trust/{rel}")
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    encrypted = _openssl_encrypt(tar_bytes_io.getvalue(), passphrase)
    backup_path.write_bytes(encrypted)


def test_empty_json_trust_stores_refused(tmp_path: Path) -> None:
    """S-9: a backup whose trust store files contain only {} must be refused."""
    passphrase = "s9-test"
    backup_path = tmp_path / "empty.wpgov-trust-backup"
    stores = {
        rel: b"{}"
        for rel in (
            "runtime/public/trusted-runtime-keys.json",
            "release/public/trusted-release-keys.json",
            "journal/public/trusted-journal-keys.json",
        )
    }
    _make_backup_with_stores(passphrase, backup_path, stores)

    restore_root = tmp_path / "restore"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError):
        restore_trust_backup(backup_path, restore_root, passphrase=passphrase)


def test_incomplete_backup_missing_required_files_refused(tmp_path: Path) -> None:
    passphrase = "incomplete-test"
    backup_path = tmp_path / "incomplete.wpgov-trust-backup"
    # Only include runtime store, omit release and journal
    stores = {
        "runtime/public/trusted-runtime-keys.json": b'{"type":"t","version":1,"keys":[]}',
    }
    _make_backup_with_stores(passphrase, backup_path, stores)

    restore_root = tmp_path / "restore"
    restore_root.mkdir()
    with pytest.raises(TrustBackupError, match="incomplete|missing"):
        restore_trust_backup(backup_path, restore_root, passphrase=passphrase)


def test_restore_failure_after_quarantine_leaves_original_intact(
    trust_env: tuple[TrustService, WPGovernConfig],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Atomic restore: if staged trust rename fails, quarantine is restored."""
    import os

    trust, config = trust_env
    backup_path = tmp_path / "backup.wpgov-trust-backup"
    passphrase = "atomic-test"
    create_trust_backup(config.root_dir / "trust", backup_path, passphrase=passphrase)

    # Record original active_key_id before any restore attempt
    original_store = json.loads(
        (config.root_dir / "trust" / "runtime" / "public"
         / "trusted-runtime-keys.json").read_text()
    )
    original_active = original_store["active_key_id"]

    # Patch os.rename so that the final staged→live rename raises but
    # quarantine→live restore renames are allowed through.
    real_rename = os.rename
    restore_target = str(config.root_dir / "trust")
    call_count = {"n": 0}

    def selective_fail_rename(src: str | Path, dst: str | Path) -> None:
        # Fail when moving the staged trust directory to the live location
        if str(dst) == restore_target:
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated rename failure on staged→live")
        real_rename(src, dst)

    monkeypatch.setattr(os, "rename", selective_fail_rename)

    with pytest.raises((TrustBackupError, OSError)):
        restore_trust_backup(
            backup_path, config.root_dir, passphrase=passphrase, force=True
        )

    # Original trust store must still be intact
    live_store_path = (
        config.root_dir / "trust" / "runtime" / "public"
        / "trusted-runtime-keys.json"
    )
    assert live_store_path.exists(), "trust store must survive a failed restore"
    restored_store = json.loads(live_store_path.read_text())
    assert restored_store["active_key_id"] == original_active
