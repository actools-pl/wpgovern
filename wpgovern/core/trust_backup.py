"""
WPGovern trust store backup and restore.

``create_trust_backup`` — creates an AES-256-CBC encrypted tarball of
the trust directory tree. The passphrase is supplied by the caller and
never stored on disk.

``restore_trust_backup`` — decrypts and unpacks the tarball back into
the trust directory. Performs content validation before committing the
restore; the existing trust directory is quarantined atomically so
restore failures leave the original intact.

Encryption uses ``openssl enc -aes-256-cbc -pbkdf2 -iter 600000``,
consistent with the openssl primitives already in use for signing.
The backup file is a standard OpenSSL-encrypted tarball and can be
decrypted manually if the wpgovern binary is unavailable.

Passphrase restriction (B-5)
-----------------------------
Passphrases containing ``\n``, ``\r``, or NUL are rejected at the API
level. ``openssl enc -pass stdin`` reads up to the first newline; a
passphrase like ``"correct\nhorse"`` silently uses only ``"correct"``
for key derivation, producing a weaker key without any error. The check
here protects callers using the Python API directly, not only the CLI.

Content validation (S-9)
-------------------------
After decryption and extraction, ``_validate_restored_trust`` checks that
each required trust store file contains a parseable JSON object with:
``type``, ``version``, a non-empty ``keys`` list, a non-empty
``active_key_id``, and all referenced public key files present on disk.
An empty ``{}`` or ``{"keys": []}`` file passes existence checks but
contains no usable key material; it is refused before the quarantine is
released.

KNOWN_LIMITS: this module provides the "operator can recover their own
deployment" layer. M-of-N Shamir secret sharing, air-gapped signing,
and HSM integration are out of scope for this reconstruction.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any


class TrustBackupError(Exception):
    """Raised when trust backup or restore fails in a recoverable way."""


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


def _openssl_encrypt(
    input_bytes: bytes,
    passphrase: str,
    iterations: int = 600000,
) -> bytes:
    """Encrypt ``input_bytes`` with AES-256-CBC / PBKDF2.

    Raises ``TrustBackupError`` if the passphrase contains newlines,
    carriage returns, or NUL bytes — these are silently truncated by
    ``openssl enc -pass stdin``, producing a weaker key than intended.
    """
    if any(ch in passphrase for ch in ("\n", "\r", "\x00")):
        raise TrustBackupError(
            "Passphrase must not contain newlines, carriage returns, or NUL "
            "bytes. These are silently truncated by openssl's passphrase "
            "reader, producing a weaker key than intended."
        )
    result = subprocess.run(
        [
            "openssl", "enc", "-aes-256-cbc",
            "-pbkdf2", "-iter", str(iterations),
            "-pass", "stdin",
        ],
        input=passphrase.encode("utf-8") + b"\n" + input_bytes,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise TrustBackupError(
            "openssl enc encryption failed: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    return result.stdout


def _openssl_decrypt(
    encrypted_bytes: bytes,
    passphrase: str,
    iterations: int = 600000,
) -> bytes:
    """Decrypt bytes produced by ``_openssl_encrypt``.

    Raises ``TrustBackupError`` on wrong passphrase or corrupt data.
    """
    result = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-256-cbc",
            "-pbkdf2", "-iter", str(iterations),
            "-pass", "stdin",
        ],
        input=passphrase.encode("utf-8") + b"\n" + encrypted_bytes,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise TrustBackupError(
            "Decryption failed — wrong passphrase or corrupt backup file. "
            "openssl: "
            + result.stderr.decode("utf-8", errors="replace").strip()
        )
    return result.stdout


# ---------------------------------------------------------------------------
# Archive helpers
# ---------------------------------------------------------------------------


def _tar_trust_dir(trust_dir: Path) -> bytes:
    """Create an in-memory tar.gz of the trust directory tree."""
    if not trust_dir.exists():
        raise TrustBackupError(
            f"Trust directory not found: {trust_dir}. Nothing to back up."
        )
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        with tarfile.open(tmp_path, "w:gz") as tar:
            tar.add(trust_dir, arcname="trust")
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)


def _untar_into(tar_bytes: bytes, target_root: Path) -> None:
    """Unpack tar.gz bytes into ``target_root``, with path-traversal guard."""
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = Path(tmp.name)
        tmp_path.write_bytes(tar_bytes)
    try:
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                member_path = Path(member.name)
                resolved = (target_root / member_path).resolve()
                try:
                    resolved.relative_to(target_root.resolve())
                except ValueError:
                    raise TrustBackupError(
                        f"Backup file contains suspicious path: {member.name}. "
                        "Restore aborted."
                    )
            tar.extractall(target_root, filter="data")
    finally:
        tmp_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


_REQUIRED_TRUST_STORES = (
    "runtime/public/trusted-runtime-keys.json",
    "release/public/trusted-release-keys.json",
    "journal/public/trusted-journal-keys.json",
)


def _validate_keypair(
    key_id: str, private_pem: Path, staging_pub_file: Path
) -> None:
    """Verify that the private key at ``private_pem`` matches the public key
    at ``staging_pub_file``. Raises ``TrustBackupError`` on mismatch or failure.
    Never silently ignores mismatches — fail-closed."""
    try:
        derived = subprocess.run(
            ["openssl", "pkey", "-pubout", "-in", str(private_pem)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        raise TrustBackupError(
            f"Backup private key validation failed for {key_id}: "
            f"openssl pkey failed: {exc.stderr.decode()[:200]}. "
            "Restore aborted. (H7)"
        ) from exc

    stored_pub = staging_pub_file.read_bytes()
    if derived.stdout.strip() != stored_pub.strip():
        raise TrustBackupError(
            f"Backup keypair mismatch for {key_id}: "
            "derived public key from private key does not match "
            "stored public key file. Possible key corruption or "
            "tampered backup. Restore aborted. (H7)"
        )


def _validate_restored_trust(trust_dir: Path, final_trust_dir: Path | None = None) -> None:
    """Raise ``TrustBackupError`` if the restored trust tree is incomplete or unsafe.

    Full contract:
    1. Required trust store files present and valid JSON.
    2. Every key path must be non-empty, a regular file (not directory), and
       resolve inside the staging trust directory. (H1, H2)
    3. Absolute paths rewritten to final destination. (H8)
    4. Active private key exists, mode 0o600, matches active public key. (H6, H7)
    5. Preactive private keys exist, mode 0o600, match their public keys. (H4)
       Retired/revoked keys: public key must be a valid file; private optional.
    6. Active private symlink created as relative target. (C1)
    7. Keypair validation is fail-closed: missing staging_pub raises, no OSError: pass.
    """
    dest_trust = final_trust_dir if final_trust_dir is not None else trust_dir
    DOMAIN_PRIVATE_DIRS = {
        "runtime/public/trusted-runtime-keys.json": "runtime/private",
        "release/public/trusted-release-keys.json":  "release/private",
        "journal/public/trusted-journal-keys.json":  "journal/private",
    }
    DOMAIN_SYMLINK_NAMES = {
        "runtime/public/trusted-runtime-keys.json": "runtime/private/active.pem",
        "release/public/trusted-release-keys.json":  "release/private/active.pem",
        "journal/public/trusted-journal-keys.json":  "journal/private/active.pem",
    }
    # Statuses requiring private key validation
    _NEEDS_PRIVATE_KEY = frozenset({"active", "preactive"})

    missing = [
        rel for rel in _REQUIRED_TRUST_STORES
        if not (trust_dir / rel).exists()
    ]
    if missing:
        raise TrustBackupError(
            "Backup is incomplete — missing required trust store files: "
            + ", ".join(missing)
            + ". Restore aborted; existing trust material is unchanged."
        )

    for rel in _REQUIRED_TRUST_STORES:
        path = trust_dir / rel
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise TrustBackupError(
                f"Backup trust store is not valid JSON: {rel}: {exc}. "
                "Restore aborted."
            ) from exc

        if not isinstance(content, dict):
            raise TrustBackupError(
                f"Backup trust store has unexpected format: {rel}. Restore aborted."
            )
        if not content.get("type"):
            raise TrustBackupError(
                f"Backup trust store missing 'type' field: {rel}. Restore aborted."
            )
        if "version" not in content:
            raise TrustBackupError(
                f"Backup trust store missing 'version' field: {rel}. Restore aborted."
            )
        keys = content.get("keys", [])
        if not isinstance(keys, list) or len(keys) == 0:
            raise TrustBackupError(
                f"Backup trust store has empty or missing 'keys' list: {rel}. "
                "A backup with no keys contains no usable material. Restore aborted."
            )
        active_key_id = content.get("active_key_id")
        if not active_key_id:
            raise TrustBackupError(
                f"Backup trust store has no active_key_id: {rel}. Restore aborted."
            )

        store_dir = path.parent
        staging_public_by_key_id: dict[str, Path] = {}

        for key_record in keys:
            if not isinstance(key_record, dict):
                continue

            key_id = key_record.get("key_id", "")
            key_path_str = key_record.get("path", "")
            key_status = key_record.get("status", "")

            # H1: reject empty/missing key paths — they are not valid file references.
            if not key_path_str:
                raise TrustBackupError(
                    f"Backup trust store key '{key_id}' in {rel} has empty "
                    "or missing 'path' field. All key records must reference "
                    "a public key file. Restore aborted. (H1)"
                )

            raw_key_file = Path(key_path_str)

            if raw_key_file.is_absolute():
                parts = raw_key_file.parts
                try:
                    trust_idx = list(parts).index("trust")
                    relative_parts = parts[trust_idx + 1:]
                    if not relative_parts:
                        raise ValueError("empty relative parts")
                    final_path = dest_trust / Path(*relative_parts)
                    key_record["path"] = str(final_path)
                    key_file = trust_dir / Path(*relative_parts)
                except (ValueError, TypeError):
                    raise TrustBackupError(
                        f"Backup trust store key path '{key_path_str}' is absolute "
                        "and does not contain a 'trust/' component. Cannot rewrite "
                        "to restored root. Restore aborted. (H8)"
                    )
            else:
                key_record["path"] = key_path_str
                key_file = store_dir / key_path_str

            # Verify the resolved path is inside the staging trust_dir.
            try:
                key_file.resolve().relative_to(trust_dir.resolve())
            except ValueError:
                raise TrustBackupError(
                    f"Backup trust store key path '{key_path_str}' resolves "
                    "outside the restored trust directory. Path escape not permitted. "
                    "Restore aborted. (H8)"
                )

            # H2: require a regular file, not a directory or symlink-to-dir.
            if not key_file.exists():
                raise TrustBackupError(
                    f"Backup trust store references missing key file: "
                    f"{key_path_str} (in {rel}). Restore aborted."
                )
            if not key_file.is_file():
                raise TrustBackupError(
                    f"Backup trust store key path '{key_path_str}' is not a regular "
                    "file (it may be a directory or special file). "
                    "Restore aborted. (H2)"
                )

            if key_id:
                staging_public_by_key_id[key_id] = key_file

        # Write back updated paths to the trust store file.
        path.write_text(json.dumps(content, indent=2) + "\n", encoding="utf-8")

        private_dir = trust_dir / DOMAIN_PRIVATE_DIRS[rel]

        # H6: active private key exists and has correct mode.
        active_pem = private_dir / f"{active_key_id}.pem"
        if not active_pem.exists():
            raise TrustBackupError(
                f"Backup for {rel}: active private key file missing: {active_pem}. "
                "Restore aborted. A backup without private keys is unusable. (H6)"
            )
        pem_mode = active_pem.stat().st_mode & 0o777
        if pem_mode != 0o600:
            try:
                os.chmod(active_pem, 0o600)
            except OSError as exc:
                raise TrustBackupError(
                    f"Backup private key {active_pem} has mode {oct(pem_mode)} "
                    f"and cannot be chmod 0o600: {exc}. Restore aborted."
                ) from exc

        # Active private symlink — relative target survives staging rename.
        symlink_path = trust_dir / DOMAIN_SYMLINK_NAMES[rel]
        symlink_target_relative = f"{active_key_id}.pem"
        if not symlink_path.exists() and not symlink_path.is_symlink():
            symlink_path.parent.mkdir(parents=True, exist_ok=True)
            symlink_path.symlink_to(symlink_target_relative)
        elif symlink_path.is_symlink():
            current_target = os.readlink(str(symlink_path))
            if current_target != symlink_target_relative:
                symlink_path.unlink()
                symlink_path.symlink_to(symlink_target_relative)

        # H7: active keypair validation — fail-closed.
        # H1: if active key is not in the map, raise immediately.
        staging_pub_file = staging_public_by_key_id.get(active_key_id)
        if staging_pub_file is None:
            raise TrustBackupError(
                f"Active key '{active_key_id}' has no public key file in the "
                f"staging trust map for {rel}. The key record may have an empty "
                "or invalid path. Restore aborted. (H1/H7)"
            )
        _validate_keypair(active_key_id, active_pem, staging_pub_file)

        # H4: validate all active/preactive keypairs — not just the active key.
        # A backup with missing or mismatched preactive private keys is accepted
        # now but breaks later when the operator tries to rotate to that key.
        for key_record in keys:
            if not isinstance(key_record, dict):
                continue
            key_id = key_record.get("key_id", "")
            key_status = key_record.get("status", "")
            if key_id == active_key_id:
                continue  # already validated above
            if key_status not in _NEEDS_PRIVATE_KEY:
                continue  # retired/revoked keys don't need private key material

            other_pem = private_dir / f"{key_id}.pem"
            if not other_pem.exists():
                raise TrustBackupError(
                    f"Backup for {rel}: {key_status} key '{key_id}' "
                    f"is missing its private key file {other_pem}. "
                    "Restore aborted. A backup must include private key material "
                    "for all active and preactive keys. (H4)"
                )
            other_mode = other_pem.stat().st_mode & 0o777
            if other_mode != 0o600:
                try:
                    os.chmod(other_pem, 0o600)
                except OSError as exc:
                    raise TrustBackupError(
                        f"Preactive private key {other_pem} has mode {oct(other_mode)} "
                        f"and cannot be chmod 0o600: {exc}. Restore aborted."
                    ) from exc
            other_pub = staging_public_by_key_id.get(key_id)
            if other_pub is None:
                raise TrustBackupError(
                    f"Preactive key '{key_id}' in {rel} has no public key file "
                    "in the staging trust map. Restore aborted. (H4)"
                )
            _validate_keypair(key_id, other_pem, other_pub)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_trust_backup(
    trust_dir: Path,
    output_path: Path,
    passphrase: str,
) -> dict[str, Any]:
    """Create an encrypted trust backup at ``output_path``.

    Returns a metadata dict with ``trust_dir``, ``output_path``,
    ``size_bytes``, ``encrypted``, ``algorithm``.

    Raises ``TrustBackupError`` if the passphrase contains newlines,
    or if the trust directory does not exist.
    """
    tar_bytes = _tar_trust_dir(trust_dir)
    encrypted = _openssl_encrypt(tar_bytes, passphrase)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypted)
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass

    return {
        "trust_dir": str(trust_dir),
        "output_path": str(output_path),
        "size_bytes": len(encrypted),
        "encrypted": True,
        "algorithm": "aes-256-cbc-pbkdf2",
        "note": (
            "Store this file securely offline. It contains private key material. "
            "Manual decryption: openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 "
            "-in <backup> | tar -xz -C <dest>"
        ),
    }


def restore_trust_backup(
    input_path: Path,
    target_root: Path,
    passphrase: str,
    force: bool = False,
) -> dict[str, Any]:
    """Restore a trust backup from ``input_path`` into ``target_root``.

    ``target_root`` is the WPGovern root; the trust tree is restored to
    ``<target_root>/trust/``.

    ``force=False`` (default) refuses to overwrite an existing trust
    directory. ``force=True`` replaces it atomically:

    1. Decrypt and extract into a staging directory.
    2. Validate content (``_validate_restored_trust``).
    3. Quarantine the existing trust directory (rename aside).
    4. Move the staged tree into place.
    5. On any failure after step 3, restore from quarantine.
    6. On success, discard the quarantine.

    This guarantees no stale, revoked, or attacker-added files survive
    the restore, and the existing trust material is preserved on failure.
    """
    trust_dir = target_root / "trust"
    if trust_dir.exists() and not force:
        raise TrustBackupError(
            f"Trust directory already exists at {trust_dir}. "
            "Use --force to overwrite. CAUTION: this will replace all "
            "current trust material including private keys."
        )

    if not input_path.exists():
        raise TrustBackupError(f"Backup file not found: {input_path}")

    encrypted = input_path.read_bytes()
    tar_bytes = _openssl_decrypt(encrypted, passphrase)

    staging_parent = target_root / ".trust_restore_staging"
    staging_parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(dir=staging_parent))

    try:
        _untar_into(tar_bytes, staging_dir)
        staged_trust = staging_dir / "trust"

        # C1 fix: pass the FINAL trust_dir so paths are rewritten to the
        # final location, not the staging directory. Paths written during
        # validation must be valid AFTER staged_trust.rename(trust_dir).
        _validate_restored_trust(staged_trust, final_trust_dir=trust_dir)

        quarantine: Path | None = None
        if trust_dir.exists():
            quarantine = staging_parent / "quarantine"
            if quarantine.exists():
                shutil.rmtree(quarantine, ignore_errors=True)
            trust_dir.rename(quarantine)

        try:
            staged_trust.rename(trust_dir)
        except Exception as exc:
            if quarantine is not None and quarantine.exists():
                quarantine.rename(trust_dir)
            raise TrustBackupError(
                f"Failed to move restored trust material into place: {exc}"
            ) from exc

        # C1 fix: validate AFTER the rename so paths point to the real final
        # location. If validation fails, restore the quarantine.
        try:
            from wpgovern.core.trust import TrustService
            from wpgovern.config import WPGovernConfig as _WGC
            _cfg = _WGC(root_dir=target_root)
            _trust = TrustService(config=_cfg)
            for domain in ("runtime", "release", "journal"):
                try:
                    _trust.validate_store(domain)
                except Exception as exc:
                    raise TrustBackupError(
                        f"Restored trust store validation failed for domain "
                        f"'{domain}': {exc}. Restore aborted."
                    ) from exc
        except TrustBackupError:
            # Restore the quarantine before re-raising
            if quarantine is not None and quarantine.exists():
                if trust_dir.exists():
                    shutil.rmtree(trust_dir, ignore_errors=True)
                quarantine.rename(trust_dir)
            raise

        if quarantine is not None and quarantine.exists():
            shutil.rmtree(quarantine, ignore_errors=True)

    finally:
        shutil.rmtree(staging_parent, ignore_errors=True)

    return {
        "restored_to": str(trust_dir),
        "backup_source": str(input_path),
        "trust_dir_exists": trust_dir.exists(),
    }
