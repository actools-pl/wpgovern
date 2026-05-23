"""
Crash-recovery journal — write path.

Companion to ``utils/recovery.py``, which reads what this module writes.
The two halves communicate exclusively through on-disk state under
``state/.journal/``. There is no in-process handoff.

Directory layout under ``<root>/state/.journal/``::

    <txn-id>.intent              # written before the os.replace loop
    <txn-id>.complete            # written after the os.replace loop succeeds
    backups/<txn-id>/<sha256>    # content-addressed pre-replace bytes
    recovery-reports/<txn-id>.json   # forensic files written by recovery
    audit-emit-failures/...          # fallback when recovery audit emit fails

Journal records use ``schema_version=2``: intent and complete records are
signed with the active journal-domain key. Recovery refuses unsigned
(schema_version=1) records during normal startup — only the operator-driven
``migrate-journal-v1-to-v2`` command acts on v1 records.

Schema versions
---------------
* 1 — unsigned records (hash-integrity only). Written by pre-signing deploys.
  Legacy. Normal recovery refuses v1 records.
* 2 — signed records. Written by every AtomicTransaction with a service_label
  since the journal trust store was bootstrapped.

Integrity model
---------------
``intent_integrity_hash`` — SHA-256 of the canonical-JSON of the record
excluding the hash and signature fields. Detects accidental corruption and
simple tamper attacks. Recovery refuses on mismatch.

``intent_signature`` — ed25519 signature over the same canonical-JSON bytes
(the signing input). This authenticates the record: recovery refuses if the
signature does not verify against a known, non-revoked journal key. The
signature gate runs before the integrity hash check in the recovery sequence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from wpgovern.errors import WPGovernError, _classify_oserror


JOURNAL_SCHEMA_VERSION = 2


class JournalError(WPGovernError):
    """Raised when journal I/O fails in a way the caller must propagate."""


class JournalSignatureError(JournalError):
    """Raised when a journal record signature cannot be produced or verified.

    Distinct from JournalError so recovery can map signature failures to
    specific refusal reasons.
    """


# ---------------------------------------------------------------------------
# Verification result constants
#
# Returned by verify_intent_signature() and verify_complete_signature().
# Recovery maps each constant to a specific refusal reason per design §5.
# ---------------------------------------------------------------------------

VERIFY_OK = "ok"
VERIFY_SIGNATURE_MISSING = "signature_missing"
VERIFY_KEY_ID_MISSING = "key_id_missing"
VERIFY_KEY_UNKNOWN = "key_unknown"
VERIFY_KEY_REVOKED = "key_revoked"
VERIFY_SIGNATURE_INVALID = "signature_invalid"


# ---------------------------------------------------------------------------
# Record dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IntentWrite:
    """One target write inside a commit's intent record.

    ``old_content_hash`` is None when the target did not exist before the
    commit (first-write target). On rollback, a None old_content_hash means
    delete the file if it exists.

    The ``staged`` field records the staging path at intent-write time and
    is included in the signed payload for forensic visibility, but is NOT
    consulted by recovery — which reads exclusively from the content-
    addressed backup store.
    """

    target: str
    staged: str
    old_content_hash: str | None
    new_content_hash: str
    mode: int


@dataclass(frozen=True)
class IntentSymlink:
    """One symlink replacement inside a commit's intent record.

    Records the symlink path, the new relative target, and the prior target
    (for rollback — if recovery sees JSON committed but symlink not yet
    updated, it can repair the symlink to ``target_name``; if it sees the
    symlink was already replaced but commit failed partway, it can roll back
    to ``prior_target`` if defined).
    """

    symlink_path: str
    target_name: str        # relative target name (e.g. "runtime-2.pem")
    prior_target: str | None  # previous target name before this commit


@dataclass
class IntentRecord:
    """Per-transaction intent record. Written before the os.replace loop.

    Fields ``intent_integrity_hash``, ``intent_signature``, and
    ``intent_signature_key_id`` are excluded from each other's computation:

    * The integrity hash is SHA-256 of canonical-JSON of every other field.
    * The signature is over the same canonical-JSON bytes.

    This means the integrity hash is stable across the signing operation,
    and signing does not invalidate the integrity hash.

    ``deletes`` lists target paths that must be unlinked as part of the
    commit. Recorded here so recovery can determine whether a pending
    delete has already executed (target absent) or still needs to
    execute (target present), and act accordingly.

    ``symlinks`` lists symlink replacements that must be applied as part of
    the commit. Recorded here so recovery can determine whether a symlink
    was already replaced (target matches new target_name) or still needs
    to be replaced. This makes symlink replacements first-class journaled
    artifacts — recovery can repair or roll back them correctly.
    """

    txn_id: str
    started_at: str
    service: str
    actor_id: str | None
    writes: list[IntentWrite]
    deletes: list[str] = field(default_factory=list)
    symlinks: list[IntentSymlink] = field(default_factory=list)
    schema_version: int = JOURNAL_SCHEMA_VERSION
    intent_integrity_hash: str = ""
    intent_signature: str = ""
    intent_signature_key_id: str = ""

    def without_integrity_hash(self) -> dict[str, Any]:
        """Return the record as a dict excluding the three signing-related fields."""
        payload = asdict(self)
        payload.pop("intent_integrity_hash", None)
        payload.pop("intent_signature", None)
        payload.pop("intent_signature_key_id", None)
        return payload

    def signing_input(self) -> bytes:
        """Canonical-JSON bytes used as input to signature computation."""
        return _canonical_json_bytes(self.without_integrity_hash())

    def as_dict(self) -> dict[str, Any]:
        payload = self.without_integrity_hash()
        payload["intent_integrity_hash"] = self.intent_integrity_hash
        payload["intent_signature"] = self.intent_signature
        payload["intent_signature_key_id"] = self.intent_signature_key_id
        return payload


@dataclass
class CompleteRecord:
    """Per-transaction complete record. Written after the last os.replace."""

    txn_id: str
    completed_at: str
    schema_version: int = JOURNAL_SCHEMA_VERSION
    complete_signature: str = ""
    complete_signature_key_id: str = ""

    def signing_input(self) -> bytes:
        payload = asdict(self)
        payload.pop("complete_signature", None)
        payload.pop("complete_signature_key_id", None)
        return _canonical_json_bytes(payload)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fsync_dir(path: Path) -> None:
    """fsync a directory. Silently no-op on platforms that don't support it."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def compute_intent_integrity_hash(record: IntentRecord) -> str:
    """SHA-256 of the canonical-JSON of the intent record excluding the
    integrity-hash and signature fields.

    Detects accidental corruption and simple tamper attacks. Recovery
    refuses on mismatch after the signature gate has passed.
    """
    return hashlib.sha256(_canonical_json_bytes(record.without_integrity_hash())).hexdigest()


def hash_file_bytes(path: Path) -> str:
    """SHA-256 hex of a file's bytes."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_and_hash_file(path: Path) -> tuple[bytes, str]:
    """Read the entire file into memory and compute its SHA-256 in a single
    open. Returns (bytes, sha256_hex).

    Single-read prevents TOCTOU between the hash computation and any
    subsequent use of the bytes — the bytes we hash are the bytes we operate
    on.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        data = fh.read()
    h.update(data)
    return data, h.hexdigest()


# ---------------------------------------------------------------------------
# openssl ed25519 signing / verification
# ---------------------------------------------------------------------------


def _openssl_sign_bytes(data: bytes, private_key_path: Path) -> bytes:
    """Sign bytes with ed25519 via openssl pkeyutl. Returns raw signature bytes.

    η-4: uses TemporaryDirectory so input and output files are in a private
    directory with non-predictable path — eliminates the symlink-race window
    from NamedTemporaryFile + deterministic adjacent path patterns.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wpgovern_jsign_") as _tmpdir:
        in_path = Path(_tmpdir) / "data.bin"
        out_path = Path(_tmpdir) / "sig.bin"
        in_path.write_bytes(data)
        try:
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign",
                    "-inkey", str(private_key_path),
                    "-rawin",
                    "-in", str(in_path),
                    "-out", str(out_path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
            return out_path.read_bytes()
        except subprocess.TimeoutExpired as exc:
            raise JournalSignatureError(
                f"openssl pkeyutl -sign timed out after {exc.timeout}s"
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise JournalSignatureError(
                f"openssl pkeyutl -sign failed: {stderr.strip() or exc}"
            ) from exc


def _openssl_verify_bytes(data: bytes, signature: bytes, public_key_path: Path) -> bool:
    """Verify ed25519 signature over bytes via openssl pkeyutl.

    Returns True on valid signature, False on cryptographic verification failure.
    Raises JournalSignatureError only for environmental failures (openssl not
    found, public key file missing).

    η-4: uses TemporaryDirectory — same private-directory pattern as sign.
    """
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wpgovern_jverify_") as _tmpdir:
        in_path = Path(_tmpdir) / "data.bin"
        sig_path = Path(_tmpdir) / "sig.bin"
        in_path.write_bytes(data)
        sig_path.write_bytes(signature)
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify",
                "-pubin",
                "-inkey", str(public_key_path),
                "-rawin",
                "-in", str(in_path),
                "-sigfile", str(sig_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        return result.returncode == 0


# ---------------------------------------------------------------------------
# Signing helpers — called from AtomicTransaction and from signing tests
# ---------------------------------------------------------------------------


def _sign_intent_record_under_lock(record: IntentRecord, trust_service: Any) -> None:
    """Sign an IntentRecord assuming the journal-trust lock is already held."""
    from wpgovern.errors import IntegrityError, NotFoundError

    try:
        trust_service.verify_journal_trust()
    except Exception as exc:
        raise JournalSignatureError(
            f"journal trust store unhealthy: {exc}. "
            "Cannot sign intent records until the trust store is repaired."
        ) from exc
    try:
        private_key_path = trust_service.active_private_key_path("journal")
    except (Exception,) as exc:
        raise JournalSignatureError(
            "no active journal signing key — run "
            "`wpgovern bootstrap-journal-key`"
        ) from exc
    key_id = private_key_path.stem
    sig_bytes = _openssl_sign_bytes(record.signing_input(), private_key_path)
    record.intent_signature = base64.b64encode(sig_bytes).decode("ascii")
    record.intent_signature_key_id = key_id


def sign_intent_record(record: IntentRecord, trust_service: Any) -> None:
    """Sign an IntentRecord in place using the active journal-domain key.

    Acquires the journal-trust lock for the duration of key-lookup + sign,
    serializing against key-compromise-journal rotation.

    Raises JournalSignatureError if no active journal key exists, the trust
    store is corrupt, or openssl signing fails.
    """
    with trust_service.lock_manager.acquire("journal-trust"):
        _sign_intent_record_under_lock(record, trust_service)


def _sign_complete_record_under_lock(record: CompleteRecord, trust_service: Any) -> None:
    """Sign a CompleteRecord assuming the journal-trust lock is already held."""
    try:
        trust_service.verify_journal_trust()
    except Exception as exc:
        raise JournalSignatureError(
            f"journal trust store unhealthy: {exc}."
        ) from exc
    try:
        private_key_path = trust_service.active_private_key_path("journal")
    except Exception as exc:
        raise JournalSignatureError(
            "no active journal signing key"
        ) from exc
    key_id = private_key_path.stem
    sig_bytes = _openssl_sign_bytes(record.signing_input(), private_key_path)
    record.complete_signature = base64.b64encode(sig_bytes).decode("ascii")
    record.complete_signature_key_id = key_id


def sign_complete_record(record: CompleteRecord, trust_service: Any) -> None:
    """Sign a CompleteRecord in place. Same construction as sign_intent_record."""
    with trust_service.lock_manager.acquire("journal-trust"):
        _sign_complete_record_under_lock(record, trust_service)


def verify_intent_signature(record: IntentRecord, trust_service: Any) -> str:
    """Verify the signature on an IntentRecord.

    Returns one of the VERIFY_* constants. Checks in order:
    1. Signature field present and non-empty.
    2. Key-id field present and non-empty.
    3. Key-id resolves in the journal trust store.
    4. Key is not revoked (active and retired_verify_only are accepted).
    5. Signature verifies cryptographically.
    """
    if not record.intent_signature:
        return VERIFY_SIGNATURE_MISSING
    if not record.intent_signature_key_id:
        return VERIFY_KEY_ID_MISSING

    key_id = record.intent_signature_key_id

    from wpgovern.errors import IntegrityError, NotFoundError
    try:
        public_key_path = trust_service.public_key_for_key_id("journal", key_id)
    except (IntegrityError, NotFoundError, Exception):
        return VERIFY_KEY_UNKNOWN

    status = trust_service.key_status("journal", key_id)
    if status == "revoked":
        return VERIFY_KEY_REVOKED

    try:
        sig_bytes = base64.b64decode(record.intent_signature, validate=True)
    except Exception:
        return VERIFY_SIGNATURE_INVALID

    if not _openssl_verify_bytes(record.signing_input(), sig_bytes, public_key_path):
        return VERIFY_SIGNATURE_INVALID

    return VERIFY_OK


def verify_complete_signature(record: CompleteRecord, trust_service: Any) -> str:
    """Verify the signature on a CompleteRecord. Same return shape as verify_intent_signature."""
    if not record.complete_signature:
        return VERIFY_SIGNATURE_MISSING
    if not record.complete_signature_key_id:
        return VERIFY_KEY_ID_MISSING

    key_id = record.complete_signature_key_id
    from wpgovern.errors import IntegrityError, NotFoundError
    try:
        public_key_path = trust_service.public_key_for_key_id("journal", key_id)
    except Exception:
        return VERIFY_KEY_UNKNOWN

    status = trust_service.key_status("journal", key_id)
    if status == "revoked":
        return VERIFY_KEY_REVOKED

    try:
        sig_bytes = base64.b64decode(record.complete_signature, validate=True)
    except Exception:
        return VERIFY_SIGNATURE_INVALID

    if not _openssl_verify_bytes(record.signing_input(), sig_bytes, public_key_path):
        return VERIFY_SIGNATURE_INVALID

    return VERIFY_OK


# ---------------------------------------------------------------------------
# JournalWriter
# ---------------------------------------------------------------------------


class JournalWriter:
    """Writes intent/complete records and the content-addressed backup store.

    Used by AtomicTransaction.commit() when a service_label is provided.
    The sequence is:

        snapshot_old_targets()  →  write_intent()  →  [os.replace loop]
                                →  write_complete()  →  cleanup_completed()

    All filesystem mutations are durable: each file write is fsynced,
    each directory mutation is fsynced.

    Args:
        root_dir: The WPGovern root directory (the directory containing
            ``state/``).
    """

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = Path(root_dir)
        self.journal_dir = self.root_dir / "state" / ".journal"
        self.backups_dir = self.journal_dir / "backups"
        self.recovery_reports_dir = self.journal_dir / "recovery-reports"
        self.audit_emit_failures_dir = self.journal_dir / "audit-emit-failures"

    def ensure_dirs(self) -> None:
        """Create the journal directory tree with mode 0700."""
        for directory in (
            self.journal_dir,
            self.backups_dir,
            self.recovery_reports_dir,
            self.audit_emit_failures_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass  # best-effort on filesystems without chmod support

    def snapshot_old_targets(
        self,
        writes: Iterable[IntentWrite],
        txn_id: str,
        target_bytes: dict[str, bytes] | None = None,
    ) -> None:
        """Snapshot pre-replace target bytes to the content-addressed backup store.

        For each write with a non-None ``old_content_hash``, copies the
        pre-replace bytes to ``backups/<txn_id>/<sha256>``. First-write
        targets (``old_content_hash is None``) produce no backup — rollback
        for them is by deletion.

        Each backup file is individually fsynced after write, and the
        per-transaction backup directory is fsynced after all files are written.

        When ``target_bytes`` is provided (a mapping of target-path string →
        pre-read file content), the backup is written from those bytes rather
        than re-reading the target. This closes the TOCTOU window between
        hash computation and snapshot copy.
        """
        self.ensure_dirs()
        per_txn_backup_dir = self.backups_dir / txn_id
        per_txn_backup_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(per_txn_backup_dir, 0o700)
        except OSError:
            pass

        wrote_anything = False
        for write in writes:
            if write.old_content_hash is None:
                continue  # first-write target — no backup needed

            target_path = Path(write.target)
            bytes_to_write: bytes | None = None
            if target_bytes is not None:
                bytes_to_write = target_bytes.get(str(target_path))

            backup_path = per_txn_backup_dir / write.old_content_hash
            if backup_path.exists():
                continue  # content-addressed dedup — same bytes already stored

            if bytes_to_write is not None:
                with backup_path.open("wb") as fh:
                    fh.write(bytes_to_write)
                    fh.flush()
                    os.fsync(fh.fileno())
            else:
                if not target_path.exists():
                    raise JournalError(
                        f"Cannot snapshot {target_path}: file missing despite "
                        f"recorded old_content_hash={write.old_content_hash}"
                    )
                with backup_path.open("wb") as fh:
                    with target_path.open("rb") as src:
                        shutil.copyfileobj(src, fh)
                    fh.flush()
                    os.fsync(fh.fileno())

            try:
                os.chmod(backup_path, 0o600)
            except OSError:
                pass
            wrote_anything = True

        if wrote_anything:
            _fsync_dir(per_txn_backup_dir)

    def write_intent(self, record: IntentRecord) -> Path:
        """Atomically write the intent record to ``<journal>/<txn>.intent``.

        Sets ``record.intent_integrity_hash`` if not already populated.
        Uses stage-then-os.replace for atomicity. Fsyncs file and parent dir.

        B4 errors (ENOSPC, EROFS, EACCES) are classified and re-raised as
        the appropriate B4Error subclass.
        """
        self.ensure_dirs()
        if not record.intent_integrity_hash:
            record.intent_integrity_hash = compute_intent_integrity_hash(record)
        else:
            recomputed = compute_intent_integrity_hash(record)
            if recomputed != record.intent_integrity_hash:
                raise JournalError(
                    "Pre-set intent_integrity_hash does not match recomputation"
                )

        final_path = self.journal_dir / f"{record.txn_id}.intent"
        staged_path = self.journal_dir / f"{record.txn_id}.intent.staged"
        payload = json.dumps(record.as_dict(), indent=2, sort_keys=True) + "\n"

        try:
            with staged_path.open("w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            classified = _classify_oserror(exc, staged_path, "intent_write")
            if classified is not None:
                raise classified from exc
            raise
        try:
            os.chmod(staged_path, 0o600)
        except OSError:
            pass
        try:
            os.replace(staged_path, final_path)
            _fsync_dir(self.journal_dir)
        except OSError as exc:
            try:
                staged_path.unlink(missing_ok=True)
            except OSError:
                pass
            classified = _classify_oserror(exc, final_path, "intent_write")
            if classified is not None:
                raise classified from exc
            raise
        return final_path

    def write_complete(self, txn_id: str, trust_service: Any = None) -> Path:
        """Atomically write the complete record after the os.replace loop.

        When ``trust_service`` is provided, the record is signed. When None,
        the record is written unsigned — used during testing and during the
        bootstrap window before the journal trust store has an active key.
        """
        self.ensure_dirs()
        record = CompleteRecord(txn_id=txn_id, completed_at=_utcnow())
        if trust_service is not None:
            sign_complete_record(record, trust_service)

        final_path = self.journal_dir / f"{txn_id}.complete"
        staged_path = self.journal_dir / f"{txn_id}.complete.staged"
        payload = json.dumps(record.as_dict(), indent=2, sort_keys=True) + "\n"

        try:
            with staged_path.open("w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            classified = _classify_oserror(exc, staged_path, "complete_write")
            if classified is not None:
                raise classified from exc
            raise
        try:
            os.chmod(staged_path, 0o600)
        except OSError:
            pass
        try:
            os.replace(staged_path, final_path)
            _fsync_dir(self.journal_dir)
        except OSError as exc:
            try:
                staged_path.unlink(missing_ok=True)
            except OSError:
                pass
            classified = _classify_oserror(exc, final_path, "complete_write")
            if classified is not None:
                raise classified from exc
            raise
        return final_path

    def cleanup_completed(self, txn_id: str) -> None:
        """Remove all journal artefacts for a successfully completed transaction.

        Best-effort: if interrupted, the next recovery run sees the orphaned
        intent+complete pair and cleans it up. Recovery correctness does not
        depend on this step having run.
        """
        for filename in (f"{txn_id}.intent", f"{txn_id}.complete"):
            path = self.journal_dir / filename
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass
        per_txn_backup_dir = self.backups_dir / txn_id
        if per_txn_backup_dir.exists():
            shutil.rmtree(per_txn_backup_dir, ignore_errors=True)
        _fsync_dir(self.journal_dir)
        if self.backups_dir.exists():
            _fsync_dir(self.backups_dir)


# ---------------------------------------------------------------------------
# Read helpers — used by RecoveryService and transaction-status
# ---------------------------------------------------------------------------


def list_intent_records(journal_dir: Path) -> list[Path]:
    """List all ``*.intent`` files in the journal directory."""
    if not journal_dir.exists():
        return []
    return sorted(journal_dir.glob("*.intent"))


def list_complete_records(journal_dir: Path) -> list[Path]:
    """List all ``*.complete`` files in the journal directory."""
    if not journal_dir.exists():
        return []
    return sorted(journal_dir.glob("*.complete"))


def read_intent_record(path: Path) -> IntentRecord:
    """Load an intent record from disk. Does not verify integrity hash or signature.

    Raises JournalSchemaError if schema_version is missing or doesn't match
    the current version. Legacy v1 records (no schema_version field) are not
    supported — the error message names the actual problem for operator clarity.
    """
    from wpgovern.errors import JournalSchemaError
    raw = json.loads(path.read_text(encoding="utf-8"))
    writes = [
        IntentWrite(
            target=w["target"],
            staged=w["staged"],
            old_content_hash=w["old_content_hash"],
            new_content_hash=w["new_content_hash"],
            mode=int(w["mode"]),
        )
        for w in raw.get("writes", [])
    ]
    raw_schema = raw.get("schema_version")
    if raw_schema is None:
        raise JournalSchemaError(
            f"Journal intent record at {path} has no schema_version field. "
            f"Legacy v1 records are not supported; current schema is "
            f"v{JOURNAL_SCHEMA_VERSION}."
        )
    if int(raw_schema) != JOURNAL_SCHEMA_VERSION:
        raise JournalSchemaError(
            f"Journal intent record at {path} has schema_version="
            f"{raw_schema}; expected {JOURNAL_SCHEMA_VERSION}."
        )
    # Parse symlinks field — must be preserved or signing_input() diverges
    raw_symlinks = raw.get("symlinks", [])
    symlinks = [
        IntentSymlink(
            symlink_path=s["symlink_path"],
            target_name=s["target_name"],
            prior_target=s.get("prior_target"),
        )
        for s in raw_symlinks
        if isinstance(s, dict)
    ]
    return IntentRecord(
        txn_id=raw["txn_id"],
        started_at=raw["started_at"],
        service=raw["service"],
        actor_id=raw.get("actor_id"),
        writes=writes,
        deletes=list(raw.get("deletes", [])),   # must be read or signing_input() diverges
        symlinks=symlinks,                        # must be read or signing_input() diverges
        schema_version=int(raw_schema),
        intent_integrity_hash=raw.get("intent_integrity_hash", ""),
        intent_signature=raw.get("intent_signature", ""),
        intent_signature_key_id=raw.get("intent_signature_key_id", ""),
    )


def read_complete_record(path: Path) -> CompleteRecord:
    """Load a complete record from disk. Does not verify the signature.

    Raises JournalSchemaError if schema_version is missing or doesn't match.
    """
    from wpgovern.errors import JournalSchemaError
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw_schema = raw.get("schema_version")
    if raw_schema is None:
        raise JournalSchemaError(
            f"Journal complete record at {path} has no schema_version field. "
            f"Legacy v1 records are not supported; current schema is "
            f"v{JOURNAL_SCHEMA_VERSION}."
        )
    if int(raw_schema) != JOURNAL_SCHEMA_VERSION:
        raise JournalSchemaError(
            f"Journal complete record at {path} has schema_version="
            f"{raw_schema}; expected {JOURNAL_SCHEMA_VERSION}."
        )
    return CompleteRecord(
        txn_id=raw["txn_id"],
        completed_at=raw["completed_at"],
        schema_version=int(raw_schema),
        complete_signature=raw.get("complete_signature", ""),
        complete_signature_key_id=raw.get("complete_signature_key_id", ""),
    )
