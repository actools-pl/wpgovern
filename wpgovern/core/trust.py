"""
WPGovern trust-store lifecycle service.

``TrustService`` manages the three trust domains that WPGovern uses for
cryptographic operations:

  runtime   — signs and verifies governance artifacts (baselines, active
               pointer, approvals)
  release   — verifies release manifests (verify-only by default)
  journal   — signs and verifies crash-recovery journal records

All three domains share the same directory layout under ``<root>/trust/``
and the same key-lifecycle state machine:

    preactive → active → retired_verify_only
                       → revoked

Data records
------------
``TrustKeyRecord`` and ``TrustStore`` are stdlib dataclasses defined here
because they are tightly coupled to the lifecycle logic in this module.

On-disk format
--------------
Each domain has a JSON trust store file at:

    trust/<domain>/public/trusted-<domain>-keys.json

Private keys live under:

    trust/<domain>/private/<key_id>.pem        (ed25519 PEM)
    trust/<domain>/private/<domain>-active.pem  (symlink → active key)

Public keys live under:

    trust/<domain>/public/<key_id>.pub

Atomicity
---------
Every trust-store mutation stages to a ``.tmp`` file and uses
``os.replace()`` for atomic commit. The symlink update uses the same
pattern (write temp symlink → os.replace to final name).
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from wpgovern.errors import IntegrityError, PolicyError, ValidationError, WPGovernError
from wpgovern.paths import Paths, build_paths
from wpgovern.utils.locking import LockManager


def _verify_keypair_cryptographic_match(
    priv_pem: Path,
    pub_path: Path,
    error_class: type = None,
) -> None:
    """Verify that priv_pem cryptographically derives the public key at pub_path.

    α-3: Shared helper called from both validate_store() and I-T-4 so both
    enforcement sites use the same contract implementation.

    Raises error_class (default TrustError) on mismatch or corrupt private key.
    Returns None silently if openssl is unavailable (FileNotFoundError).
    """
    if error_class is None:
        error_class = TrustError  # forward reference resolved at call time
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubout", "-in", str(priv_pem)],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        raise error_class(
            f"Private key validation failed for {priv_pem.name}: "
            f"{exc.stderr.decode()[:200] if exc.stderr else str(exc)}"
        ) from exc
    except FileNotFoundError:
        return  # openssl unavailable — skip gracefully

    if result.stdout.strip() != pub_path.read_bytes().strip():
        raise error_class(
            f"Trust keypair mismatch: private key {priv_pem.name} does not "
            f"derive registered public key {pub_path.name}"
        )


TrustDomain = Literal["runtime", "release", "journal"]
KeyStatus = Literal["preactive", "active", "retired_verify_only", "revoked"]


class TrustError(IntegrityError):
    """Raised for trust-store and key lifecycle failures."""


@dataclass(slots=True)
class TrustKeyRecord:
    """A single key entry in a domain trust store."""
    key_id: str
    path: str
    status: KeyStatus
    created_at: str
    usage: list[str]
    activated_at: str | None = None
    revoked_at: str | None = None
    revoke_reason: str | None = None


@dataclass(slots=True)
class TrustStore:
    """Deserialized domain trust store."""
    type: str
    version: int
    active_key_id: str | None
    keys: list[TrustKeyRecord]
    legacy_verification_enabled: bool | None = None
    legacy_compatibility_key_id: str | None = None


class TrustService:
    """Trust-store lifecycle service for all three WPGovern signing domains.

    Serializes every trust-store mutation under advisory file locks so that
    concurrent CLI invocations (rare but possible) cannot race.

    Args:
        config: ``WPGovernConfig`` instance. Used to derive paths if
            ``paths`` is not provided.
        paths: ``Paths`` instance. Derived from ``config`` if not provided.
        lock_manager: ``LockManager`` instance. Created from
            ``paths.locks_dir`` if not provided.
    """

    def __init__(
        self,
        config: Any = None,
        paths: Paths | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        if paths is None:
            paths = build_paths(config)
        self.config = config
        self.paths = paths
        self.lock_manager = lock_manager or LockManager(locks_dir=self.paths.locks_dir)

    # ------------------------------------------------------------------
    # Store initialization and loading
    # ------------------------------------------------------------------

    def init_store(self, domain: TrustDomain) -> Path:
        """Ensure the trust store and directory tree exist for ``domain``.

        Idempotent. Returns the store path.
        """
        store_path = self._store_path(domain)
        store_path.parent.mkdir(parents=True, exist_ok=True)
        private_dir = self._private_dir(domain)
        private_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(private_dir, 0o700)
        except OSError:
            pass  # best-effort on platforms without chmod
        self._public_dir(domain).mkdir(parents=True, exist_ok=True)
        if not store_path.exists():
            self._atomic_write_json(store_path, self._default_store_payload(domain))
        return store_path

    def load_store(self, domain: TrustDomain) -> TrustStore:
        """Load and deserialize the trust store for ``domain``.

        Raises ``TrustError`` if the JSON is malformed.
        """
        store_path = self.init_store(domain)
        try:
            payload = json.loads(store_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise TrustError(f"{domain} trust store is not valid JSON: {exc}") from exc

        keys: list[TrustKeyRecord] = []
        for item in payload.get("keys", []):
            keys.append(TrustKeyRecord(
                key_id=item["key_id"],
                path=item["path"],
                status=item["status"],
                created_at=item["created_at"],
                usage=list(item.get("usage", [])),
                activated_at=item.get("activated_at"),
                revoked_at=item.get("revoked_at"),
                revoke_reason=item.get("revoke_reason"),
            ))
        return TrustStore(
            type=payload["type"],
            version=int(payload["version"]),
            active_key_id=payload.get("active_key_id"),
            keys=keys,
            legacy_verification_enabled=payload.get("legacy_verification_enabled"),
            legacy_compatibility_key_id=payload.get("legacy_compatibility_key_id"),
        )

    def validate_store(self, domain: TrustDomain) -> None:
        """Validate the trust store for ``domain``.

        Checks: required fields, no duplicate key_ids, exactly one active
        key, correct usage per status, active symlink consistency.

        Raises ``TrustError`` on any violation.
        """
        store = self.load_store(domain)

        if not store.type:
            raise TrustError(f"{domain} trust store missing type")
        if not isinstance(store.version, int):
            raise TrustError(f"{domain} trust store version must be int")

        key_ids = [r.key_id for r in store.keys]
        duplicates = {kid for kid in key_ids if key_ids.count(kid) > 1}
        if duplicates:
            raise TrustError(f"Duplicate key_id entries: {', '.join(sorted(duplicates))}")

        active_records = [r for r in store.keys if r.status == "active"]
        if store.keys:
            if store.active_key_id is None:
                raise TrustError(f"{domain} trust store has keys but no active_key_id")
            if len(active_records) != 1:
                raise TrustError(
                    f"{domain} trust store must have exactly one active key, "
                    f"found {len(active_records)}"
                )
            active = active_records[0]
            if active.key_id != store.active_key_id:
                raise TrustError(
                    f"{domain} active_key_id {store.active_key_id!r} does not match "
                    f"active record {active.key_id!r}"
                )

        # M-H1: verify the active private symlink resolves inside trust/<domain>/private.
        # An absolute symlink to outside the tree passes name-match but escapes governance.
        active_link = self._active_private_link(domain)
        if active_link.is_symlink():
            try:
                resolved = active_link.resolve()
                priv_dir = active_link.parent.resolve()
                resolved.relative_to(priv_dir)
            except ValueError:
                raise TrustError(
                    f"{domain} active private symlink resolves outside "
                    f"trust/{domain}/private: {active_link.resolve()}"
                )

        for record in store.keys:
            if not record.key_id:
                raise TrustError(f"{domain} trust store contains empty key_id")
            # H3: reject empty paths and require a regular file, not just existence.
            if not record.path:
                raise TrustError(
                    f"{domain} trust store key '{record.key_id}' has empty path"
                )
            key_path = Path(record.path)
            if not key_path.exists():
                raise TrustError(f"{domain} public key path missing: {record.path}")
            if not key_path.is_file():
                raise TrustError(
                    f"{domain} public key path is not a regular file: {record.path}"
                )
            # M-H1: require the key path to resolve inside the governed trust tree.
            # A path pointing outside trust/<domain>/public can be used to route
            # verification through attacker-controlled material.
            expected_pub_dir = self.paths.root / "trust" / domain / "public"
            try:
                key_path.resolve().relative_to(expected_pub_dir.resolve())
            except ValueError:
                raise TrustError(
                    f"{domain} public key path resolves outside the governed "
                    f"trust directory: {record.path} (expected inside "
                    f"{expected_pub_dir})"
                )

            usage_set = set(record.usage)
            required_active = {"verify"} if domain == "release" else {"sign", "verify"}
            if record.status == "active":
                if not required_active.issubset(usage_set):
                    raise TrustError(
                        f"{domain} active key usage does not match expected "
                        f"for {record.key_id}: {record.usage}"
                    )
            elif record.status == "retired_verify_only":
                if usage_set != {"verify"}:
                    raise TrustError(
                        f"{domain} retired_verify_only key {record.key_id!r} "
                        "must only have verify usage"
                    )
            elif record.status == "revoked":
                if record.usage:
                    raise TrustError(
                        f"{domain} revoked key {record.key_id!r} must have empty usage"
                    )
            elif record.status == "preactive":
                expected_preactive = {"verify"} if domain == "release" else {"sign", "verify"}
                if usage_set != expected_preactive:
                    raise TrustError(
                        f"{domain} preactive key {record.key_id!r} has invalid "
                        f"usage {record.usage}"
                    )
                if record.activated_at is not None:
                    raise TrustError(
                        f"{domain} preactive key {record.key_id!r} must not "
                        "have activated_at set"
                    )
            else:
                raise TrustError(
                    f"{domain} key {record.key_id!r} has invalid status {record.status!r}"
                )

        if store.active_key_id is not None:
            self._validate_active_private_link(domain, store.active_key_id)

        # α-3: validate cryptographic keypair match for active/preactive keys.
        # validate_store is the public API gate — if it doesn't enforce keypair
        # consistency, callers cannot rely on the store being usable for signing.
        # Uses the same helper as I-T-4 so both sites enforce the same contract.
        for record in store.keys:
            if record.status not in ("active", "preactive"):
                continue
            priv_pem = self._private_dir(domain) / f"{record.key_id}.pem"
            if not priv_pem.is_file():
                continue  # I-T-4 catches missing private keys separately
            if not record.path:
                continue  # I-T-3 catches empty paths separately
            pub_path = Path(record.path)
            if not pub_path.is_file():
                continue  # I-T-3 catches missing public keys separately
            _verify_keypair_cryptographic_match(priv_pem, pub_path, TrustError)

    # ------------------------------------------------------------------
    # Key lifecycle
    # ------------------------------------------------------------------

    def generate_key(
        self,
        domain: TrustDomain,
        key_id: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> TrustKeyRecord:
        """Generate a new ed25519 key in ``domain`` with status ``preactive``.

        ε-1: keys are generated in a private staging directory, verified for
        keypair consistency, registered in the trust store, and only then
        atomically published into the governed directories. On any failure
        between staging and publication, the staged files are removed so no
        orphan key material lands in governed dirs.

        Raises ``TrustError`` if ``key_id`` already exists in the store.
        """
        self._validate_key_id(key_id)
        self.init_store(domain)
        lock_name = self._domain_lock_name(domain)

        with self.lock_manager.acquire(lock_name):
            store = self.load_store(domain)
            if any(r.key_id == key_id for r in store.keys):
                raise TrustError(f"{domain} key {key_id!r} already exists")

            # Staging directory: sibling of private/ and public/ so
            # os.replace is atomic (same filesystem). Named with key_id
            # and random suffix so concurrent generations never collide
            # and crash leftovers are visible to operators.
            domain_root = self._domain_root(domain)
            staging_dir = domain_root / f".keygen-{key_id}-{secrets.token_hex(4)}"
            staging_dir.mkdir(parents=True, exist_ok=False)
            os.chmod(staging_dir, 0o700)

            staged_private = staging_dir / f"{key_id}.pem"
            staged_public = staging_dir / f"{key_id}.pub"

            try:
                # Generate into staging — not into governed dirs
                self._run_openssl(["genpkey", "-algorithm", "ed25519",
                                   "-out", str(staged_private)])
                self._run_openssl(["pkey", "-in", str(staged_private),
                                   "-pubout", "-out", str(staged_public)])
                os.chmod(staged_private, 0o600)

                # Verify the staged keypair derives correctly before publishing.
                # Catches openssl bugs, hardware faults, or filesystem corruption
                # that would produce a registered key failing I-T-4 immediately.
                _verify_keypair_cryptographic_match(staged_private, staged_public)

                # Build the record. Path points at the FINAL location.
                final_private = self._private_dir(domain) / f"{key_id}.pem"
                final_public = self._public_dir(domain) / f"{key_id}.pub"
                usage = ["verify"] if domain == "release" else ["sign", "verify"]
                record = TrustKeyRecord(
                    key_id=key_id,
                    path=str(final_public),
                    status="preactive",
                    created_at=self._utcnow(),
                    usage=usage,
                )
                payload = self._store_to_payload(store)
                payload["keys"].append(self._record_to_payload(record))

                # Register in trust store FIRST. If this fails, no key material
                # is published and staging cleanup runs in the except block.
                # If this succeeds but a subsequent replace fails, I-T-6 detects
                # the registered-but-missing state.
                self._atomic_write_json(self._store_path(domain), payload)

                # Atomic publish: os.replace is atomic on POSIX same-filesystem.
                # Staging dir is a sibling of private/ so this invariant holds.
                os.replace(staged_private, final_private)
                os.replace(staged_public, final_public)

                # Best-effort: fsync parent dirs so new entries survive power loss.
                self._fsync_dir(self._private_dir(domain))
                self._fsync_dir(self._public_dir(domain))

            except Exception:
                # Cleanup: remove staged files then staging dir.
                # Best-effort — I-T-6 catches anything that leaks past this.
                try:
                    if staged_private.is_file():
                        staged_private.unlink()
                    if staged_public.is_file():
                        staged_public.unlink()
                except OSError:
                    pass
                try:
                    staging_dir.rmdir()
                except OSError:
                    pass
                raise
            else:
                # Success: staging dir should be empty after the replace calls.
                try:
                    staging_dir.rmdir()
                except OSError:
                    pass

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type=f"{self._event_prefix(domain)}.key.generated",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**actor_context, "key_id": key_id, "domain": domain},
                )
            return record

    def activate_key(
        self,
        domain: TrustDomain,
        key_id: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> TrustKeyRecord:
        """Activate a preactive key. Retires the previous active key.

        Acquires both the governance lock and the domain-specific trust lock
        to serialize key activation against any governance operation.
        """
        self._validate_key_id(key_id)
        self.init_store(domain)

        with self.lock_manager.acquire_many(["governance", self._domain_lock_name(domain)]):
            store = self.load_store(domain)
            target = self._find_record(store, key_id)
            if target is None:
                raise TrustError(f"{domain} key {key_id!r} not found")
            if target.status != "preactive":
                raise TrustError(
                    f"{domain} key {key_id!r} has status {target.status!r} "
                    "and cannot be activated"
                )

            # α-2: use is_file() not exists() — directories return True for exists().
            # An operator error or attacker manipulation that creates a directory at
            # the .pem path would pass .exists() and allow activation to proceed with
            # the symlink pointing at a directory.
            private_dir = self._private_dir(domain)
            target_pem = private_dir / f"{key_id}.pem"
            if not target_pem.is_file():
                raise TrustError(
                    f"{domain} key {key_id!r} cannot be activated: private key "
                    f"file missing at {target_pem}. Verify the key was generated "
                    "correctly and the private key file is present."
                )

            # α-1: mirror the private-key precondition for the public key.
            # Preconditions must be checked before any state-mutating transaction, not after.
            # If the public key is missing, validate_store() would catch it but only
            # AFTER the transaction commits — too late to prevent state mutation.
            public_dir = self._public_dir(domain)
            target_pub = public_dir / f"{key_id}.pub"
            if not target_pub.is_file():
                raise TrustError(
                    f"{domain} key {key_id!r} cannot be activated: public key "
                    f"file missing at {target_pub}. Verify the key was generated "
                    "correctly and the public key file is present."
                )

            now = self._utcnow()
            for record in store.keys:
                if record.status == "active":
                    record.status = "retired_verify_only"
                    record.usage = ["verify"]

            target.status = "active"
            target.activated_at = now
            target.usage = ["verify"] if domain == "release" else ["sign", "verify"]
            store.active_key_id = key_id

            # Journal the activation as an atomic transaction so that
            # JSON write + symlink update fail or succeed together.
            # Prevents the H4+M2 composition where JSON is written but
            # the symlink update fails, leaving no active signing key.
            from wpgovern.utils.transaction import AtomicTransaction
            import json as _json_trust
            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)
            store_path = self._store_path(domain)
            payload_text = _json_trust.dumps(self._store_to_payload(store), indent=2) + "\n"

            _has_journal_key = False
            try:
                _has_journal_key = bool(self.active_key_id("journal"))
            except Exception:
                pass

            symlink_path = self._active_private_link(domain)
            symlink_target_relative = f"{key_id}.pem"

            with AtomicTransaction(
                staging_root,
                service_label=(
                    f"TrustService.activate_{domain}_key" if _has_journal_key else None
                ),
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=self,
            ) as txn:
                txn.stage_text(store_path, payload_text)
                # Stage the symlink in the SAME transaction — JSON + symlink
                # are atomically consistent. If symlink update fails, the
                # JSON write is still committed but the error is surfaced
                # and the caller can retry (the JSON will be in the new state,
                # but a retry of activate_key after a symlink-only failure
                # is recoverable because validate_store will detect the desync).
                txn.stage_symlink_replace(symlink_path, symlink_target_relative)
                txn.commit()

            self.validate_store(domain)

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type=f"{self._event_prefix(domain)}.key.activated",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**actor_context, "key_id": key_id, "domain": domain},
                )
            return target

    def revoke_key(
        self,
        domain: TrustDomain,
        key_id: str,
        reason: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> TrustKeyRecord:
        """Revoke a non-active key.

        The currently active key cannot be revoked directly — it must first
        be superseded by activating a new key.

        ε.2-3: revocation is now journaled through AtomicTransaction, mirroring
        activate_key's structure. Recovery can replay incomplete revocations and
        the audit chain correctly reflects whether the revoke succeeded.
        """
        self._validate_key_id(key_id)
        if not reason.strip():
            raise TrustError("Revocation reason cannot be empty")
        self.init_store(domain)

        with self.lock_manager.acquire(self._domain_lock_name(domain)):
            store = self.load_store(domain)
            if store.active_key_id == key_id:
                raise PolicyError("currently active runtime key cannot be revoked directly")
            target = self._find_record(store, key_id)
            if target is None:
                raise TrustError(f"{domain} key {key_id!r} not found")
            if target.status == "revoked":
                return target

            target.status = "revoked"
            target.revoked_at = self._utcnow()
            target.revoke_reason = reason
            target.usage = []

            # ε.2-3: journaled write — same pattern as activate_key.
            # Mutation happens in-memory first, then the serialized payload is staged.
            import json as _json_trust
            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)
            store_path = self._store_path(domain)
            payload_text = _json_trust.dumps(self._store_to_payload(store), indent=2) + "\n"

            _has_journal_key = False
            try:
                _has_journal_key = bool(self.active_key_id("journal"))
            except Exception:
                pass

            from wpgovern.utils.transaction import AtomicTransaction
            with AtomicTransaction(
                staging_root,
                service_label=(
                    f"TrustService.revoke_{domain}_key" if _has_journal_key else None
                ),
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=self,
            ) as txn:
                txn.stage_text(store_path, payload_text)
                txn.commit()

            self.validate_store(domain)

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type=f"{self._event_prefix(domain)}.key.revoked",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**actor_context, "key_id": key_id, "domain": domain,
                             "revoke_reason": reason},
                )
            return target

    # ------------------------------------------------------------------
    # Key lookup
    # ------------------------------------------------------------------

    def active_key_id(self, domain: TrustDomain) -> str | None:
        return self.load_store(domain).active_key_id

    def active_public_key_path(self, domain: TrustDomain) -> Path:
        store = self.load_store(domain)
        if store.active_key_id is None:
            raise TrustError(f"{domain} trust store has no active key")
        record = self._find_record(store, store.active_key_id)
        if record is None:
            raise TrustError(
                f"{domain} active key {store.active_key_id!r} is not registered"
            )
        return Path(record.path)

    def public_key_for_key_id(self, domain: TrustDomain, key_id: str) -> Path:
        store = self.load_store(domain)
        record = self._find_record(store, key_id)
        if record is None:
            raise IntegrityError(
                f"{domain} key {key_id!r} is not registered in the trust store"
            )
        return Path(record.path)

    def key_status(self, domain: TrustDomain, key_id: str) -> KeyStatus:
        store = self.load_store(domain)
        record = self._find_record(store, key_id)
        if record is None:
            raise IntegrityError(
                f"{domain} key {key_id!r} is not registered in the trust store"
            )
        return record.status

    def active_private_key_path(self, domain: TrustDomain) -> Path:
        """Return the path to the active private key file.

        Cross-checks the symlink target against the trust store's
        ``active_key_id``. Raises ``TrustError`` if they disagree — this
        detects the desync that occurs when ``activate_key`` fails after
        writing the JSON but before updating the symlink.
        """
        link = self._active_private_link(domain)
        if not link.is_symlink():
            raise TrustError(f"{domain} active private key symlink missing: {link}")
        resolved = link.resolve(strict=False)
        if not resolved.exists():
            raise TrustError(f"{domain} active private key target missing: {resolved}")

        store = self.load_store(domain)
        expected_key_id = store.active_key_id
        if expected_key_id is not None:
            symlink_key_id = resolved.stem
            if symlink_key_id != expected_key_id:
                raise TrustError(
                    f"{domain} trust store / symlink desync: trust store "
                    f"active_key_id={expected_key_id!r} but symlink resolves to "
                    f"{symlink_key_id!r}.pem. Run `wpgovern trust-key-activate "
                    f"{domain} {expected_key_id}` to re-establish the symlink, "
                    "or restore from a known-good trust backup."
                )
        return resolved

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    def verify_runtime_trust(self) -> dict:
        self.validate_store("runtime")
        return self.get_runtime_store()

    def verify_release_trust(self) -> dict:
        self.validate_store("release")
        return self.get_release_store()

    def verify_journal_trust(self) -> dict:
        self.validate_store("journal")
        return self.get_journal_store()

    def get_runtime_store(self) -> dict:
        return json.loads(self.init_store("runtime").read_text(encoding="utf-8"))

    def get_release_store(self) -> dict:
        return json.loads(self.init_store("release").read_text(encoding="utf-8"))

    def get_journal_store(self) -> dict:
        return json.loads(self.init_store("journal").read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Domain-specific convenience wrappers
    # ------------------------------------------------------------------

    def init_runtime_trust_store(self) -> Path:
        return self.init_store("runtime")

    def init_release_trust_store(self) -> Path:
        return self.init_store("release")

    def init_journal_trust_store(self) -> Path:
        return self.init_store("journal")

    def generate_runtime_key(self, key_id: str, **kw: Any) -> TrustKeyRecord:
        return self.generate_key("runtime", key_id, **kw)

    def generate_release_key(self, key_id: str, **kw: Any) -> TrustKeyRecord:
        return self.generate_key("release", key_id, **kw)

    def generate_journal_key(self, key_id: str, **kw: Any) -> TrustKeyRecord:
        return self.generate_key("journal", key_id, **kw)

    def activate_runtime_key(self, key_id: str, **kw: Any) -> TrustKeyRecord:
        return self.activate_key("runtime", key_id, **kw)

    def activate_release_key(self, key_id: str, **kw: Any) -> TrustKeyRecord:
        return self.activate_key("release", key_id, **kw)

    def activate_journal_key(self, key_id: str, **kw: Any) -> TrustKeyRecord:
        return self.activate_key("journal", key_id, **kw)

    def revoke_runtime_key(self, key_id: str, reason: str, **kw: Any) -> TrustKeyRecord:
        return self.revoke_key("runtime", key_id, reason, **kw)

    def revoke_release_key(self, key_id: str, reason: str, **kw: Any) -> TrustKeyRecord:
        return self.revoke_key("release", key_id, reason, **kw)

    def revoke_journal_key(self, key_id: str, reason: str, **kw: Any) -> TrustKeyRecord:
        return self.revoke_key("journal", key_id, reason, **kw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_active_private_link(
        self, domain: TrustDomain, active_key_id: str
    ) -> None:
        link = self._active_private_link(domain)
        if not link.is_symlink():
            raise TrustError(f"{domain} active private key symlink missing: {link}")
        target_name = os.readlink(link)
        actual_key_id = Path(target_name).stem
        if actual_key_id != active_key_id:
            raise TrustError(
                f"{domain} active private key symlink points to {actual_key_id!r}, "
                f"expected {active_key_id!r}"
            )
        resolved = (link.parent / target_name).resolve(strict=False)
        if not resolved.exists():
            raise TrustError(f"{domain} active private key target missing: {resolved}")

    def _store_path(self, domain: TrustDomain) -> Path:
        if domain == "runtime":
            return self.paths.runtime_trust_store
        if domain == "release":
            return self.paths.release_trust_store
        return self.paths.journal_trust_store

    def _domain_root(self, domain: TrustDomain) -> Path:
        """Return the root directory for a trust domain (trust/<domain>/).

        Used by generate_key to place staging dirs alongside private/ and
        public/ so os.replace is an atomic same-filesystem operation.
        """
        return self.paths.root / "trust" / domain

    def _fsync_dir(self, path: Path) -> None:
        """Fsync a directory to ensure new directory entries survive power loss."""
        try:
            fd = os.open(str(path), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass  # best-effort

    def _private_dir(self, domain: TrustDomain) -> Path:
        if domain == "runtime":
            return self.paths.runtime_private_dir
        if domain == "release":
            return self.paths.release_private_dir
        return self.paths.journal_private_dir

    def _public_dir(self, domain: TrustDomain) -> Path:
        if domain == "runtime":
            return self.paths.runtime_public_dir
        if domain == "release":
            return self.paths.release_public_dir
        return self.paths.journal_public_dir

    def _active_private_link(self, domain: TrustDomain) -> Path:
        if domain == "runtime":
            return self.paths.runtime_active_private_key
        if domain == "release":
            return self.paths.release_active_private_key
        return self.paths.journal_active_private_key

    def _domain_lock_name(self, domain: TrustDomain) -> str:
        if domain == "runtime":
            return "runtime-trust"
        if domain == "release":
            return "release-trust"
        return "journal-trust"

    def _event_prefix(self, domain: TrustDomain) -> str:
        if domain == "runtime":
            return "trust"
        if domain == "release":
            return "release"
        return "journal"

    def _default_store_payload(self, domain: TrustDomain) -> dict[str, Any]:
        base: dict[str, Any] = {
            "type": f"wpgovern.{domain}_trust_store",
            "version": 1,
            "active_key_id": None,
            "keys": [],
        }
        if domain == "runtime":
            base["legacy_verification_enabled"] = False
            base["legacy_compatibility_key_id"] = None
        return base

    def _find_record(
        self, store: TrustStore, key_id: str
    ) -> TrustKeyRecord | None:
        for record in store.keys:
            if record.key_id == key_id:
                return record
        return None

    def _store_to_payload(self, store: TrustStore) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": store.type,
            "version": store.version,
            "active_key_id": store.active_key_id,
            "keys": [self._record_to_payload(r) for r in store.keys],
        }
        if store.legacy_verification_enabled is not None:
            payload["legacy_verification_enabled"] = store.legacy_verification_enabled
        if store.legacy_compatibility_key_id is not None or "runtime" in store.type:
            payload["legacy_compatibility_key_id"] = store.legacy_compatibility_key_id
        return payload

    def _record_to_payload(self, record: TrustKeyRecord) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "key_id": record.key_id,
            "path": record.path,
            "status": record.status,
            "created_at": record.created_at,
            "usage": record.usage,
        }
        if record.activated_at is not None:
            payload["activated_at"] = record.activated_at
        if record.revoked_at is not None:
            payload["revoked_at"] = record.revoked_at
        if record.revoke_reason is not None:
            payload["revoke_reason"] = record.revoke_reason
        return payload

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.tmp")
        data = json.dumps(payload, indent=2, sort_keys=False) + "\n"
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    def _run_openssl(self, args: list[str]) -> None:
        try:
            subprocess.run(
                ["openssl", *args],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace").strip()
            raise TrustError(f"OpenSSL command failed: {stderr or exc}") from exc

    @staticmethod
    def _validate_key_id(key_id: str) -> None:
        if not key_id.strip():
            raise TrustError("key_id cannot be empty")
        if "/" in key_id or "\\" in key_id or ".." in key_id:
            raise ValidationError(f"invalid characters in key_id {key_id!r}")

    @staticmethod
    def _utcnow() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
