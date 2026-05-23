"""
WPGovern approval lifecycle service.

``ApprovalRecord`` is a stdlib dataclass defined here because it is tightly
coupled to the approval state machine in this module.

``ApprovalService.load()`` is self-verifying: every call verifies the approval
signature against the runtime trust domain before returning the record. Callers
get a signature-checked record without having to remember to verify themselves.

For diagnostic / forensic use cases that legitimately need to read an approval
without verification, use ``load_untrusted_for_inspection_only()``. Its name
carries the warning explicitly. Any caller using it must NOT use the returned
record for enforcement decisions.

Approval state machine
----------------------
    approved → consumed     (by baseline.activate, rollback.activate, etc.)
    approved → revoked      (explicit operator revocation)
    approved → expired      (TTL elapsed, for breakglass approvals)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import NotFoundError, PolicyError, ValidationError
from wpgovern.paths import Paths, build_paths
from wpgovern.utils.locking import LockManager


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(slots=True)
class ApprovalRecord:
    """A single approval record as loaded from disk."""

    approval_id: str
    type: str
    status: str
    payload: dict[str, Any]

    def __getitem__(self, key: str) -> Any:
        return self.payload[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)


class ApprovalService:
    """Approval lifecycle service.

    Manages the create / consume / revoke / expire state machine for all
    approval types (baseline, rollback, breakglass).

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance.
        signing: ``SigningService`` instance.
    """

    VALID_STATUSES = {"approved", "consumed", "revoked", "expired"}

    def __init__(
        self,
        config: Any = None,
        paths: Paths | None = None,
        signing: SigningService | None = None,
        trust_service: TrustService | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        self.config = config
        self.paths = paths or build_paths(config)
        self.signing = signing or SigningService(paths=self.paths)
        # F3: trust_service for AtomicTransaction journaling (None = no journal)
        self.trust_service = trust_service
        # F3: lock_manager for serialize consume/revoke/check_expiry
        self.lock_manager = lock_manager or LockManager(
            locks_dir=self.paths.locks_dir
        )

    def load(self, approval_id: str) -> ApprovalRecord:
        """Load an approval and verify its signature.

        This is the safe, default entry point. Every caller that makes an
        enforcement decision must use this method — not the raw JSON read
        path. The signature is verified against the runtime trust domain
        before the record is returned.

        For diagnostic use without verification, see
        ``load_untrusted_for_inspection_only``.
        """
        self._validate_id(approval_id)
        path = self.paths.approvals_dir / f"{approval_id}.json"
        if not path.exists():
            raise NotFoundError(f"Approval '{approval_id}' not found")
        self.signing.verify_runtime_artifact(path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        status = str(payload.get("status") or "")
        if status not in self.VALID_STATUSES:
            raise ValidationError(f"invalid status '{status}'")
        return ApprovalRecord(
            approval_id=str(payload.get("approval_id") or approval_id),
            type=str(payload.get("type") or ""),
            status=status,
            payload=payload,
        )

    def load_untrusted_for_inspection_only(
        self, approval_id: str
    ) -> ApprovalRecord:
        """Load an approval WITHOUT signature verification.

        This method exists for diagnostics, listing, and forensic inspection
        of suspect approvals. It must NOT be used for enforcement decisions.
        Use ``load()`` for any code path that acts on the approval record.
        """
        self._validate_id(approval_id)
        path = self.paths.approvals_dir / f"{approval_id}.json"
        if not path.exists():
            raise NotFoundError(f"Approval '{approval_id}' not found")
        payload = json.loads(path.read_text(encoding="utf-8"))
        status = str(payload.get("status") or "")
        if status not in self.VALID_STATUSES:
            raise ValidationError(f"invalid status '{status}'")
        return ApprovalRecord(
            approval_id=str(payload.get("approval_id") or approval_id),
            type=str(payload.get("type") or ""),
            status=status,
            payload=payload,
        )

    def require_approved(
        self,
        approval_id: str,
        expected_type: str | None = None,
    ) -> ApprovalRecord:
        """Assert the approval is in the approved state and ready for use.

        Runs expiry check first (marking time-expired approvals as expired),
        then loads with signature verification, then validates type and status.

        Raises ``PolicyError`` if the approval is consumed, revoked, expired,
        or has the wrong type.

        Note: does NOT acquire the "approvals" lock — callers that need
        atomic check-then-mutate must acquire the lock externally (consume/revoke
        do this). This method is used by prepare_consume and other callers that
        are already under a lock held by the outer service.
        """
        self._apply_expiry_if_needed(approval_id)
        record = self.load(approval_id)
        if expected_type is not None and record.type != expected_type:
            raise PolicyError(f"Approval '{approval_id}' expected '{expected_type}'")
        if record.status == "consumed":
            raise PolicyError(f"Approval '{approval_id}' already consumed")
        if record.status == "revoked":
            raise PolicyError(f"Approval '{approval_id}' has been revoked")
        if record.status == "expired":
            raise PolicyError(f"Approval '{approval_id}' has expired")
        if record.status != "approved":
            raise PolicyError(f"Approval '{approval_id}' is not approved")
        return record

    def check_expiry(self, approval_id: str) -> ApprovalRecord:
        """Check and apply expiry for time-limited approvals (acquires lock).

        F3: Acquires "approvals" lock. This is the public entry point.
        Internal callers that already hold the lock use _apply_expiry_if_needed().
        """
        with self.lock_manager.acquire_many(["approvals"]):
            return self._apply_expiry_if_needed(approval_id)

    def _apply_expiry_if_needed(self, approval_id: str) -> ApprovalRecord:
        """Apply expiry without acquiring the lock — for internal callers."""
        record = self.load(approval_id)
        expires_at = record.payload.get("expires_at")
        if expires_at and record.status == "approved" and utc_now_iso() > str(expires_at):
            payload = dict(record.payload)
            payload["status"] = "expired"
            payload["expired_at"] = utc_now_iso()
            self._atomic_write_and_sign(approval_id, payload)
            raise PolicyError(f"Approval '{approval_id}' has expired")
        return record

    def consume(
        self,
        approval_id: str,
        expected_type: str | None = None,
        *,
        _under_lock: bool = False,
    ) -> ApprovalRecord:
        """Consume an approval. Raises ``PolicyError`` if already consumed.

        F2: JSON and signature sidecar are written atomically via AtomicTransaction.
        F3: Acquires "approvals" lock before check-then-mutate to prevent
            double-consumption and consume-revoke races.
            Pass _under_lock=True if the caller already holds "approvals"
            (e.g. RollbackService.activate which uses its own locking).
        """
        def _do_consume():
            record = self.require_approved_under_lock(approval_id, expected_type=expected_type)
            payload = dict(record.payload)
            payload["status"] = "consumed"
            payload["consumed_at"] = utc_now_iso()
            self._atomic_write_and_sign(approval_id, payload)

        if _under_lock:
            _do_consume()
        else:
            with self.lock_manager.acquire_many(["approvals"]):
                _do_consume()
        return self.load(approval_id)

    def prepare_consume(
        self,
        approval_id: str,
        expected_type: str | None = None,
    ) -> tuple[Path, dict[str, Any]]:
        """Validate consumability and return ``(final_path, consumed_payload)``.

        Does not write anything. The caller stages and commits the write
        atomically alongside other governance state (via
        ``AtomicTransaction.stage_signed_json``).

        ``require_approved`` is called so all state-machine and expiry
        invariants apply exactly as in ``consume``.
        """
        record = self.require_approved(approval_id, expected_type=expected_type)
        payload = dict(record.payload)
        payload["status"] = "consumed"
        payload["consumed_at"] = utc_now_iso()
        final_path = self.paths.approvals_dir / f"{approval_id}.json"
        return final_path, payload

    def revoke(
        self,
        approval_id: str,
        reason: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> ApprovalRecord:
        """Revoke an approved (not yet consumed) approval.

        F2: JSON and signature sidecar are written atomically via AtomicTransaction.
        F3: Acquires "approvals" and per-approval locks before check-then-mutate
            to prevent consume-revoke races.
        """
        if not reason.strip():
            raise ValidationError("reason must not be empty")
        with self.lock_manager.acquire_many(["approvals"]):
            record = self.load(approval_id)
            if record.status == "consumed":
                raise PolicyError(
                    f"Approval '{approval_id}' cannot be revoked after consumption"
                )
            if record.status == "revoked":
                raise PolicyError(f"Approval '{approval_id}' has been revoked")
            if record.status != "approved":
                raise PolicyError(
                    f"Approval '{approval_id}' cannot be revoked from state "
                    f"'{record.status}'"
                )
            payload = dict(record.payload)
            payload["status"] = "revoked"
            payload["revoked_at"] = utc_now_iso()
            payload["revoke_reason"] = reason
            self._atomic_write_and_sign(approval_id, payload)

        if audit_logger is not None and actor_context is not None:
            audit_logger.emit(
                event_type="approval.revoked",
                actor=str(actor_context.get("actor_id") or ""),
                outcome="success",
                details={
                    **actor_context,
                    "approval_id": approval_id,
                    "approval_type": record.type,
                    "revoke_reason": reason,
                },
            )
        return self.load(approval_id)

    def require_approved_under_lock(
        self,
        approval_id: str,
        expected_type: str | None = None,
    ) -> ApprovalRecord:
        """Like require_approved — assumes caller already holds "approvals" lock."""
        self._apply_expiry_if_needed(approval_id)
        record = self.load(approval_id)
        if expected_type is not None and record.type != expected_type:
            raise PolicyError(f"Approval '{approval_id}' expected '{expected_type}'")
        if record.status == "consumed":
            raise PolicyError(f"Approval '{approval_id}' already consumed")
        if record.status == "revoked":
            raise PolicyError(f"Approval '{approval_id}' has been revoked")
        if record.status == "expired":
            raise PolicyError(f"Approval '{approval_id}' has expired")
        if record.status != "approved":
            raise PolicyError(f"Approval '{approval_id}' is not approved")
        return record

    def _atomic_write_and_sign(self, approval_id: str, payload: dict[str, Any]) -> None:
        """F2: Write approval JSON and its signature sidecar atomically.

        Replaces the old _write_and_sign (which wrote JSON then signature
        in two separate steps — a crash between them left an unsigned approval).
        Uses AtomicTransaction.stage_signed_json so both files are committed
        together or neither is.
        """
        from wpgovern.utils.transaction import AtomicTransaction
        path = self.paths.approvals_dir / f"{approval_id}.json"
        staging_root = self.paths.root / "state" / ".transactions"
        staging_root.mkdir(parents=True, exist_ok=True)
        with AtomicTransaction(
            staging_root,
            service_label=None,  # approval writes not journaled (KNOWN_LIMITS)
        ) as txn:
            txn.stage_signed_json(path, payload, self.signing)
            txn.commit()

    def _write_and_sign(self, approval_id: str, payload: dict[str, Any]) -> None:
        """Deprecated — use _atomic_write_and_sign instead."""
        self._atomic_write_and_sign(approval_id, payload)

    def _atomic_write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.tmp")
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    @staticmethod
    def _validate_id(value: str) -> None:
        if not value.strip():
            raise ValidationError("approval_id cannot be empty")
        if "/" in value or "\\" in value or ".." in value:
            raise ValidationError("invalid path separators")
