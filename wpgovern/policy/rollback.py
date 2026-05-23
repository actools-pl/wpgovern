"""
WPGovern rollback lifecycle service.

``RollbackService`` manages governed rollback operations:
  approve  — bind a rollback approval to a target baseline
  activate — execute the rollback atomically

Rollback activation commits four files via ``AtomicTransaction``:
  1. Rollback record
  2. Approval record (consumed)
  3. Active pointer (updated to target baseline)
  4. Supersession record

The reconciliation gate is checked before activation proceeds.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from wpgovern.core.signing import SigningService
from wpgovern.errors import NotFoundError, PolicyError, ValidationError
from wpgovern.paths import Paths, build_paths
from wpgovern.policy.approval import ApprovalService
from wpgovern.utils.locking import LockManager


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RollbackError(PolicyError):
    """Raised for rollback governance failures."""


class RollbackActivationResult(str):
    """str subclass carrying rollback metadata fields."""

    def __new__(
        cls,
        rollback_id: str,
        from_baseline_id: str | None = None,
        to_baseline_id: str | None = None,
        approval_id: str | None = None,
        supersession_id: str | None = None,
    ) -> "RollbackActivationResult":
        obj = str.__new__(cls, rollback_id)
        obj.rollback_id = rollback_id
        obj.from_baseline_id = from_baseline_id
        obj.to_baseline_id = to_baseline_id
        obj.rolled_back_from = from_baseline_id
        obj.rolled_back_to = to_baseline_id
        obj.approval_id = approval_id
        obj.supersession_id = supersession_id
        return obj

    def as_dict(self) -> dict:
        return {
            "rollback_id": self.rollback_id,
            "from_baseline_id": self.from_baseline_id,
            "to_baseline_id": self.to_baseline_id,
            "approval_id": self.approval_id,
            "supersession_id": self.supersession_id,
        }


class RollbackService:
    """Governed rollback service.

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance.
        signing: ``SigningService`` instance.
        approvals: ``ApprovalService`` instance.
        lock_manager: ``LockManager`` instance.
    """

    def __init__(
        self,
        config: object = None,
        paths: Paths | None = None,
        signing: SigningService | None = None,
        approvals: ApprovalService | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        self.paths = paths or build_paths(config)
        self.signing = signing or SigningService(paths=self.paths)
        self.approvals = approvals or ApprovalService(
            paths=self.paths, signing=self.signing
        )
        self.lock_manager = lock_manager or LockManager(
            locks_dir=self.paths.locks_dir
        )

    def approve(
        self,
        target_baseline_id: str,
        reason: str,
        approved_by: str = "python-control-plane",
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> str:
        """Create a signed rollback approval bound to ``target_baseline_id``.

        Verifies that the target baseline exists and its signature is valid
        before writing the approval. Returns the approval_id.
        """
        _validate_baseline_id(target_baseline_id)
        if not reason.strip():
            raise RollbackError("Rollback reason cannot be empty")
        if not approved_by.strip():
            raise RollbackError("approved_by cannot be empty")

        with self.lock_manager.acquire_many(["approvals", "baselines"]):
            target_path = self.paths.baselines_dir / f"{target_baseline_id}.json"
            if not target_path.exists():
                raise NotFoundError(
                    f"Target baseline '{target_baseline_id}' not found"
                )
            self.signing.verify_runtime_artifact(target_path)

            approval_id = _timestamped_id("rollback-approval")
            approval_path = self.paths.approvals_dir / f"{approval_id}.json"
            payload = {
                "approval_id": approval_id,
                "type": "rollback",
                "target_baseline_id": target_baseline_id,
                "reason": reason,
                "approved_by": approved_by,
                "approved_at": utc_now_iso(),
                "status": "approved",
            }
            self._atomic_write_and_sign(approval_path, payload)

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type="rollback.approve",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={
                        **actor_context,
                        "approval_id": approval_id,
                        "target_baseline_id": target_baseline_id,
                        "reason": reason,
                    },
                )
            return approval_id

    def activate(
        self,
        approval_id: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> RollbackActivationResult:
        """Execute a rollback approval atomically.

        Commits four signed files: rollback record, consumed approval,
        updated active pointer, and supersession record. Checks the
        reconciliation gate before proceeding.
        """
        if not approval_id.strip():
            raise RollbackError("approval_id cannot be empty")

        lock_names = ["governance", "approvals", "baselines", "active-state"]
        with self.lock_manager.acquire_many(lock_names):
            approval_path = self.paths.approvals_dir / f"{approval_id}.json"
            if not approval_path.exists():
                raise RollbackError(
                    f"Rollback approval '{approval_id}' not found"
                )

            approval = self.approvals.load(approval_id)
            if approval.get("type") != "rollback":
                raise RollbackError(
                    f"Approval '{approval_id}' is not a rollback approval"
                )

            if self.paths.reconciliation_required.exists():
                gate = (
                    self.paths.reconciliation_required.read_text(
                        encoding="utf-8"
                    ).strip()
                    or "unknown"
                )
                raise RollbackError(
                    f"Rollback blocked: reconciliation required ({gate})"
                )

            self.signing.verify_runtime_artifact(approval_path)
            self.approvals.require_approved(approval_id, expected_type="rollback")

            target_baseline_id = str(approval.get("target_baseline_id") or "")
            _validate_baseline_id(target_baseline_id)
            target_path = self.paths.baselines_dir / f"{target_baseline_id}.json"
            if not target_path.exists():
                raise NotFoundError(
                    f"Target baseline '{target_baseline_id}' not found"
                )
            self.signing.verify_runtime_artifact(target_path)

            if not self.paths.active_pointer.exists():
                raise RollbackError("No active baseline present")
            self.signing.verify_active_pointer()

            try:
                active_payload = json.loads(
                    self.paths.active_pointer.read_text(encoding="utf-8")
                )
            except json.JSONDecodeError as exc:
                raise RollbackError(
                    f"Active pointer is not valid JSON: {exc}"
                ) from exc

            current_id = str(active_payload.get("baseline_id") or "")
            if not current_id:
                raise RollbackError("No active baseline present")

            now = utc_now_iso()
            rollback_id = _timestamped_id("rollback")
            self.paths.state_rollbacks.mkdir(parents=True, exist_ok=True)
            rollback_path = self.paths.state_rollbacks / f"{rollback_id}.json"
            rollback_payload = {
                "rollback_id": rollback_id,
                "rolled_back_from": current_id,
                "rolled_back_to": target_baseline_id,
                "approval_id": approval_id,
                "activated_at": now,
            }

            approval_consume_path, approval_consumed_payload = (
                self.approvals.prepare_consume(approval_id, expected_type="rollback")
            )

            new_active_payload = {
                "baseline_id": target_baseline_id,
                "activated_at": now,
                "previous_baseline_id": current_id,
                "rollback": True,
            }

            self.paths.state_supersessions.mkdir(parents=True, exist_ok=True)
            supersession_id = _timestamped_id("supersession")
            supersession_path = (
                self.paths.state_supersessions / f"{supersession_id}.json"
            )
            supersession_payload = {
                "supersession_id": supersession_id,
                "superseded_baseline_id": current_id,
                "replacement_baseline_id": target_baseline_id,
                "rollback": True,
                "recorded_at": now,
            }

            from wpgovern.utils.transaction import AtomicTransaction

            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)

            with AtomicTransaction(
                staging_root,
                service_label="RollbackService.activate",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=self.signing.trust,
            ) as txn:
                txn.stage_signed_json(rollback_path, rollback_payload, self.signing)
                txn.stage_signed_json(
                    approval_consume_path, approval_consumed_payload, self.signing
                )
                txn.stage_signed_json(
                    self.paths.active_pointer, new_active_payload, self.signing
                )
                txn.stage_signed_json(
                    supersession_path, supersession_payload, self.signing
                )
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                details = {
                    "rollback_id": rollback_id,
                    "approval_id": approval_id,
                    "from": current_id,
                    "to": target_baseline_id,
                    "supersession_id": supersession_id,
                }
                audit_logger.emit(
                    event_type="rollback.activate",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**details, **actor_context},
                )

            return RollbackActivationResult(
                rollback_id, current_id, target_baseline_id,
                approval_id, supersession_id,
            )

    def _atomic_write_and_sign(self, approval_path: Path, payload: dict) -> None:
        """δ-2: Write approval JSON and signature sidecar atomically.

        Replaces the two-step JSON-write + sign_runtime_artifact pattern.
        Both files commit together or neither commits — no window for stale
        signatures or partial artifacts requiring manual cleanup.
        Same pattern as BreakglassService._atomic_write_and_sign and
        ApprovalService._atomic_write_and_sign.
        """
        from wpgovern.utils.transaction import AtomicTransaction
        staging_root = self.paths.root / "state" / ".transactions"
        staging_root.mkdir(parents=True, exist_ok=True)
        with AtomicTransaction(staging_root, service_label=None) as txn:
            txn.stage_signed_json(approval_path, payload, self.signing)
            txn.commit()


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _timestamped_id(prefix: str) -> str:
    """Generate a collision-resistant ID from a timestamp and a UUID4 suffix.

    Second-resolution timestamps alone collide when two operations happen
    within the same second (automation, test environments, batch execution).
    The UUID4 suffix makes the probability of collision negligible.
    """
    import uuid
    stamp = (
        utc_now_iso().replace("-", "").replace(":", "").replace("T", "")[:14]
    )
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}-{stamp}-{suffix}"

def _validate_baseline_id(baseline_id: str) -> None:
    if not baseline_id.strip():
        raise RollbackError("target_baseline_id cannot be empty")
    if "/" in baseline_id or "\\" in baseline_id or ".." in baseline_id:
        raise ValidationError("invalid path separators")


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    data = __import__("json").dumps(payload, indent=2, sort_keys=False) + "\n"
    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
