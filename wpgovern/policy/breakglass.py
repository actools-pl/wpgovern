"""
WPGovern break-glass emergency governance service.

``BreakglassService`` manages the break-glass lifecycle:
  approve  — create a time-limited break-glass approval
  activate — execute the break-glass authorization and raise the reconciliation gate
  review   — record the post-incident review (required for reconciliation to close)

Break-glass activate commits four artifacts atomically:
  1. Emergency record
  2. Approval record (consumed)
  3. Reconciliation record
  4. Reconciliation-required gate file (plain text sentinel)

The gate file placement inside the same transaction guarantees that
activation cannot leave the system in a state where the emergency is
recorded but the reconciliation gate has not been raised.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wpgovern.core.signing import SigningService
from wpgovern.errors import NotFoundError, PolicyError, ValidationError
from wpgovern.paths import Paths, build_paths
from wpgovern.policy.approval import ApprovalService
from wpgovern.utils.locking import LockManager


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class BreakglassError(PolicyError):
    """Raised for break-glass governance failures."""


class BreakglassActivationResult(str):
    """str subclass carrying activation metadata fields."""

    def __new__(
        cls,
        emergency_id: str,
        reconciliation_id: str | None = None,
        approval_id: str | None = None,
        incident_id: str | None = None,
        baseline_id: str | None = None,
    ) -> "BreakglassActivationResult":
        obj = str.__new__(cls, emergency_id)
        obj.emergency_id = emergency_id
        obj.reconciliation_id = reconciliation_id
        obj.approval_id = approval_id
        obj.incident_id = incident_id
        obj.baseline_id = baseline_id
        return obj

    def as_dict(self) -> dict:
        return {
            "emergency_id": self.emergency_id,
            "reconciliation_id": self.reconciliation_id,
            "approval_id": self.approval_id,
            "incident_id": self.incident_id,
            "baseline_id": self.baseline_id,
        }


class ReviewResult(str):
    """str subclass carrying review_id."""

    def __new__(cls, review_id: str) -> "ReviewResult":
        obj = str.__new__(cls, review_id)
        obj.review_id = review_id
        return obj


class BreakglassService:
    """Emergency break-glass governance service.

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
        incident_id: str,
        justification: str,
        ttl_minutes: int,
        approved_by: str = "python-control-plane",
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> str:
        """Create a signed time-limited break-glass approval.

        Returns the approval_id.
        """
        _validate_identifier("incident_id", incident_id)
        if not justification.strip():
            raise ValidationError("justification must not be empty")
        if not approved_by.strip():
            raise ValidationError("approved_by must not be empty")
        if ttl_minutes <= 0:
            raise ValidationError("ttl_minutes must be greater than zero")

        with self.lock_manager.acquire_many(["approvals"]):
            approval_id = _timestamped_id("breakglass")
            approval_path = self.paths.approvals_dir / f"{approval_id}.json"
            expires_at = _future_iso(ttl_minutes)
            payload = {
                "approval_id": approval_id,
                "type": "breakglass",
                "incident_id": incident_id,
                "justification": justification,
                "approved_by": approved_by,
                "approved_at": utc_now_iso(),
                "expires_at": expires_at,
                "status": "approved",
            }
            self._atomic_write_and_sign(approval_path, payload)

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type="breakglass.approve",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={
                        **actor_context,
                        "approval_id": approval_id,
                        "incident_id": incident_id,
                        "justification": justification,
                        "ttl_minutes": ttl_minutes,
                        "expires_at": expires_at,
                    },
                )
            return approval_id

    def activate(
        self,
        approval_id: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> BreakglassActivationResult:
        """Execute a break-glass authorization atomically.

        Commits four artifacts: emergency record, consumed approval,
        reconciliation record, and reconciliation-required gate file.
        The gate file is placed inside the same transaction as the
        emergency record — they are inseparable.
        """
        if not approval_id.strip():
            raise BreakglassError("approval_id cannot be empty")

        lock_names = [
            "governance", "approvals", "active-state", "emergency", "reconciliation"
        ]
        with self.lock_manager.acquire_many(lock_names):
            approval_path = self.paths.approvals_dir / f"{approval_id}.json"
            if not approval_path.exists():
                raise BreakglassError(f"Approval '{approval_id}' not found")

            approval = self.approvals.load(approval_id)
            if approval.get("type") != "breakglass":
                raise BreakglassError(
                    f"Approval '{approval_id}' is not a break-glass approval"
                )

            self.signing.verify_runtime_artifact(approval_path)
            self.approvals.require_approved(approval_id, expected_type="breakglass")

            if not self.paths.active_pointer.exists():
                raise NotFoundError("Active pointer missing")
            self.signing.verify_active_pointer()

            try:
                active_payload = json.loads(
                    self.paths.active_pointer.read_text(encoding="utf-8")
                )
            except json.JSONDecodeError as exc:
                raise BreakglassError(
                    f"Active pointer is not valid JSON: {exc}"
                ) from exc

            current_id = str(active_payload.get("baseline_id") or "")
            if not current_id:
                raise NotFoundError("Active pointer missing")

            expires_at = str(approval.get("expires_at") or "")
            if not expires_at:
                raise BreakglassError(
                    f"Break-glass approval '{approval_id}' missing expires_at"
                )

            now = utc_now_iso()
            emergency_id = _timestamped_id("emergency")
            self.paths.state_emergency.mkdir(parents=True, exist_ok=True)
            emergency_path = self.paths.state_emergency / f"{emergency_id}.json"
            emergency_payload = {
                "emergency_id": emergency_id,
                "baseline_id": current_id,
                "approval_id": approval_id,
                "activated_at": now,
                "status": "active",
                "reviewed": False,
            }

            approval_consume_path, approval_consumed_payload = (
                self.approvals.prepare_consume(approval_id, expected_type="breakglass")
            )

            self.paths.state_reconciliation.mkdir(parents=True, exist_ok=True)
            recon_id = _timestamped_id("recon")
            recon_path = self.paths.state_reconciliation / f"{recon_id}.json"
            recon_payload = {
                "reconciliation_id": recon_id,
                "source": "breakglass",
                "approval_id": approval_id,
                "incident_id": approval.get("incident_id"),
                "created_at": now,
                "status": "required",
            }

            self.paths.reconciliation_required.parent.mkdir(
                parents=True, exist_ok=True
            )

            from wpgovern.utils.transaction import AtomicTransaction

            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)

            with AtomicTransaction(
                staging_root,
                service_label="BreakglassService.activate",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=self.signing.trust,
            ) as txn:
                txn.stage_signed_json(
                    emergency_path, emergency_payload, self.signing
                )
                txn.stage_signed_json(
                    approval_consume_path, approval_consumed_payload, self.signing
                )
                txn.stage_signed_json(recon_path, recon_payload, self.signing)
                txn.stage_text(
                    self.paths.reconciliation_required,
                    recon_id + "\n",
                    mode=0o644,
                )
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                details = {
                    "emergency_id": emergency_id,
                    "approval_id": approval_id,
                    "incident_id": str(approval.get("incident_id") or ""),
                    "baseline_id": current_id,
                    "reconciliation_id": recon_id,
                }
                audit_logger.emit(
                    event_type="breakglass.activate",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**details, **actor_context},
                )

            return BreakglassActivationResult(
                emergency_id, recon_id, approval_id,
                str(approval.get("incident_id") or ""), current_id,
            )

    def review(
        self,
        emergency_id: str,
        outcome: str,
        findings: str,
        reviewed_by: str = "python-control-plane",
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> ReviewResult:
        """Record a post-incident review of a break-glass emergency.

        Commits two artifacts atomically: the review record and an update
        to the emergency record setting ``reviewed=True`` and ``review_id``.
        """
        _validate_identifier("emergency_id", emergency_id)
        if not outcome.strip():
            raise ValidationError("review outcome must not be empty")
        if not findings.strip():
            raise ValidationError("review findings must not be empty")
        if not reviewed_by.strip():
            raise ValidationError("reviewed_by cannot be empty")

        lock_names = ["governance", "emergency", "reconciliation"]
        with self.lock_manager.acquire_many(lock_names):
            emergency_path = self.paths.state_emergency / f"{emergency_id}.json"
            if not emergency_path.exists():
                raise NotFoundError(
                    f"Emergency record '{emergency_id}' not found"
                )

            self.signing.verify_runtime_artifact(emergency_path)

            try:
                emergency_payload = json.loads(
                    emergency_path.read_text(encoding="utf-8")
                )
            except json.JSONDecodeError as exc:
                raise BreakglassError(
                    f"Emergency record '{emergency_id}' is not valid JSON: {exc}"
                ) from exc

            approval_id = str(emergency_payload.get("approval_id") or "")
            if not approval_id:
                raise BreakglassError(
                    f"Emergency record '{emergency_id}' missing approval_id"
                )

            approval = self.approvals.load(approval_id)
            approval_path = self.paths.approvals_dir / f"{approval_id}.json"
            self.signing.verify_runtime_artifact(approval_path)

            incident_id = str(approval.get("incident_id") or "")
            review_id = _timestamped_id("review")
            self.paths.state_emergency_reviews.mkdir(parents=True, exist_ok=True)
            review_path = (
                self.paths.state_emergency_reviews / f"{review_id}.json"
            )
            review_payload = {
                "review_id": review_id,
                "emergency_id": emergency_id,
                "approval_id": approval_id,
                "incident_id": incident_id,
                "reviewed_by": reviewed_by,
                "reviewed_at": utc_now_iso(),
                "outcome": outcome,
                "findings": findings,
            }

            updated_emergency = dict(emergency_payload)
            updated_emergency["reviewed"] = True
            updated_emergency["review_id"] = review_id

            from wpgovern.utils.transaction import AtomicTransaction

            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)

            with AtomicTransaction(
                staging_root,
                service_label="BreakglassService.review",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=self.signing.trust,
            ) as txn:
                txn.stage_signed_json(review_path, review_payload, self.signing)
                txn.stage_signed_json(
                    emergency_path, updated_emergency, self.signing
                )
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                details = {
                    "review_id": review_id,
                    "emergency_id": emergency_id,
                    "approval_id": approval_id,
                    "incident_id": incident_id,
                    "outcome": outcome,
                }
                audit_logger.emit(
                    event_type="breakglass.review",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**details, **actor_context},
                )

            return ReviewResult(review_id)

    def _atomic_write_and_sign(self, approval_path: Path, payload: dict) -> None:
        """δ-1: Write approval JSON and signature sidecar atomically.

        Replaces the two-step JSON-write + sign_runtime_artifact pattern.
        Both files commit together or neither commits — no window for stale
        signatures or partial artifacts requiring manual cleanup.
        Same pattern as ApprovalService._atomic_write_and_sign.
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

def _future_iso(minutes: int) -> str:
    base = datetime.strptime(utc_now_iso(), "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return (base + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_identifier(field: str, value: str) -> None:
    if not value.strip():
        raise ValidationError(
            "incident ID must not be empty"
            if field == "incident_id"
            else f"{field} cannot be empty"
        )
    if "/" in value or "\\" in value or ".." in value:
        raise ValidationError(f"invalid path separators in {field} '{value}'")


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    data = __import__("json").dumps(payload, indent=2, sort_keys=False) + "\n"
    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            __import__("os").fsync(fh.fileno())
        __import__("os").replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
