"""
WPGovern reconciliation lifecycle service.

``ReconciliationService`` manages the reconciliation debt created by
break-glass activations. It enforces the full review chain before allowing
reconciliation to be marked complete and the gate to be cleared.

Enforcement invariant: a break-glass reconciliation cannot complete unless:
1. An emergency record for the linked approval_id exists.
2. That emergency record is signed and ``reviewed=True``.
3. The linked review record exists, is signed, and matches the emergency
   and approval IDs.

Non-break-glass reconciliation (source != "breakglass") completes without
the review chain check.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wpgovern.core.signing import SigningService
from wpgovern.errors import IntegrityError, NotFoundError, PolicyError, ValidationError
from wpgovern.paths import Paths, build_paths
from wpgovern.utils.locking import LockManager


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReconciliationError(PolicyError, NotFoundError, IntegrityError):
    """Raised for reconciliation governance failures."""


class ReconciliationRecord(dict):
    """dict subclass with attribute access for reconciliation payload fields."""

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError as exc:
            raise AttributeError(key) from exc


class ReconciliationService:
    """Reconciliation lifecycle service.

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance.
        signing: ``SigningService`` instance.
        lock_manager: ``LockManager`` instance.
    """

    def __init__(
        self,
        config: object = None,
        paths: Paths | None = None,
        signing: SigningService | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        self.paths = paths or build_paths(config)
        self.signing = signing or SigningService(paths=self.paths)
        self.lock_manager = lock_manager or LockManager(
            locks_dir=self.paths.locks_dir
        )

    def load(self, reconciliation_id: str) -> dict[str, Any]:
        """Load a reconciliation record from disk."""
        _validate_identifier("reconciliation_id", reconciliation_id)
        path = self.paths.state_reconciliation / f"{reconciliation_id}.json"
        if not path.exists():
            raise ReconciliationError(
                f"Reconciliation '{reconciliation_id}' not found"
            )
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReconciliationError(
                f"Reconciliation '{reconciliation_id}' is not valid JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ReconciliationError(
                f"Reconciliation '{reconciliation_id}' must be a JSON object"
            )
        return payload

    def validate_breakglass_review(self, reconciliation_id: str) -> None:
        """Validate the full break-glass review chain for ``reconciliation_id``.

        Checks:
        1. Emergency record exists for the linked approval_id.
        2. Emergency record signature is valid.
        3. Emergency record has ``reviewed=True`` and a ``review_id``.
        4. Review record exists, signature is valid.
        5. Review record ``emergency_id`` and ``approval_id`` match.

        No-op for non-break-glass reconciliation records.
        Must be called inside the reconciliation lock boundary.
        """
        reconciliation = self.load(reconciliation_id)
        if reconciliation.get("source") != "breakglass":
            return

        approval_id = str(reconciliation.get("approval_id") or "")
        if not approval_id:
            raise ReconciliationError(
                f"Reconciliation '{reconciliation_id}' missing approval_id"
            )

        emergency_path = self._find_emergency_by_approval_id(approval_id)
        if emergency_path is None:
            raise ReconciliationError(
                f"No emergency record found for approval_id '{approval_id}'"
            )

        self.signing.verify_runtime_artifact(emergency_path)
        emergency = self._load_json_object(emergency_path, "Emergency record")

        if emergency.get("reviewed") is not True:
            raise ReconciliationError("Emergency has not been reviewed")

        review_id = str(emergency.get("review_id") or "")
        if not review_id:
            raise ReconciliationError(
                "Emergency marked reviewed but review_id missing"
            )

        review_path = self.paths.state_emergency_reviews / f"{review_id}.json"
        if not review_path.exists():
            raise ReconciliationError(
                f"Review record '{review_id}' not found"
            )

        self.signing.verify_runtime_artifact(review_path)
        review = self._load_json_object(review_path, "Review record")

        actual_emergency_id = emergency_path.stem
        if str(review.get("emergency_id") or "") != actual_emergency_id:
            raise ReconciliationError("Review record does not match emergency ID")
        if str(review.get("approval_id") or "") != approval_id:
            raise ReconciliationError("Review record does not match approval ID")

        recon_incident = reconciliation.get("incident_id")
        review_incident = review.get("incident_id")
        if recon_incident is not None and review_incident != recon_incident:
            raise ReconciliationError("Review record does not match incident ID")

    def complete(
        self,
        reconciliation_id: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> ReconciliationRecord:
        """Mark a reconciliation as completed and remove the gate file.

        For break-glass reconciliations, ``validate_breakglass_review()`` must
        pass before completion proceeds.
        """
        _validate_identifier("reconciliation_id", reconciliation_id)

        lock_names = ["governance", "emergency", "reconciliation"]
        with self.lock_manager.acquire_many(lock_names):
            reconciliation_path = (
                self.paths.state_reconciliation / f"{reconciliation_id}.json"
            )
            if not reconciliation_path.exists():
                raise ReconciliationError(
                    f"Reconciliation '{reconciliation_id}' not found"
                )

            self.signing.verify_runtime_artifact(reconciliation_path)

            payload = self.load(reconciliation_id)
            self.validate_breakglass_review(reconciliation_id)

            # Verify gate consistency BEFORE mutating any state.
            # Pre-fix, the gate check happened after writing the completed
            # record — a gate mismatch left a signed "completed" record on
            # disk with the gate still blocking activations.
            gate_value: str | None = None
            if self.paths.reconciliation_required.exists():
                gate_value = (
                    self.paths.reconciliation_required.read_text(
                        encoding="utf-8"
                    ).strip()
                )
                if gate_value and gate_value != reconciliation_id:
                    raise ReconciliationError(
                        f"Reconciliation gate points to '{gate_value}', "
                        f"not '{reconciliation_id}'"
                    )

            # Gate is consistent — commit record + signature + gate removal
            # as a single atomic transaction. A crash between write and sign
            # previously left a completed-but-invalid-signature record that
            # stranded the system (retry failed at verify_runtime_artifact).
            payload["status"] = "completed"
            payload["completed_at"] = utc_now_iso()

            from wpgovern.utils.transaction import AtomicTransaction
            from wpgovern.core.trust import TrustService

            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)
            trust_svc = TrustService(paths=self.paths)

            with AtomicTransaction(
                staging_root,
                service_label="ReconciliationService.complete",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=trust_svc,
            ) as txn:
                txn.stage_signed_json(
                    reconciliation_path,
                    payload,
                    self.signing,
                )
                if self.paths.reconciliation_required.exists():
                    txn.stage_delete(self.paths.reconciliation_required)
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type="reconciliation.complete",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={
                        **actor_context,
                        "reconciliation_id": reconciliation_id,
                        "status": payload.get("status"),
                    },
                )

            # Postcondition: gate must be gone before we declare success.
            # If the gate still exists after the AtomicTransaction, something
            # went wrong in commit() — fail loudly rather than returning
            # success with the gate still blocking activations.
            if self.paths.reconciliation_required.exists():
                raise ReconciliationError(
                    f"Reconciliation '{reconciliation_id}' record was committed "
                    "but the reconciliation gate file still exists. "
                    "Manual removal of the gate file is required."
                )

            return ReconciliationRecord(payload)

    def _find_emergency_by_approval_id(
        self, approval_id: str
    ) -> Path | None:
        if not self.paths.state_emergency.exists():
            return None
        for path in sorted(self.paths.state_emergency.glob("*.json")):
            if path.name.endswith(".sig.json"):
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if (
                isinstance(payload, dict)
                and str(payload.get("approval_id") or "") == approval_id
            ):
                return path
        return None

    def _load_json_object(self, path: Path, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReconciliationError(
                f"{label} '{path.name}' is not valid JSON: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise ReconciliationError(
                f"{label} '{path.name}' must be a JSON object"
            )
        return ReconciliationRecord(payload)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _validate_identifier(field: str, value: str) -> None:
    if not value.strip():
        raise ReconciliationError(f"{field} cannot be empty")
    if "/" in value or "\\" in value or ".." in value:
        raise ValidationError("invalid path separators")


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    data = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
