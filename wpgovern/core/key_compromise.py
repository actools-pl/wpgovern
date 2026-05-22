"""
WPGovern key-compromise recovery protocol.

``KeyCompromiseService`` orchestrates the five-step response to a
compromised signing key:

  1. Generate a replacement key in the affected trust domain.
  2. Activate the replacement key.
  3. Revoke the compromised key.
  4. Re-sign active governance artifacts with the replacement key (runtime domain).
  5. Write and sign a forensic compromise report.

Supported domains: ``runtime``, ``release``.

KNOWN_LIMITS: key-compromise partial failure (S-7). If the process is
killed between steps 1-3, the key state can be inconsistent (e.g.,
replacement generated but not activated, or activated but compromised
key not yet revoked). This is a known deferred limitation — see the
phase plan KNOWN_LIMITS table.

Locking note
------------
``TrustService`` acquires its own domain locks internally for each
lifecycle step. ``KeyCompromiseService`` must NOT hold any trust-domain
lock while calling ``TrustService`` lifecycle methods — doing so on the
same process would deadlock (POSIX ``flock`` is per-open-file-description,
not re-entrant across two distinct ``open()`` calls on the same path).
The governance lock and artifact re-sign locks are acquired AFTER all
``TrustService`` steps complete.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import WPGovernError
from wpgovern.paths import Paths, build_paths
from wpgovern.utils.locking import LockManager


class KeyCompromiseError(WPGovernError):
    """Raised for key-compromise protocol failures."""


@dataclass(frozen=True)
class CompromiseResult:
    """Result of a key-compromise recovery operation."""

    compromise_id: str
    domain: str
    compromised_key_id: str
    replacement_key_id: str
    report_path: Path
    re_signed_artifacts: list[str]
    failed_artifacts: list[str]


class KeyCompromiseService:
    """Key-compromise recovery protocol service.

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance.
        trust: ``TrustService`` instance.
        signing: ``SigningService`` instance.
        lock_manager: ``LockManager`` instance.
    """

    def __init__(
        self,
        config: object = None,
        paths: Paths | None = None,
        trust: TrustService | None = None,
        signing: SigningService | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        self.paths = paths or build_paths(config)
        self.lock_manager = lock_manager or LockManager(
            locks_dir=self.paths.locks_dir
        )
        self.trust = trust or TrustService(
            paths=self.paths, lock_manager=self.lock_manager
        )
        self.signing = signing or SigningService(
            paths=self.paths, trust=self.trust
        )

    def recover_runtime_key(
        self,
        compromised_key_id: str,
        replacement_key_id: str,
        reason: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> CompromiseResult:
        """Execute the runtime key-compromise recovery protocol."""
        return self._recover(
            domain="runtime",
            compromised_key_id=compromised_key_id,
            replacement_key_id=replacement_key_id,
            reason=reason,
            audit_logger=audit_logger,
            actor_context=actor_context,
        )

    def recover_release_key(
        self,
        compromised_key_id: str,
        replacement_key_id: str,
        reason: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> CompromiseResult:
        """Execute the release key-compromise recovery protocol."""
        return self._recover(
            domain="release",
            compromised_key_id=compromised_key_id,
            replacement_key_id=replacement_key_id,
            reason=reason,
            audit_logger=audit_logger,
            actor_context=actor_context,
        )

    def _recover(
        self,
        domain: str,
        compromised_key_id: str,
        replacement_key_id: str,
        reason: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> CompromiseResult:
        _validate_identifier("compromised_key_id", compromised_key_id)
        _validate_identifier("replacement_key_id", replacement_key_id)
        if compromised_key_id == replacement_key_id:
            raise KeyCompromiseError(
                "replacement_key_id must differ from compromised_key_id"
            )
        if not reason.strip():
            raise KeyCompromiseError("reason cannot be empty")

        store = self.trust.load_store(domain)  # type: ignore[arg-type]
        compromised = _find_key(store.keys, compromised_key_id)
        if compromised is None:
            raise KeyCompromiseError(
                f"{domain} key '{compromised_key_id}' not found"
            )
        if compromised.status == "revoked":
            raise KeyCompromiseError(
                f"{domain} key '{compromised_key_id}' is already revoked"
            )

        # Steps 1-3: TrustService acquires its own locks for each call.
        # No trust-domain locks held here — see module docstring.
        # IMPORTANT: no audit emits between these three calls. Each emit
        # is a potential failure point; if the audit chain is corrupt at
        # compromise time, the emit raises and leaves the trust state
        # partially mutated (replacement preactive, compromised still active).
        # All emits are batched after the trust state is secured and written
        # best-effort inside the lock block below.
        self.trust.generate_key(domain, replacement_key_id)  # type: ignore[arg-type]
        self.trust.activate_key(domain, replacement_key_id)  # type: ignore[arg-type]
        self.trust.revoke_key(domain, compromised_key_id, f"compromised: {reason}")  # type: ignore[arg-type]
        # Trust state is now secured: replacement is active, compromised is revoked.

        re_signed: list[str] = []
        failed: list[str] = []

        lock_names = ["governance"]
        if domain == "runtime":
            lock_names.extend([
                "approvals", "baselines", "active-state",
                "emergency", "reconciliation",
            ])

        with self.lock_manager.acquire_many(lock_names):
            if domain == "runtime":
                for artifact in self._runtime_artifacts_to_resign():
                    try:
                        if artifact.exists() and not artifact.name.endswith(
                            ".sig.json"
                        ):
                            self.signing.sign_runtime_artifact(artifact)
                            re_signed.append(str(artifact))
                    except Exception as exc:  # noqa: BLE001
                        failed.append(
                            f"{artifact}: {type(exc).__name__}: {exc}"
                        )

            import uuid as _uuid
            _stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            _suffix = _uuid.uuid4().hex[:8]
            compromise_id = f"key-compromise-{_stamp}-{_suffix}"
            report_path = (
                self.paths.state_dir / "key-compromises" / f"{compromise_id}.json"
            )
            payload = {
                "compromise_id": compromise_id,
                "domain": domain,
                "compromised_key_id": compromised_key_id,
                "replacement_key_id": replacement_key_id,
                "reason": reason,
                "recorded_at": _utcnow(),
                "re_signed_artifacts": re_signed,
                "failed_artifacts": failed,
                "status": "completed_with_failures" if failed else "completed",
            }
            self._atomic_write_and_sign(report_path, payload, domain=domain)

            if audit_logger is not None and actor_context is not None:
                # All four audit records are emitted here — after trust state
                # is secured and the report is written. Each emit is wrapped
                # individually so a corrupt or failing chain does not prevent
                # subsequent records from being attempted.
                # The trust state is safe regardless of whether these succeed.
                _actor = str(actor_context.get("actor_id") or "")
                _base = {**actor_context, "domain": domain}
                for _event, _details in [
                    (
                        f"trust.key.generated",
                        {**_base, "key_id": replacement_key_id},
                    ),
                    (
                        f"trust.key.activated",
                        {**_base, "key_id": replacement_key_id},
                    ),
                    (
                        "journal.key.revoked" if domain == "journal"
                        else "trust.key.revoked",
                        {**_base, "key_id": compromised_key_id,
                         "revoke_reason": f"compromised: {reason}"},
                    ),
                    (
                        f"key-compromise-{domain}",
                        {
                            **actor_context,
                            "key_id": compromised_key_id,
                            "domain": domain,
                            "revoke_reason": reason,
                            "target_id": str(report_path),
                            "status": payload["status"],
                        },
                    ),
                ]:
                    try:
                        audit_logger.emit(
                            event_type=_event,
                            actor=_actor,
                            outcome="success" if not failed else "warning",
                            details=_details,
                        )
                    except Exception:  # noqa: BLE001
                        # Best-effort: audit chain failure must not prevent
                        # the compromise response from being recorded as
                        # completed. The trust state is already secured.
                        pass

        return CompromiseResult(
            compromise_id=compromise_id,
            domain=domain,
            compromised_key_id=compromised_key_id,
            replacement_key_id=replacement_key_id,
            report_path=report_path,
            re_signed_artifacts=re_signed,
            failed_artifacts=failed,
        )

    def _runtime_artifacts_to_resign(self) -> Iterable[Path]:
        roots = [
            self.paths.baselines_dir,
            self.paths.approvals_dir,
            self.paths.state_supersessions,
            self.paths.state_rollbacks,
            self.paths.state_emergency,
            self.paths.state_emergency_reviews,
            self.paths.state_reconciliation,
        ]
        if self.paths.active_pointer.exists():
            yield self.paths.active_pointer
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(root.glob("*.json")):
                if path.name.endswith(".sig.json"):
                    continue
                yield path

    def _atomic_write_and_sign(
        self, report_path: Path, payload: dict, domain: str = "runtime"
    ) -> None:
        """Write a report JSON and its runtime-key signature sidecar atomically.

        η-3: ALL compromise reports are signed with the runtime key regardless
        of the key domain being compromised. The original conditional
        (if domain == "runtime") left release-domain compromise reports unsigned,
        making forensic evidence of release key compromise tamper-able.
        The runtime key is the authoritative signing key for governance audit
        evidence; using it for all domains gives release reports the same
        integrity guarantees as runtime reports.
        """
        from wpgovern.utils.transaction import AtomicTransaction
        staging_root = self.paths.root / "state" / ".transactions"
        staging_root.mkdir(parents=True, exist_ok=True)
        with AtomicTransaction(staging_root, service_label=None) as txn:
            txn.stage_signed_json(report_path, payload, self.signing)
            txn.commit()


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _find_key(keys, key_id: str):
    for key in keys:
        if key.key_id == key_id:
            return key
    return None


def _validate_identifier(field: str, value: str) -> None:
    if not value.strip():
        raise KeyCompromiseError(f"{field} cannot be empty")
    if "/" in value or "\\" in value or ".." in value:
        raise KeyCompromiseError(f"Invalid {field} '{value}'")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcnow_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def _atomic_write_json(path: Path, payload: dict) -> None:
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
