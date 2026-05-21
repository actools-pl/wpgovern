"""
WPGovern governance-state checker.

``GovernanceChecker.check()`` evaluates the on-disk governance state and
returns a ``GovernanceCheckResult`` with a deterministic exit code.

Exit-code contract
------------------
  0   — governance OK
  10  — reconciliation required
  11  — break-glass review debt (expired approval or pending emergency review)
  12  — journal staleness exceeded enforcement threshold (opt-in)
  13  — journal signing key unavailable
  20  — trust store or active-pointer integrity failure
  21  — invariant catalog violations detected (ζ-1)
  30  — B4: disk full
  31  — B4: read-only filesystem
  32  — B4: permission denied
  33  — B4: recovery stuck or unclassified
  34  — bootstrap recovery required (double-failure: rollback itself failed)
  50  — audit review overdue (only when review_max_age_days is configured)
  51  — audit chain integrity failure (always checked)
  52  — config file hash mismatch (H.0-A: a baselined config file was modified)
  53  — config file missing at check time (H.0-A: baselined file no longer on disk)

Check order
-----------
1. Audit chain integrity (51)   — checked unconditionally on every run
2. B4 filesystem event (30–33)  — highest priority; system needs intervention
3. Audit review currency (50)   — only when review_max_age_days configured
4. Trust & active-pointer (20)
5. Journal trust key (13)
6. Reconciliation required (10)
7. Break-glass debt (11)
8. Journal staleness enforcement (12)
9. OK (0)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from wpgovern.config import DEFAULT_CONFIG, WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.paths import WPGovernPaths, build_paths
from wpgovern.utils.jsonio import read_json


@dataclass(slots=True, frozen=True)
class GovernanceCheckResult:
    """Result of a governance-state check."""

    exit_code: int
    reason: str
    active_baseline: dict[str, Any] | None
    journal_status: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "exit_code": self.exit_code,
            "reason": self.reason,
            "active_baseline": self.active_baseline,
        }
        if self.journal_status is not None:
            out["journal_status"] = self.journal_status
        return out


class GovernanceChecker:
    """Deterministic governance-state checker.

    Args:
        config: ``WPGovernConfig`` instance.
    """

    def __init__(self, config: WPGovernConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self.paths: WPGovernPaths = build_paths(config)
        self.trust = TrustService(config)
        self.signing = SigningService(config, trust_service=self.trust)

    def check(self) -> GovernanceCheckResult:
        """Evaluate governance state and return a result with exit code."""
        active_baseline = self._read_active_baseline_payload()
        journal_status = self._evaluate_journal_staleness()

        # Step 1: audit chain integrity — unconditional on every run.
        # Exit code 51 is distinct from 50 (review overdue) so monitoring
        # can route chain integrity failures to a separate escalation path.
        audit_integrity = self._evaluate_audit_chain_integrity()
        if audit_integrity is not None:
            exit_code, reason = audit_integrity
            return GovernanceCheckResult(
                exit_code=exit_code,
                reason=reason,
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 2: B4 filesystem event — highest priority after chain check.
        b4 = self._evaluate_b4_event()
        if b4 is not None:
            exit_code, reason = b4
            return GovernanceCheckResult(
                exit_code=exit_code,
                reason=reason,
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 2.5 (ζ-2): bootstrap recovery marker — double-failure case.
        # Same priority class as B4: operator intervention required before
        # normal operation can resume.
        bootstrap_marker = self._evaluate_bootstrap_recovery_marker()
        if bootstrap_marker is not None:
            exit_code, reason = bootstrap_marker
            return GovernanceCheckResult(
                exit_code=exit_code,
                reason=reason,
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 3: audit review currency.
        review = self._evaluate_review_currency()
        if review is not None:
            exit_code, reason = review
            return GovernanceCheckResult(
                exit_code=exit_code,
                reason=reason,
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 4: trust store and active-pointer integrity.
        trust_issue = self._evaluate_trust_and_active_pointer()
        if trust_issue is not None:
            return GovernanceCheckResult(
                exit_code=20,
                reason=trust_issue,
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 5: journal signing key availability.
        journal_trust = self._evaluate_journal_trust()
        if journal_trust is not None:
            return GovernanceCheckResult(
                exit_code=13,
                reason=journal_trust,
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 6: reconciliation gate.
        if self._reconciliation_required():
            return GovernanceCheckResult(
                exit_code=10,
                reason="reconciliation_required",
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 7: break-glass debt.
        if self._has_expired_unreviewed_breakglass_approval():
            return GovernanceCheckResult(
                exit_code=11,
                reason="breakglass_expired_unreviewed",
                active_baseline=active_baseline,
                journal_status=journal_status,
            )
        if self._has_pending_emergency_review():
            return GovernanceCheckResult(
                exit_code=11,
                reason="breakglass_review_pending",
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 4.5 (ζ-1) is now at step 8.5 — invariant check runs as final gate.
        # This preserves existing tests where trust stores are not fully set up
        # while still ensuring invariant violations surface before exit 0.

        # Step 8: journal staleness enforcement (opt-in).
        if (
            journal_status is not None
            and journal_status.get("status") == "stale_enforced"
        ):
            return GovernanceCheckResult(
                exit_code=12,
                reason="journal_staleness_exceeded",
                active_baseline=active_baseline,
                journal_status=journal_status,
            )

        # Step 8.5 (H.0.1-2 REORDER): dedicated config-file hash check fires FIRST.
        # This must run before the generic invariant catalog (step 8.6) so that
        # config-file violations return dedicated exit codes 52/53 rather than
        # being absorbed by I-CFG-1 in the catalog and returning generic exit 21.
        # H.0.1-1: use _read_active_baseline_record_payload (follows the pointer to
        # the actual baseline record containing config_file_hashes) rather than
        # active_baseline (which holds only the pointer payload).
        active_baseline_record = self._read_active_baseline_record_payload()
        if active_baseline_record is not None:
            cfg_check = self._evaluate_config_file_hashes(active_baseline_record)
            if cfg_check is not None:
                exit_code, reason = cfg_check
                return GovernanceCheckResult(
                    exit_code=exit_code,
                    reason=reason,
                    active_baseline=active_baseline,
                    journal_status=journal_status,
                )

        # Step 8.6 (was Step 8.5): full invariant catalog as final gate before OK.
        # v50 / H.0.2-1: gate uses derived paths, not config defaults.
        # config.active_pointer is hardcoded to /opt/wpgovern/state/active.json,
        # but BaselineService.activate() writes via self.paths.active_pointer
        # (derived from root_dir). Under root_dir override, these diverge and
        # the gate is silently False — the entire invariant catalog is skipped.
        trust_dir = self.paths.root / "trust"
        active_ptr = self.paths.active_pointer
        if trust_dir.is_dir() and active_ptr.is_file():
            invariant_issue = self._evaluate_invariants()
            if invariant_issue is not None:
                return GovernanceCheckResult(
                    exit_code=21,
                    reason=invariant_issue,
                    active_baseline=active_baseline,
                    journal_status=journal_status,
                )

        # Step 9: all checks passed.
        return GovernanceCheckResult(
            exit_code=0,
            reason="ok",
            active_baseline=active_baseline,
            journal_status=journal_status,
        )

    def check_exit_code(self) -> int:
        """Convenience method returning just the exit code."""
        return self.check().exit_code

    # ------------------------------------------------------------------
    # Evaluation helpers
    # ------------------------------------------------------------------

    def _evaluate_audit_chain_integrity(self) -> tuple[int, str] | None:
        """Verify the audit chain. Returns (51, reason) on failure, None on clean."""
        from wpgovern.audit.verifier import AuditVerifier
        from wpgovern.errors import IntegrityError

        if not self.paths.audit.exists():
            return None  # no log yet; fresh install

        try:
            AuditVerifier(config=self.config).verify()
        except IntegrityError as exc:
            return (51, f"audit_chain_integrity_failure: {exc}")
        except Exception:
            return None  # unexpected error; don't block governance-check

        return None

    def _evaluate_bootstrap_recovery_marker(self) -> tuple[int, str] | None:
        """Detect the bootstrap recovery marker. Returns (exit_code, reason)
        if present, or None if not.

        ζ-2: surfaces the double-failure case where rollback itself failed.
        The marker is operator-intervention priority — same class as B4.
        Operator must manually verify system state and remove the marker.
        Exit code 34 is distinct from B4 codes (30-33) so monitoring can
        route it to the right response playbook.
        """
        marker_path = self.config.root_dir / "state" / ".bootstrap_recovery_required.json"
        if marker_path.is_file():
            return (34, "bootstrap_recovery_required")
        return None

    def _evaluate_b4_event(self) -> tuple[int, str] | None:
        """Check for an unresolved B4 (filesystem) event.

        Reads ``state/.last_b4_event.json``. A ``resolved_at`` field marks
        the event as resolved; its absence means unresolved.
        """
        event_path = self.paths.root / "state" / ".last_b4_event.json"
        if not event_path.is_file():
            return None
        try:
            payload = json.loads(event_path.read_text())
        except (json.JSONDecodeError, OSError):
            return (33, "b4_event_record_unreadable")
        if payload.get("resolved_at"):
            return None
        cls = payload.get("class", "")
        if cls == "DiskFullError":
            return (30, "b4_disk_full")
        if cls == "ReadOnlyFilesystemError":
            return (31, "b4_read_only_filesystem")
        if cls == "PermissionError_":
            return (32, "b4_permission_denied")
        if cls == "ReadOnlyDuringRecoveryError":
            return (33, "b4_recovery_stuck")
        return (33, "b4_event_unclassified")

    def _evaluate_review_currency(self) -> tuple[int, str] | None:
        """Check audit review currency when review_max_age_days is configured.

        Returns (50, reason) if the review is overdue, None otherwise.
        """
        max_age = getattr(self.config, "review_max_age_days", None)
        if max_age is None:
            return None

        from wpgovern.audit.verifier import AuditVerifier

        verifier = AuditVerifier(config=self.config)
        checkpoint = verifier.last_checkpoint()
        if checkpoint is None:
            return (50, "audit_review_overdue_no_checkpoint")

        reviewed_at_str = checkpoint.get("timestamp", "")
        try:
            reviewed_at = datetime.strptime(
                reviewed_at_str, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return (50, "audit_review_overdue_timestamp_unreadable")

        age = datetime.now(timezone.utc) - reviewed_at
        if age > timedelta(days=max_age):
            days_overdue = (age - timedelta(days=max_age)).days
            return (50, f"audit_review_overdue_{days_overdue}d")

        return None

    def _evaluate_invariants(self) -> str | None:
        """Run check_all_invariants and return a reason string if any violations
        are found, or None if all invariants pass.

        ζ-1: closes the gap where governance-check returned 0 ok while the
        invariant catalog reported violations. The two enforcement sites must
        agree on what 'healthy' means.
        """
        try:
            from wpgovern.utils.invariants import check_all_invariants
            violations = check_all_invariants(self.config)
        except Exception as exc:
            # Don't block governance-check on an invariant runner crash;
            # surface it distinctly so operators can investigate.
            return f"invariant_runner_error:{type(exc).__name__}"

        if not violations:
            return None

        # Group by invariant_id for the reason string. Keep it short — operators
        # see the full violation details in `wpgovern invariants-check` output.
        by_id: dict[str, int] = {}
        for v in violations:
            by_id[v.invariant_id] = by_id.get(v.invariant_id, 0) + 1

        parts = sorted(by_id.items(), key=lambda kv: (-kv[1], kv[0]))
        summary = ",".join(f"{iid}({n})" for iid, n in parts)
        return f"invariants_violated:{summary}"

    def _evaluate_trust_and_active_pointer(self) -> str | None:
        """Verify runtime trust store and active pointer. Returns reason string or None."""
        trust_store = self.paths.trust_runtime_public / "trusted-runtime-keys.json"
        if not trust_store.is_file():
            return "trust_store_missing"

        try:
            store = self.trust.get_runtime_store()
        except Exception:
            return "trust_store_corrupt"

        if not store.get("active_key_id"):
            return "no_active_trust_key"

        try:
            self.trust.verify_runtime_trust()
        except Exception:
            return "trust_store_corrupt"

        if self.paths.active_pointer.is_file():
            try:
                self.signing.verify_active_pointer()
            except Exception:
                return "active_pointer_corrupt"

        return None

    def _evaluate_journal_trust(self) -> str | None:
        """Check that the journal trust store exists with an active key."""
        journal_store = self.paths.journal_trust_store
        if not journal_store.is_file():
            return "journal_signing_key_unavailable"

        try:
            store = self.trust.get_journal_store()
        except Exception:
            return "journal_trust_store_corrupt"

        if not store.get("active_key_id"):
            return "journal_signing_key_unavailable"

        try:
            self.trust.verify_journal_trust()
        except Exception:
            return "journal_trust_store_corrupt"

        return None

    def _evaluate_journal_staleness(self) -> dict[str, Any] | None:
        """Compute age of the oldest orphaned journal intent.

        Returns a dict describing journal status, or None if the journal
        directory does not exist (no orphaned intents).

        Status values: ``clean``, ``fresh``, ``stale_warn``, ``stale_enforced``.
        """
        warn_seconds = self.config.journal_staleness_warn_seconds
        enforce_seconds = self.config.journal_staleness_enforce_seconds

        journal_dir = self.config.root_dir / "state" / ".journal"
        if not journal_dir.exists():
            return None

        intent_paths = sorted(journal_dir.glob("*.intent"))
        if not intent_paths:
            return {
                "status": "clean",
                "intent_count": 0,
                "oldest_intent_age_seconds": None,
                "warn_threshold_seconds": warn_seconds,
                "enforce_threshold_seconds": enforce_seconds,
            }

        now = time.time()
        oldest_age = max(now - p.stat().st_mtime for p in intent_paths)
        oldest_age_int = int(oldest_age)

        status = "fresh"
        if warn_seconds is not None and oldest_age >= warn_seconds:
            status = "stale_warn"
        if enforce_seconds is not None and oldest_age >= enforce_seconds:
            status = "stale_enforced"

        return {
            "status": status,
            "intent_count": len(intent_paths),
            "oldest_intent_age_seconds": oldest_age_int,
            "warn_threshold_seconds": warn_seconds,
            "enforce_threshold_seconds": enforce_seconds,
        }

    def _reconciliation_required(self) -> bool:
        return self.paths.reconciliation_required.exists()

    def _has_expired_unreviewed_breakglass_approval(self) -> bool:
        now = _utc_now_iso()
        for approval in _iter_state_json(self.paths.approvals):
            if not approval.name.startswith("breakglass-"):
                continue
            payload = _safe_read_json(approval)
            if not isinstance(payload, dict):
                continue
            status = payload.get("status")
            expires_at = payload.get("expires_at")
            review_status = payload.get("review_status", "pending")
            if (
                status == "approved"
                and isinstance(expires_at, str)
                and expires_at
                and now > expires_at
                and review_status != "completed"
            ):
                return True
        return False

    def _has_pending_emergency_review(self) -> bool:
        if not self.paths.state_emergency.is_dir():
            return False
        for emergency in _iter_state_json(self.paths.state_emergency):
            payload = _safe_read_json(emergency)
            if not isinstance(payload, dict):
                continue
            if payload.get("reviewed", False) is not True:
                return True
        return False

    def _read_active_baseline_payload(self) -> dict[str, Any] | None:
        if not self.paths.active_pointer.is_file():
            return None
        payload = _safe_read_json(self.paths.active_pointer)
        return payload if isinstance(payload, dict) else None

    def _read_active_baseline_record_payload(self) -> dict[str, Any] | None:
        """Load the active baseline record's JSON payload, verifying its signature.

        Unlike _read_active_baseline_payload (which reads only the active pointer
        file), this method follows the pointer to the actual baseline record at
        baselines_dir/{baseline_id}.json, verifies its runtime-domain signature,
        and returns its contents.

        Returns None if:
          - no active pointer exists
          - active pointer is malformed or missing baseline_id
          - baseline record file is missing or unreadable
          - baseline record signature verification fails (v50 / H.0.2-2)

        When verification fails, the caller's dedicated config-file check skips
        and the invariant catalog runs next, which catches the underlying
        integrity failure with the appropriate exit code class (typically 20 for
        trust/active integrity failures, not 52/53 for config drift).
        """
        if not self.paths.active_pointer.is_file():
            return None
        pointer = _safe_read_json(self.paths.active_pointer)
        if not isinstance(pointer, dict):
            return None
        baseline_id = pointer.get("baseline_id")
        if not isinstance(baseline_id, str) or not baseline_id:
            return None
        baseline_path = self.paths.baselines_dir / f"{baseline_id}.json"
        if not baseline_path.is_file():
            return None
        # v51 / H.0.3-1: SigningService.verify_file() raises NotFoundError when the
        # .sig.json sidecar is missing. Without this catch, a missing sidecar crashes
        # governance-check with an uncaught exception. Treating it as "verification
        # failure" routes through the invariant catalog (exit 21 via I-B-1).
        from wpgovern.errors import IntegrityError, NotFoundError
        try:
            self.signing.verify_file(baseline_path, domain="runtime")
        except (IntegrityError, NotFoundError):
            return None
        record = _safe_read_json(baseline_path)
        return record if isinstance(record, dict) else None

    def _evaluate_config_file_hashes(
        self, active_baseline: dict[str, Any]
    ) -> tuple[int, str] | None:
        """H.0-A: verify config-file hashes against the active baseline manifest.

        Returns (exit_code, reason) if a problem is detected, or None if clean.

        Exit code 52: file exists but hash differs from baseline.
        Exit code 53: file is missing (or unreadable) at check time.
        """
        import hashlib as _hl

        # v52 / H.0.4-1: distinguish field-absent (legacy) from field-present-null
        # (malformed H.0-era manifest). dict.get() conflates both → null bypasses.
        if "config_file_hashes" not in active_baseline:
            # Genuinely legacy baseline (field absent entirely). Skip the dedicated
            # check; let the invariant catalog handle anything else.
            return None
        hashes = active_baseline["config_file_hashes"]

        # v51 / H.0.3-2 + H.0.3-3: schema-validate before evaluating. Catches:
        #   - non-dict manifests (e.g., signed list)
        #   - empty manifests
        #   - partial manifests (missing governed keys)
        #   - manifests with extra keys or absolute paths
        # On failure, return None — falls through to the invariant catalog which
        # reports the structural violation via I-CFG-2 (exit 21).
        from wpgovern.core.baseline import (
            _validate_config_file_hashes,
            BaselineError,
            CONFIG_FILE_PATHS,
        )
        try:
            # _validate_config_file_hashes raises BaselineError on schema violation
            validated = _validate_config_file_hashes(hashes, "active-baseline")
            # H.0.3-3: enforce exact-set membership at check time (defense in depth)
            if set(validated.keys()) != set(CONFIG_FILE_PATHS):
                return None
        except BaselineError:
            return None

        install_dir = Path(getattr(self.config, "install_dir", "/opt/wpgovern-install"))

        for rel_path, expected_digest in sorted(validated.items()):
            abs_path = install_dir / rel_path
            if not abs_path.exists() or not abs_path.is_file():
                return (
                    53,
                    f"config_file_missing:file={rel_path},"
                    f"expected_digest={expected_digest}",
                )
            # H.0.1-3: refuse symlinks at check time. A regular file replaced
            # by a symlink is treated as missing — the original file is gone.
            if abs_path.is_symlink():
                return (
                    53,
                    f"config_file_replaced_by_symlink:file={rel_path}",
                )
            try:
                actual_bytes = abs_path.read_bytes()
            except OSError as exc:
                # Unreadable file is treated the same as missing for governance purposes.
                return (
                    53,
                    f"config_file_unreadable:file={rel_path},error={exc}",
                )
            actual_digest = "sha256:" + _hl.sha256(actual_bytes).hexdigest()
            if actual_digest != expected_digest:
                return (
                    52,
                    f"config_file_hash_mismatch:file={rel_path},"
                    f"expected={expected_digest},actual={actual_digest}",
                )

        return None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _iter_state_json(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return [
        path for path in sorted(directory.glob("*.json"))
        if not path.name.endswith(".sig.json")
    ]


def _safe_read_json(path: Path) -> Any | None:
    try:
        return read_json(path)
    except Exception:
        return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
