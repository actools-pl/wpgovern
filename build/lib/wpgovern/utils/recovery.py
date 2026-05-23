"""
Crash-recovery routine — read path.

Reads orphaned in-flight commits from ``state/.journal/`` left by an
interrupted ``AtomicTransaction.commit`` and resolves them safely.

Invocation: ``RecoveryService(config).recover()`` runs at process startup,
before any mutating service acquires a lock. See the fatal-on-refused contract
below.

Fatal-on-refused contract
--------------------------
``recover()`` raises ``RecoveryRefusedError`` if any orphaned intent was
refused. The exception carries the full ``RecoveryResult`` as ``.result``.
This makes the contract un-ignorable through control flow — callers cannot
forget to check the result because an unchecked refused outcome raises rather
than returning silently.

Callers that genuinely want refused outcomes without raising — operator
tooling, diagnostics, audit verification — use ``recover_with_diagnostics()``
instead.

Recovery sequence for each intent (design §4)
----------------------------------------------
1. Read the intent record.  Malformed file → refuse.
2. Schema version check.  v1 records → refuse (only migrate-journal-v1-to-v2
   acts on v1).
3. Signature verification gate.  Any failure → refuse with service=None
   (the record's service field is untrusted until the signature passes).
4. Integrity hash check (defense-in-depth after the signature gate).
5. Complete record check.  If present: verify signature, verify txn_id
   binding, verify schema_version.
6. Classify writes (already_replaced / still_old / divergent).
7. Decide outcome: abandoned / completed / rolled_back / refused.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wpgovern.audit.logger import AuditError, AuditLogger
from wpgovern.errors import (
    WPGovernError,
    B4Error,
    ReadOnlyDuringRecoveryError,
    _classify_during_recovery,
)
from wpgovern.paths import build_paths
from wpgovern.utils.journal import (
    JOURNAL_SCHEMA_VERSION,
    IntentRecord,
    IntentWrite,
    JournalWriter,
    VERIFY_KEY_ID_MISSING,
    VERIFY_KEY_REVOKED,
    VERIFY_KEY_UNKNOWN,
    VERIFY_OK,
    VERIFY_SIGNATURE_INVALID,
    VERIFY_SIGNATURE_MISSING,
    compute_intent_integrity_hash,
    hash_file_bytes,
    list_complete_records,
    list_intent_records,
    read_and_hash_file,
    read_complete_record,
    read_intent_record,
    verify_complete_signature,
    verify_intent_signature,
)
from wpgovern.utils.locking import LockManager


class RecoveryError(WPGovernError):
    """Raised for recovery-internal failures that prevent the routine from
    running at all (e.g. unable to acquire the recovery lock).

    Distinct from RecoveryRefusedError, which is raised when recovery ran
    but found state it cannot safely resolve.
    """


class RecoveryRefusedError(WPGovernError):
    """Raised by ``recover()`` when one or more orphaned intents were refused.

    Carries the full RecoveryResult as ``.result`` so callers can produce
    informative diagnostics without re-running discovery.
    """

    def __init__(self, result: "RecoveryResult", message: str | None = None) -> None:
        self.result = result
        if message is None:
            message = (
                f"Recovery refused {result.refused_count} orphaned "
                f"transaction(s); inspect with `wpgovern recovery-replay "
                f"--list` and resolve via `wpgovern recovery-replay <txn_id>`."
            )
        super().__init__(message)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecoveryOutcome:
    """One outcome line in a recovery run's result."""

    txn_id: str
    event_type: str  # recovery.abandoned / completed / rolled_back / refused
    reason: str | None = None  # populated for recovery.refused only

    @property
    def refused(self) -> bool:
        return self.event_type == "recovery.refused"


@dataclass
class RecoveryResult:
    """Aggregated result from a single ``recover()`` invocation."""

    outcomes: list[RecoveryOutcome] = field(default_factory=list)
    audit_emit_failures: int = 0
    orphan_backup_dirs_swept: int = 0
    orphan_complete_files_swept: int = 0

    @property
    def any_refused(self) -> bool:
        return any(o.refused for o in self.outcomes)

    @property
    def refused_count(self) -> int:
        return sum(1 for o in self.outcomes if o.refused)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcnow_filesafe() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _classify_writes(
    intent: IntentRecord,
) -> tuple[list[IntentWrite], list[IntentWrite], list[IntentWrite]]:
    """Bucket each write into already_replaced, still_old, or divergent.

    A first-write target (old_content_hash=None) that is absent is "still_old".
    An existing target (old_content_hash != None) that is absent is "divergent".
    """
    already_replaced: list[IntentWrite] = []
    still_old: list[IntentWrite] = []
    divergent: list[IntentWrite] = []

    for w in intent.writes:
        target_path = Path(w.target)
        if not target_path.exists():
            if w.old_content_hash is None:
                still_old.append(w)
            else:
                divergent.append(w)
            continue

        actual_hash = hash_file_bytes(target_path)
        if actual_hash == w.new_content_hash:
            already_replaced.append(w)
        elif actual_hash == w.old_content_hash:
            still_old.append(w)
        else:
            divergent.append(w)

    return already_replaced, still_old, divergent


# ---------------------------------------------------------------------------
# RecoveryService
# ---------------------------------------------------------------------------


class RecoveryService:
    """Process-startup crash-recovery routine.

    Construction is cheap and non-mutating. ``recover()`` is the only method
    that touches disk. Idempotent: running twice produces the same outcome
    (the second run sees an empty journal and no-ops).

    Args:
        config: WPGovernConfig instance.
        lock_manager: LockManager instance. Created from paths if not provided.
        audit_logger: AuditLogger instance. Created lazily when needed.
    """

    @classmethod
    def from_root_and_trust(cls, root: Path, trust_service: Any) -> "RecoveryService":
        """α-4: Construct from root path and an existing TrustService.

        Used by AtomicTransaction._invoke_in_process_recovery() so recovery
        can be invoked synchronously within a live process without needing a
        full WPGovernConfig object.
        """
        from wpgovern.config import WPGovernConfig
        cfg = WPGovernConfig(
            root_dir=root,
            install_dir=root / "install",
            runtime_trust_store=root / "trust" / "runtime" / "public" / "trusted-runtime-keys.json",
            release_trust_store=root / "trust" / "release" / "public" / "trusted-release-keys.json",
            active_pointer=root / "state" / "active.json",
            audit_log=root / "audit" / "audit.log",
            alert_sinks=({"type": "none"},),
        )
        instance = cls(config=cfg)
        instance._trust = trust_service
        return instance

    def __init__(
        self,
        config: Any = None,
        lock_manager: LockManager | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.config = config
        self.paths = build_paths(config)
        self.root_dir = Path(self.paths.root)
        self.journal_dir = self.root_dir / "state" / ".journal"
        self.backups_dir = self.journal_dir / "backups"
        self.recovery_reports_dir = self.journal_dir / "recovery-reports"
        self.audit_emit_failures_dir = self.journal_dir / "audit-emit-failures"
        self.lock_manager = lock_manager or LockManager(locks_dir=self.paths.locks_dir)
        self._audit_logger = audit_logger
        self._trust: Any = None  # lazily constructed

    def _trust_service(self) -> Any:
        """Lazily construct (or return cached) TrustService for signature verification."""
        if self._trust is None:
            from wpgovern.core.trust import TrustService
            self._trust = TrustService(
                paths=self.paths,
                lock_manager=self.lock_manager,
            )
        return self._trust

    @staticmethod
    def _check_future_started_at(started_at: str) -> str | None:
        """Refuse intents whose started_at is more than one hour in the future.

        Returns None on healthy timestamps, or a refusal-reason string on
        violation. Malformed timestamps return None (structural issues are
        caught by the integrity hash check).
        """
        from datetime import timedelta

        try:
            ts = datetime.strptime(started_at, "%Y-%m-%dT%H:%M:%SZ")
            ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None
        now = datetime.now(timezone.utc)
        if ts > now + timedelta(hours=1):
            return f"intent_started_at_in_future ({started_at} > now+1h)"
        return None

    # -- public entry point ---------------------------------------------------

    def recover(self) -> RecoveryResult:
        """Resolve every orphaned in-flight commit.

        Raises RecoveryRefusedError if any intent was refused. On clean
        recovery, returns RecoveryResult.

        Use recover_with_diagnostics() to inspect refused outcomes without
        raising.
        """
        result = self.recover_with_diagnostics()
        if result.any_refused:
            raise RecoveryRefusedError(result)
        return result

    def recover_with_diagnostics(self) -> RecoveryResult:
        """Run recovery and return RecoveryResult unconditionally.

        Never raises on refused outcomes. The diagnostic / inspection entry
        point for operator tooling and tests that need to enumerate every
        outcome including refusals. Callers accept responsibility for
        honouring the fatal-on-refused contract (or explicitly opting out).
        """
        result = RecoveryResult()

        # Fast no-op: no journal directory. Common case on first start or
        # before any journal-enabled commit has run.
        if not self.journal_dir.exists():
            return result

        with self.lock_manager.acquire("recovery"):
            result.orphan_backup_dirs_swept = self._sweep_orphan_backup_dirs()
            result.orphan_complete_files_swept = self._sweep_orphan_complete_files()

            intent_paths = list_intent_records(self.journal_dir)
            if not intent_paths:
                return result

            complete_txn_ids = {p.stem for p in list_complete_records(self.journal_dir)}

            for intent_path in intent_paths:
                try:
                    outcome = self._process_one_intent(
                        intent_path, complete_txn_ids, result
                    )
                except ReadOnlyDuringRecoveryError as stuck:
                    self._handle_recovery_stuck(intent_path, stuck, result)
                    raise
                result.outcomes.append(outcome)

        return result

    # -- per-intent processing ------------------------------------------------

    def _process_one_intent(
        self,
        intent_path: Path,
        complete_txn_ids: set[str],
        result: RecoveryResult,
    ) -> RecoveryOutcome:
        """Resolve a single orphaned intent. Returns the outcome record.

        Never raises in normal recovery scenarios. Even "could not read the
        intent file" is converted to a recovery.refused outcome.

        Recovery sequence:
        1. Read intent (JSON errors → refuse, service=None)
        2. Schema version check (v1 → refuse; only migrate command acts on v1)
        3. Signature verification gate (any failure → refuse, service=None)
        4. Integrity hash check (defense-in-depth)
        5. Complete record check (5a: sig, 5b: txn_id binding, 5c: schema_version)
        6. Classify writes
        7. Decide outcome
        """
        txn_id = intent_path.stem

        # Step 1
        try:
            intent = read_intent_record(intent_path)
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            return self._refuse(
                txn_id, result, reason=f"intent record unreadable: {exc}", service=None,
            )
        except Exception as exc:
            # β-3: JournalSchemaError (missing/wrong schema_version) must surface
            # as recovery.refused rather than an uncaught exception.
            from wpgovern.errors import JournalSchemaError
            if isinstance(exc, JournalSchemaError):
                return self._refuse(
                    txn_id, result, reason=f"intent record schema error: {exc}", service=None,
                )
            raise

        # Step 2
        if intent.schema_version != JOURNAL_SCHEMA_VERSION:
            return self._refuse(
                txn_id, result,
                reason=f"unknown schema_version {intent.schema_version}",
                service=intent.service,
            )

        # Step 3: signature gate
        sig_result = verify_intent_signature(intent, self._trust_service())
        if sig_result == VERIFY_SIGNATURE_MISSING:
            return self._refuse(
                txn_id, result, reason="intent_signature missing",
                service=None, untrusted_record=intent,
                untrusted_signature_status=sig_result,
            )
        if sig_result == VERIFY_KEY_ID_MISSING:
            return self._refuse(
                txn_id, result, reason="intent_signature_key_id missing",
                service=None, untrusted_record=intent,
                untrusted_signature_status=sig_result,
            )
        if sig_result == VERIFY_KEY_UNKNOWN:
            return self._refuse(
                txn_id, result, reason="intent_signature_key_id unknown",
                service=None, untrusted_key_id_claimed=intent.intent_signature_key_id,
                untrusted_record=intent, untrusted_signature_status=sig_result,
            )
        if sig_result == VERIFY_KEY_REVOKED:
            return self._refuse(
                txn_id, result, reason="intent_signature_key_id revoked",
                service=None, untrusted_key_id_claimed=intent.intent_signature_key_id,
                untrusted_record=intent, untrusted_signature_status=sig_result,
            )
        if sig_result == VERIFY_SIGNATURE_INVALID:
            return self._refuse(
                txn_id, result, reason="intent_signature invalid",
                service=None, untrusted_key_id_claimed=intent.intent_signature_key_id,
                untrusted_record=intent, untrusted_signature_status=sig_result,
            )
        # sig_result == VERIFY_OK; record is authenticated.

        # Step 4: integrity hash (defense-in-depth)
        recomputed = compute_intent_integrity_hash(intent)
        if recomputed != intent.intent_integrity_hash:
            return self._refuse(
                txn_id, result,
                reason="intent_integrity_hash mismatch",
                service=intent.service,
            )

        # Future-timestamp check
        future_check = self._check_future_started_at(intent.started_at)
        if future_check is not None:
            return self._refuse(
                txn_id, result, reason=future_check, service=intent.service,
            )

        # Step 5: complete record check
        if txn_id in complete_txn_ids:
            complete_path = self.journal_dir / f"{txn_id}.complete"
            try:
                complete_record = read_complete_record(complete_path)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                return self._refuse(
                    txn_id, result,
                    reason=f"complete record unreadable: {exc}",
                    service=intent.service,
                )

            # 5a: complete record signature
            csig = verify_complete_signature(complete_record, self._trust_service())
            if csig != VERIFY_OK:
                reason_map = {
                    VERIFY_SIGNATURE_MISSING: "complete_signature missing",
                    VERIFY_KEY_ID_MISSING: "complete_signature_key_id missing",
                    VERIFY_KEY_UNKNOWN: "complete_signature_key_id unknown",
                    VERIFY_KEY_REVOKED: "complete_signature_key_id revoked",
                    VERIFY_SIGNATURE_INVALID: "complete_signature invalid",
                }
                return self._refuse(
                    txn_id, result,
                    reason=reason_map.get(csig, f"complete_signature failed: {csig}"),
                    service=intent.service,
                )

            # 5b: txn_id binding — prevents a renamed complete record from
            # silently skipping a partial commit.
            if complete_record.txn_id != intent.txn_id:
                return self._refuse(
                    txn_id, result, reason="complete_signature txn_id mismatch",
                    service=intent.service,
                    untrusted_key_id_claimed=complete_record.complete_signature_key_id,
                )

            # 5c: schema_version check on complete record
            if complete_record.schema_version != JOURNAL_SCHEMA_VERSION:
                return self._refuse(
                    txn_id, result,
                    reason=(
                        f"complete record unknown schema_version "
                        f"{complete_record.schema_version}"
                    ),
                    service=intent.service,
                )

            # All sub-checks passed. Honor the complete record.
            self._cleanup_artefacts(txn_id)
            self._emit_audit(
                "recovery.completed", "success", intent.service, txn_id, result,
                extra_details={"intent_signature_key_id": intent.intent_signature_key_id},
            )
            return RecoveryOutcome(txn_id=txn_id, event_type="recovery.completed")

        # Step 6: no complete record — classify writes
        already_replaced, still_old, divergent = _classify_writes(intent)

        if divergent:
            return self._refuse(
                txn_id, result,
                reason=f"{len(divergent)} target(s) diverged from intent",
                service=intent.service,
                divergent_count=len(divergent),
            )

        if not already_replaced:
            # Kill point 1: nothing replaced yet. Abandon.
            self._cleanup_artefacts(txn_id)
            self._emit_audit(
                "recovery.abandoned", "success", intent.service, txn_id, result,
                extra_details={"intent_signature_key_id": intent.intent_signature_key_id},
            )
            return RecoveryOutcome(txn_id=txn_id, event_type="recovery.abandoned")

        if not still_old:
            # Kill point 3 without complete record: all replaces landed.
            # Execute pending deletes and symlink replacements before writing
            # the complete record.
            pending_deletes = getattr(intent, "deletes", []) or []
            for del_path_str in pending_deletes:
                del_target = Path(del_path_str)
                if del_target.exists():
                    try:
                        del_target.unlink()
                    except OSError as exc:
                        from wpgovern.errors import _classify_during_recovery
                        classified = _classify_during_recovery(exc, del_target, "recovery_pending_delete")
                        if classified is not None:
                            try:
                                state_dir = self.paths.root / "state"
                                state_dir.mkdir(parents=True, exist_ok=True)
                                event = classified.to_dict()
                                event["detected_at"] = _utcnow()
                                event["txn_id"] = txn_id
                                event["context"] = "recovery_pending_delete"
                                event_path = state_dir / ".last_b4_event.json"
                                staged = event_path.with_suffix(".json.tmp")
                                staged.write_text(
                                    json.dumps(event, indent=2, sort_keys=True) + "\n"
                                )
                                os.replace(staged, event_path)
                                os.chmod(event_path, 0o600)
                            except OSError:
                                pass
                            self._emit_audit(
                                "recovery.stuck", "failure", intent.service, txn_id, result,
                                extra_details={"b4_event": classified.to_dict()},
                            )
                            return RecoveryOutcome(txn_id=txn_id, event_type="recovery.stuck")
                        return self._refuse(
                            txn_id, result,
                            reason=(
                                f"recovery could not execute staged delete for "
                                f"{del_path_str}: {exc}. Manual removal required."
                            ),
                            service=intent.service,
                        )

            # Execute pending symlink replacements.
            # H1: symlinks are now first-class journaled artifacts.
            # Recovery must repair symlinks that weren't yet updated.
            pending_symlinks = getattr(intent, "symlinks", []) or []
            for symlink_intent in pending_symlinks:
                sl_path = Path(symlink_intent.symlink_path)
                target_name = symlink_intent.target_name
                # Check if the symlink already points to the target (idempotent)
                already_correct = False
                if sl_path.is_symlink():
                    try:
                        import os as _os
                        current = Path(_os.readlink(str(sl_path))).name
                        already_correct = (current == target_name)
                    except OSError:
                        pass
                if not already_correct:
                    try:
                        sl_path.parent.mkdir(parents=True, exist_ok=True)
                        tmp_link = sl_path.with_suffix(".symlink_tmp")
                        if tmp_link.exists() or tmp_link.is_symlink():
                            tmp_link.unlink()
                        tmp_link.symlink_to(target_name)
                        tmp_link.rename(sl_path)
                    except OSError as exc:
                        from wpgovern.errors import _classify_during_recovery
                        classified = _classify_during_recovery(exc, sl_path, "recovery_pending_symlink")
                        if classified is not None:
                            try:
                                state_dir = self.paths.root / "state"
                                state_dir.mkdir(parents=True, exist_ok=True)
                                event = classified.to_dict()
                                event["detected_at"] = _utcnow()
                                event["txn_id"] = txn_id
                                event["context"] = "recovery_pending_symlink"
                                event_path = state_dir / ".last_b4_event.json"
                                staged_ev = event_path.with_suffix(".json.tmp")
                                staged_ev.write_text(
                                    json.dumps(event, indent=2, sort_keys=True) + "\n"
                                )
                                os.replace(staged_ev, event_path)
                                os.chmod(event_path, 0o600)
                            except OSError:
                                pass
                            self._emit_audit(
                                "recovery.stuck", "failure", intent.service, txn_id, result,
                                extra_details={"b4_event": classified.to_dict()},
                            )
                            return RecoveryOutcome(txn_id=txn_id, event_type="recovery.stuck")
                        return self._refuse(
                            txn_id, result,
                            reason=(
                                f"recovery could not repair symlink {sl_path} → "
                                f"{target_name!r}: {exc}."
                            ),
                            service=intent.service,
                        )

            # H2: verify post-conditions before emitting recovery.completed.
            # recovery.completed must mean "the system reached the intended end-state,"
            # not merely "the journaled steps were processed."
            # For trust activation: verify active.pem points to active_key_id.pem.
            post_condition_ok = True
            if pending_symlinks:
                for symlink_intent in pending_symlinks:
                    sl_path = Path(symlink_intent.symlink_path)
                    expected = symlink_intent.target_name
                    if sl_path.is_symlink():
                        try:
                            import os as _os
                            actual = Path(_os.readlink(str(sl_path))).name
                            if actual != expected:
                                post_condition_ok = False
                        except OSError:
                            post_condition_ok = False
                    else:
                        post_condition_ok = False

            if not post_condition_ok:
                return self._refuse(
                    txn_id, result,
                    reason=(
                        "recovery processed pending operations but post-condition "
                        "verification failed: symlink state does not match intent. "
                        "Manual repair required."
                    ),
                    service=intent.service,
                )
            # Write the complete record now and mark done.
            writer = JournalWriter(self.root_dir)
            try:
                writer.write_complete(txn_id, trust_service=self._trust_service())
            except Exception as exc:
                # H2/M1: a failure writing the complete record during recovery
                # must NOT bubble as a raw exception.
                # B4 → recovery.stuck (system needs operator intervention)
                # other → recovery.refused (structured refusal with reason)
                is_b4 = isinstance(exc, B4Error)
                if is_b4:
                    # Persist B4 evidence for governance-check
                    try:
                        state_dir = self.paths.root / "state"
                        state_dir.mkdir(parents=True, exist_ok=True)
                        event = exc.to_dict()
                        event["detected_at"] = _utcnow()
                        event["txn_id"] = txn_id
                        event["context"] = "recovery_complete_write"
                        event_path = state_dir / ".last_b4_event.json"
                        staged = event_path.with_suffix(".json.tmp")
                        staged.write_text(
                            json.dumps(event, indent=2, sort_keys=True) + "\n"
                        )
                        os.replace(staged, event_path)
                        os.chmod(event_path, 0o600)
                    except OSError:
                        pass
                    # Emit recovery.stuck — B4 means the system needs operator help
                    self._emit_audit(
                        "recovery.stuck", "failure", intent.service, txn_id, result,
                        extra_details={"b4_event": exc.to_dict()},
                    )
                    return RecoveryOutcome(txn_id=txn_id, event_type="recovery.stuck")
                else:
                    return self._refuse(
                        txn_id, result,
                        reason=(
                            f"recovery complete-write failed: {exc}. "
                            "Governance commit is complete but journal evidence is missing. "
                            "Manual recovery-replay required."
                        ),
                        service=intent.service,
                    )
            self._cleanup_artefacts(txn_id)
            self._emit_audit(
                "recovery.completed", "success", intent.service, txn_id, result,
                extra_details={"intent_signature_key_id": intent.intent_signature_key_id},
            )
            return RecoveryOutcome(txn_id=txn_id, event_type="recovery.completed")

        # Kill point 2: partial commit. Roll back from the backup store.
        try:
            restored, deleted = self._roll_back_partial(intent, already_replaced)
        except RecoveryError as exc:
            return self._refuse(txn_id, result, reason=str(exc), service=intent.service)

        report_path, report_hash = self._write_forensic_file(
            txn_id, intent, action="rolled_back",
            restored=restored, deleted=deleted, divergent=[],
        )
        self._emit_audit(
            "recovery.rolled_back", "success", intent.service, txn_id, result,
            extra_details={
                "targets_restored_count": len(restored),
                "targets_deleted_count": len(deleted),
                "recovery_report_id": report_path.name,
                "recovery_report_hash": report_hash,
                "intent_signature_key_id": intent.intent_signature_key_id,
            },
        )
        self._cleanup_artefacts(txn_id)
        return RecoveryOutcome(txn_id=txn_id, event_type="recovery.rolled_back")

    # -- rollback mechanics ---------------------------------------------------

    def _roll_back_partial(
        self,
        intent: IntentRecord,
        already_replaced: list[IntentWrite],
    ) -> tuple[list[str], list[str]]:
        """Restore each already-replaced target from its backup file.

        Strategy: verify ALL backups first, restore only after all pass.
        This prevents partial rollback that would leave some targets at
        old state and others at new — which is worse than the partial commit.

        Each backup file is read once into memory for both hash verification
        and restoration, preventing TOCTOU between verify and write.
        """
        per_txn_backup_dir = self.backups_dir / intent.txn_id

        # Phase 1: read + verify every required backup.
        verified_backup_bytes: dict[str, bytes] = {}
        for w in already_replaced:
            if w.old_content_hash is None:
                continue  # first-write target — rollback by deletion, no backup
            backup_path = per_txn_backup_dir / w.old_content_hash
            if not backup_path.exists():
                raise RecoveryError(
                    f"backup file missing for target {w.target} "
                    f"(expected {backup_path})"
                )
            backup_path_str = str(backup_path)
            if backup_path_str in verified_backup_bytes:
                continue
            content, actual_hash = read_and_hash_file(backup_path)
            if actual_hash != w.old_content_hash:
                raise RecoveryError(
                    f"backup file corrupted for target {w.target}: "
                    f"recorded hash {w.old_content_hash}, got {actual_hash}"
                )
            verified_backup_bytes[backup_path_str] = content

        # Phase 2: restore from in-memory verified bytes.
        restored: list[str] = []
        deleted: list[str] = []
        for w in already_replaced:
            target_path = Path(w.target)
            if w.old_content_hash is None:
                if target_path.exists():
                    try:
                        target_path.unlink()
                    except OSError as exc:
                        b4 = _classify_during_recovery(exc, target_path, "recovery_rollback")
                        if b4 is not None:
                            raise b4 from exc
                        raise
                deleted.append(str(target_path))
                continue

            backup_path = per_txn_backup_dir / w.old_content_hash
            backup_bytes = verified_backup_bytes[str(backup_path)]
            staged_path = target_path.with_suffix(target_path.suffix + ".recovery-staged")
            try:
                with staged_path.open("wb") as dst:
                    dst.write(backup_bytes)
                    dst.flush()
                    os.fsync(dst.fileno())
            except OSError as exc:
                b4 = _classify_during_recovery(exc, staged_path, "recovery_rollback")
                if b4 is not None:
                    raise b4 from exc
                raise
            try:
                os.chmod(staged_path, w.mode)
            except OSError:
                pass
            try:
                os.replace(staged_path, target_path)
            except OSError as exc:
                b4 = _classify_during_recovery(exc, target_path, "recovery_rollback")
                if b4 is not None:
                    raise b4 from exc
                raise
            try:
                fd = os.open(target_path.parent, os.O_RDONLY)
                try:
                    os.fsync(fd)
                except OSError:
                    pass
                finally:
                    os.close(fd)
            except OSError:
                pass
            restored.append(str(target_path))

        return restored, deleted

    # -- audit emission -------------------------------------------------------

    def _ensure_audit_logger(self) -> AuditLogger:
        if self._audit_logger is None:
            self._audit_logger = AuditLogger(
                config=self.config,
                paths=self.paths,
                lock_manager=self.lock_manager,
            )
        return self._audit_logger

    def _emit_audit(
        self,
        event_type: str,
        outcome: str,
        service: str | None,
        txn_id: str,
        result: RecoveryResult,
        extra_details: dict[str, Any] | None = None,
    ) -> None:
        """Emit a recovery audit record. Never blocks recovery.

        If AuditLogger.emit raises, the payload is written to a disk fallback
        file and recovery proceeds. Recovery's job is filesystem consistency;
        audit emission is best-effort relative to that.
        """
        details: dict[str, Any] = {"txn_id": txn_id}
        if service:
            details["service"] = service
        if extra_details:
            details.update(extra_details)

        try:
            logger = self._ensure_audit_logger()
            logger.emit(
                event_type=event_type,
                actor="recovery",
                outcome=outcome,
                details=details,
            )
        except Exception:  # noqa: BLE001
            self._write_audit_emit_failure(event_type, outcome, details, txn_id)
            result.audit_emit_failures += 1

    def _handle_recovery_stuck(
        self,
        intent_path: Path,
        stuck: ReadOnlyDuringRecoveryError,
        result: RecoveryResult,
    ) -> None:
        """Handle a B4 condition encountered inside the recovery rollback path.

        Emits ``recovery.stuck`` with the classified b4_event details, writes
        a forensic file, and records the B4 event for ``governance-check`` to
        surface as exit 33.

        Recovery does not continue after a stuck event. The intent remains on
        disk for retry after operator intervention.
        """
        txn_id = intent_path.stem
        b4_event = stuck.to_dict()
        b4_event["detected_at"] = _utcnow()

        try:
            self.recovery_reports_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "txn_id": txn_id,
                "action": "stuck",
                "recovered_at": _utcnow(),
                "b4_event": b4_event,
            }
            forensic_path = self.recovery_reports_dir / f"{txn_id}.json"
            staged = forensic_path.with_suffix(forensic_path.suffix + ".staged")
            staged.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            os.replace(staged, forensic_path)
        except OSError:
            import sys
            sys.stderr.write(f"[B4 stuck] forensic write failed for {txn_id}: {stuck}\n")

        self._emit_audit(
            event_type="recovery.stuck",
            outcome="failure",
            service=None,
            txn_id=txn_id,
            result=result,
            extra_details={"b4_event": b4_event},
        )

        try:
            state_dir = self.paths.root / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            event_path = state_dir / ".last_b4_event.json"
            event_record = dict(b4_event)
            event_record["txn_id"] = txn_id
            event_record["context"] = "recovery"
            staged = event_path.with_suffix(".json.tmp")
            staged.write_text(
                json.dumps(event_record, indent=2, sort_keys=True) + "\n"
            )
            os.replace(staged, event_path)
            os.chmod(event_path, 0o600)   # M1: invariant I-FS-6 requires 0600
        except OSError:
            pass

    def _write_audit_emit_failure(
        self,
        event_type: str,
        outcome: str,
        details: dict[str, Any],
        txn_id: str,
    ) -> None:
        try:
            self.audit_emit_failures_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.audit_emit_failures_dir, 0o700)
            except OSError:
                pass
            fallback_path = self.audit_emit_failures_dir / (
                f"{txn_id}-{_utcnow_filesafe()}.json"
            )
            payload = {
                "would_have_been_event_type": event_type,
                "would_have_been_outcome": outcome,
                "would_have_been_details": details,
                "actor": "recovery",
                "failed_at": _utcnow(),
            }
            fallback_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            try:
                os.chmod(fallback_path, 0o600)
            except OSError:
                pass
        except Exception:  # noqa: BLE001
            pass

    # -- helpers --------------------------------------------------------------

    def _refuse(
        self,
        txn_id: str,
        result: RecoveryResult,
        reason: str,
        service: str | None,
        divergent_count: int = 0,
        untrusted_key_id_claimed: str | None = None,
        untrusted_record: "IntentRecord | None" = None,
        untrusted_signature_status: str | None = None,
    ) -> RecoveryOutcome:
        """Refuse to recover one intent. Emits recovery.refused and leaves the
        intent + backups in place for operator inspection.
        """
        report_path, report_hash = self._write_forensic_file(
            txn_id, intent=None, action="refused",
            restored=[], deleted=[], divergent=[],
            reason=reason,
            untrusted_key_id_claimed=untrusted_key_id_claimed,
            untrusted_record=untrusted_record,
            untrusted_signature_status=untrusted_signature_status,
        )
        extra: dict[str, Any] = {
            "recovery_report_id": report_path.name,
            "recovery_report_hash": report_hash,
        }
        if divergent_count:
            extra["divergent_targets_count"] = divergent_count
        self._emit_audit(
            "recovery.refused", "failure", service, txn_id, result,
            extra_details=extra,
        )
        return RecoveryOutcome(txn_id=txn_id, event_type="recovery.refused", reason=reason)

    def _cleanup_artefacts(self, txn_id: str) -> None:
        """Remove journal artefacts for a resolved (non-refused) transaction."""
        for filename in (f"{txn_id}.intent", f"{txn_id}.complete"):
            p = self.journal_dir / filename
            try:
                if p.exists():
                    p.unlink()
            except OSError:
                pass
        per_txn_backup_dir = self.backups_dir / txn_id
        if per_txn_backup_dir.exists():
            shutil.rmtree(per_txn_backup_dir, ignore_errors=True)

    def _sweep_orphan_backup_dirs(self) -> int:
        """Remove backup directories with no matching intent file.

        Residue from a kill between snapshot and intent-write. No commit
        happened, so no audit record is needed.
        """
        if not self.backups_dir.exists():
            return 0
        count = 0
        for entry in self.backups_dir.iterdir():
            if not entry.is_dir():
                continue
            txn_id = entry.name
            if (self.journal_dir / f"{txn_id}.intent").exists():
                continue
            shutil.rmtree(entry, ignore_errors=True)
            count += 1
        return count

    def _sweep_orphan_complete_files(self) -> int:
        """Remove ``.complete`` files with no matching ``.intent`` file.

        Mirrors _sweep_orphan_backup_dirs. Cleans forensic clutter without
        any security effect — recovery only consults complete files for
        txn_ids that appear in the intent list.
        """
        if not self.journal_dir.exists():
            return 0
        count = 0
        for complete_path in self.journal_dir.glob("*.complete"):
            txn_id = complete_path.stem
            if (self.journal_dir / f"{txn_id}.intent").exists():
                continue
            try:
                complete_path.unlink()
                count += 1
            except OSError:
                pass
        return count

    def _write_forensic_file(
        self,
        txn_id: str,
        intent: IntentRecord | None,
        action: str,
        restored: list[str],
        deleted: list[str],
        divergent: list[IntentWrite],
        reason: str | None = None,
        untrusted_key_id_claimed: str | None = None,
        untrusted_record: "IntentRecord | None" = None,
        untrusted_signature_status: str | None = None,
    ) -> tuple[Path, str]:
        """Write a per-transaction forensic file and return (path, sha256).

        The caller emits the audit record AFTER this returns, using
        recovery_report_hash as a chain anchor on the externally-referenced
        file.
        """
        self.recovery_reports_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.recovery_reports_dir, 0o700)
        except OSError:
            pass

        payload: dict[str, Any] = {
            "txn_id": txn_id,
            "action": action,
            "recovered_at": _utcnow(),
        }
        if intent is not None:
            payload["service"] = intent.service
            payload["actor_id"] = intent.actor_id
            payload["started_at"] = intent.started_at
            payload["targets"] = [
                {
                    "target": w.target,
                    "old_content_hash": w.old_content_hash,
                    "new_content_hash": w.new_content_hash,
                }
                for w in intent.writes
            ]
            if intent.intent_signature_key_id:
                payload["intent_signature_key_id"] = intent.intent_signature_key_id

        if untrusted_key_id_claimed is not None or untrusted_record is not None:
            untrusted_block: dict[str, Any] = {}
            if untrusted_key_id_claimed is not None:
                untrusted_block["signature_key_id_claimed"] = untrusted_key_id_claimed
            if untrusted_record is not None:
                untrusted_block["service"] = untrusted_record.service
                untrusted_block["actor_id"] = untrusted_record.actor_id
                untrusted_block["started_at"] = untrusted_record.started_at
                untrusted_block["writes_count"] = len(untrusted_record.writes)
                untrusted_block["signature_present"] = bool(untrusted_record.intent_signature)
                if untrusted_signature_status is not None:
                    untrusted_block["signature_key_id_known"] = (
                        untrusted_signature_status not in (
                            VERIFY_KEY_UNKNOWN, VERIFY_KEY_ID_MISSING,
                        )
                    )
                    untrusted_block["signature_key_revoked"] = (
                        untrusted_signature_status == VERIFY_KEY_REVOKED
                    )
            payload["untrusted_record_fields"] = untrusted_block

        if restored:
            payload["restored_targets"] = restored
        if deleted:
            payload["deleted_targets"] = deleted
        if divergent:
            payload["divergent_targets"] = [w.target for w in divergent]
        if reason:
            payload["reason"] = reason

        report_path = self.recovery_reports_dir / f"{txn_id}.json"
        staged_path = report_path.with_suffix(report_path.suffix + ".staged")
        body = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        with staged_path.open("w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(staged_path, 0o600)
        except OSError:
            pass
        os.replace(staged_path, report_path)

        report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
        return report_path, report_hash
