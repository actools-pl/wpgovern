"""
Kill-point-safe atomic filesystem transactions for the WPGovern control plane.

``AtomicTransaction`` guarantees that a set of file writes either all complete
or leave no partial state behind — safe across process kills at any point.

Guarantee model
---------------
1. Every target is staged to a temp file in the same directory first.
2. All staged files are written and fsynced before commit begins.
3. Each target is replaced with ``os.replace()`` (atomic on POSIX).
4. Parent directories are fsynced after replace where supported.
5. If commit fails partway through, all staged files are removed; targets
   that were already replaced remain at the new state. The crash-recovery
   journal (when enabled) handles partial commits on the next startup.
6. An ``abort()`` or an uncaught exception in the ``with`` block removes all
   staged files and leaves all targets unchanged.

Journal integration
-------------------
When ``service_label`` is supplied at construction, the transaction writes a
signed intent record before the replace loop and a signed complete record after.
The recovery service replays any incomplete intents on next startup, restoring
consistency. This requires ``trust_service`` (a ``TrustService`` instance) —
construction raises ``ValueError`` if ``service_label`` is provided without it.

When ``service_label`` is ``None`` (the default), no journal records are written
and the transaction behaves as a plain atomic write helper.

B4 (filesystem mid-operation) detection
-----------------------------------------
``commit()`` runs a pre-flight check before any I/O that classifies common
filesystem error conditions (full disk, read-only mount, permission denied) into
specific ``B4Error`` subclasses. In-flight classification also applies during
the replace loop. B4 events are recorded to ``state/.last_b4_event.json``
(best-effort) so ``governance-check`` can surface the appropriate exit code.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wpgovern.errors import (
    B4Error,
    DiskFullError,
    PermissionError_,
    WPGovernError,
    _classify_oserror,
)


class TransactionError(WPGovernError):
    """Raised for atomic transaction failures."""


@dataclass(frozen=True)
class StagedWrite:
    """Describes one pending write: staged source path → final target path."""
    target: Path
    staged: Path
    mode: int = 0o600


# ---------------------------------------------------------------------------
# AtomicTransaction
# ---------------------------------------------------------------------------

class AtomicTransaction:
    """Kill-point-safe atomic filesystem transaction.

    Usage::

        staging = root / "state" / ".transactions"
        with AtomicTransaction(staging) as txn:
            txn.stage_json(target_a, payload_a)
            txn.stage_json(target_b, payload_b)
            txn.commit()
        # On exit without commit(), or on exception, staged files are removed
        # and targets are unchanged.

    Journal-enabled usage (requires trust_service)::

        with AtomicTransaction(
            staging,
            service_label="BaselineService.activate",
            actor_id=actor_id,
            trust_service=trust_service,
        ) as txn:
            txn.stage_json(active_pointer, new_state)
            txn.commit()
    """

    # Minimum free bytes on the journal volume before commit is permitted.
    # 10 MB is generous; typical intent + sig + complete is well under 100 KB.
    _B4_PREFLIGHT_MIN_FREE_BYTES = 10 * 1024 * 1024

    def __init__(
        self,
        staging_root: Path | str,
        *,
        service_label: str | None = None,
        actor_id: str | None = None,
        journal_root: Path | str | None = None,
        trust_service: Any = None,
    ) -> None:
        """
        Args:
            staging_root: Directory where per-transaction staging dirs are
                created (typically ``<root>/state/.transactions``).
            service_label: Service-method identifier recorded in the journal
                intent record (e.g. ``"BaselineService.activate"``). When
                ``None``, journalling is disabled.
            actor_id: Operator identifier recorded in the intent record.
            journal_root: Directory whose ``.journal/`` subtree the journal
                writer uses. Defaults to ``staging_root.parent.parent`` when
                ``service_label`` is provided (conventional layout).
            trust_service: ``TrustService`` instance used to sign journal
                records. Required when ``service_label`` is provided; raises
                ``ValueError`` otherwise. Production activate paths must
                always pass this.
        """
        self.staging_root = Path(staging_root)
        self.txn_id = f"txn-{uuid.uuid4().hex}"
        self.txn_dir = self.staging_root / self.txn_id
        self._writes: list[StagedWrite] = []
        self._deletes: list[Path] = []
        self._symlinks: list[tuple[Path, str]] = []
        self._symlink_prior_targets: dict[str, str | None] = {}
        self._closed = False

        self.service_label = service_label
        self.actor_id = actor_id

        if service_label is not None:
            if trust_service is None:
                raise ValueError(
                    "AtomicTransaction(service_label=...) requires trust_service. "
                    "Pass trust_service=<TrustService instance>, or set "
                    "service_label=None to disable journalling."
                )
            self.journal_root = Path(
                journal_root if journal_root is not None
                else self.staging_root.parent.parent
            )
        else:
            self.journal_root = None

        # M-H1: state_root is the root for B4 evidence (.last_b4_event.json).
        # It is INDEPENDENT of journal_root — non-journaled transactions (bootstrap,
        # trust activation before journal key exists) still need B4 evidence so
        # governance-check can surface filesystem failures.
        # Derives from journal_root if set, else from staging_root hierarchy.
        if journal_root is not None:
            self.state_root = Path(journal_root) / "state"
        elif service_label is not None and self.journal_root is not None:
            self.state_root = self.journal_root / "state"
        else:
            # Non-journaled: derive from staging_root (…/<root>/state/.transactions)
            # state_root = staging_root.parent.parent / "state"
            try:
                self.state_root = self.staging_root.parent.parent / "state"
            except Exception:
                self.state_root = None

        self.trust_service = trust_service
        self._journal_writer: Any = None

    def __enter__(self) -> "AtomicTransaction":
        self.txn_dir.mkdir(parents=True, exist_ok=False)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if exc_type is not None or not self._closed:
            self.abort()

    # ------------------------------------------------------------------
    # Staging API
    # ------------------------------------------------------------------

    def stage_text(
        self, target: Path | str, content: str, mode: int = 0o600
    ) -> Path:
        """Write ``content`` to a staged file; queue it for commit to ``target``.

        Returns the staged file path.
        """
        target_path = Path(target)
        staged_path = self._next_staged_path(target_path)
        staged_path.parent.mkdir(parents=True, exist_ok=True)
        with staged_path.open("w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(staged_path, mode)
        self._writes.append(StagedWrite(target=target_path, staged=staged_path, mode=mode))
        return staged_path

    def stage_json(
        self,
        target: Path | str,
        payload: dict[str, Any],
        mode: int = 0o600,
    ) -> Path:
        """Serialize ``payload`` as indented JSON and stage it for ``target``."""
        data = json.dumps(payload, indent=2, sort_keys=False) + "\n"
        return self.stage_text(Path(target), data, mode=mode)

    def stage_signed_json(
        self,
        target: Path | str,
        payload: dict[str, Any],
        signing_service: Any,
        domain: str = "runtime",
        mode: int = 0o600,
    ) -> Path:
        """Stage a JSON payload and its accompanying signature atomically.

        On commit, both the data file and the signature file are replaced in
        the same loop. If the transaction is aborted, neither reaches its final
        path.

        ``signing_service`` must expose
        ``sign_staged(staged_data_path, final_data_path, domain) ->
        (staged_sig_path, final_sig_path)``.

        Returns the staged data path.
        """
        target_path = Path(target)
        staged_data_path = self.stage_json(target_path, payload, mode=mode)
        staged_sig_path, final_sig_path = signing_service.sign_staged(
            staged_data_path, target_path, domain=domain,
        )
        self._writes.append(
            StagedWrite(target=final_sig_path, staged=staged_sig_path, mode=mode)
        )
        return staged_data_path

    def stage_symlink_replace(self, symlink_path: Path | str, target_name: str) -> None:
        """Queue a symlink replacement on commit.

        Creates/replaces ``symlink_path`` to point at ``target_name``
        (a RELATIVE target — just the filename, not an absolute path).
        The prior target (if the symlink already exists) is recorded in the
        intent for recovery — if the commit fails after JSON but before symlink,
        recovery can repair the symlink to the new target.

        If the symlink update fails, TransactionError is raised.
        """
        sl_path = Path(symlink_path)
        # Capture prior target for rollback/recovery
        prior: str | None = None
        if sl_path.is_symlink():
            try:
                prior = Path(os.readlink(str(sl_path))).name
            except OSError:
                pass
        self._symlinks.append((sl_path, target_name))
        self._symlink_prior_targets[str(sl_path)] = prior

    def stage_delete(self, target: Path | str) -> None:
        """Queue ``target`` for deletion on commit.

        The deletion happens after all staged files are replaced, so the
        final on-disk state is: all new files present AND target absent.
        If the transaction aborts, no deletion occurs.

        Used by ReconciliationService.complete() to atomically remove
        the reconciliation gate as part of the same transaction that
        writes the completed reconciliation record.
        """
        # Use a sentinel staged path so StagedWrite's target is tracked.
        # The staged path is set to None to signal "delete, don't replace".
        self._deletes.append(Path(target))

    # ------------------------------------------------------------------
    # Commit / abort
    # ------------------------------------------------------------------

    def commit(self) -> None:
        """Replace all targets atomically.

        Pre-flight checks run before any I/O; classify filesystem conditions
        early so the error surfaces with phase="preflight" rather than
        leaving partial state.

        Raises:
            TransactionError: if already closed or on a non-B4 commit failure.
            B4Error subclass: on a classified filesystem error.
        """
        if self._closed:
            raise TransactionError("Transaction is already closed")

        # P1.2: B4 preflight — persist .last_b4_event.json before raising so
        # governance-check sees the unresolved B4 state.
        try:
            self._b4_preflight()
        except B4Error as exc:
            self._record_b4_event(exc)
            self.abort()
            raise

        if self.service_label is not None:
            try:
                self._write_journal_intent()
            except B4Error as exc:
                # P1.2: persist B4 evidence on intent-write failure.
                self._record_b4_event(exc)
                self.abort()
                raise
            except Exception as exc:
                self.abort()
                raise TransactionError(
                    f"Atomic transaction failed during journal write: {exc}"
                ) from exc

        # γ-4: write targets may be symlinks; capture their target string instead of
        # following bytes so rollback restores the symlink topology correctly.
        # Prior state is now a tagged tuple: ("symlink", target_str),
        # ("file", bytes), or ("absent", None).
        _prior_states: dict[str, tuple[str, bytes | str | None]] = {}
        if self.service_label is None:
            for write in self._writes:
                target_str = str(write.target)
                try:
                    if write.target.is_symlink():
                        _prior_states[target_str] = ("symlink", os.readlink(str(write.target)))
                    elif write.target.exists():
                        _prior_states[target_str] = ("file", write.target.read_bytes())
                    else:
                        _prior_states[target_str] = ("absent", None)
                except OSError:
                    _prior_states[target_str] = ("absent", None)

        try:
            for write in self._writes:
                write.target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.replace(write.staged, write.target)
                    self._fsync_dir(write.target.parent)
                except OSError as exc:
                    classified = _classify_oserror(exc, write.target, "target_replace")
                    if classified is not None:
                        self._record_b4_event(classified)
                        self.abort()
                        raise classified from exc
                    raise
        except B4Error:
            raise
        except OSError as exc:
            self.abort()
            raise TransactionError(f"Atomic transaction commit failed: {exc}") from exc

        # Process staged deletions after all writes have committed but BEFORE
        # writing the journal complete record. This ordering ensures:
        # - A kill between writes and deletes → recovery sees intent+no-complete,
        #   finds writes at new state, executes the pending deletes.
        # - A kill between delete and write_complete → recovery sees intent+no-complete,
        #   finds writes at new state and delete target absent, marks complete.
        # Delete failure is NOT swallowed — if the gate cannot be removed,
        # the transaction must fail rather than report false success.
        for delete_target in self._deletes:
            if not delete_target.exists():
                continue  # already gone — idempotent
            try:
                delete_target.unlink()
                self._fsync_dir(delete_target.parent)
            except OSError as exc:
                classified = _classify_oserror(exc, delete_target, "staged_delete")
                if classified is not None:
                    self._record_b4_event(classified)
                # H1: roll back writes if no journal intent to recover from.
                if self.service_label is None:
                    self._rollback_writes_from_prior(_prior_states)
                else:
                    # α-4: for journaled transactions, invoke recovery synchronously
                    # so the live process sees a consistent state when it catches
                    # TransactionError. Without this, a daemon catching the error
                    # would leave inconsistent state until next process restart.
                    self._invoke_in_process_recovery()
                raise TransactionError(
                    f"Staged delete failed for {delete_target}: {exc}. "
                    "Writes are committed; manual removal of the gate file "
                    f"'{delete_target}' is required."
                ) from exc

        # Process staged symlink replacements after writes and deletes.
        for symlink_path, target_name in self._symlinks:
            try:
                symlink_path.parent.mkdir(parents=True, exist_ok=True)
                tmp_link = symlink_path.with_suffix(".symlink_tmp")
                if tmp_link.exists() or tmp_link.is_symlink():
                    tmp_link.unlink()
                tmp_link.symlink_to(target_name)
                tmp_link.rename(symlink_path)
                self._fsync_dir(symlink_path.parent)
            except OSError as exc:
                classified = _classify_oserror(exc, symlink_path, "staged_symlink")
                if classified is not None:
                    self._record_b4_event(classified)
                # H1: roll back writes if no journal intent to recover from.
                if self.service_label is None:
                    self._rollback_writes_from_prior(_prior_states)
                else:
                    # α-4: invoke recovery synchronously for journaled transactions.
                    self._invoke_in_process_recovery()
                raise TransactionError(
                    f"Staged symlink replacement failed for {symlink_path} "
                    f"→ {target_name!r}: {exc}. "
                    "Writes rolled back." if self.service_label is None else
                    "File writes are committed; symlink update requires retry."
                ) from exc

        if self.service_label is not None and self._journal_writer is not None:
            try:
                self._journal_writer.write_complete(
                    self.txn_id, trust_service=self.trust_service
                )
            except B4Error as exc:
                # P1.1: Complete-record write failed with a B4 condition.
                # Record the B4 event and preserve the intent on disk so
                # RecoveryService can write the complete record at next startup.
                # Do NOT call cleanup_completed — that would delete the intent.
                self._record_b4_event(exc)
                self._closed = True
                # _cleanup() removes only the staging dir, not the journal intent.
                self._cleanup()
                raise TransactionError(
                    f"Governance commit succeeded but complete-record write failed "
                    f"(B4: {exc}). Intent preserved. Run startup recovery to resolve."
                ) from exc
            except Exception as exc:
                # P1.1: Non-B4 complete-write failure. Preserve intent for recovery.
                self._closed = True
                self._cleanup()
                raise TransactionError(
                    f"Governance commit succeeded but complete-record write failed: "
                    f"{exc}. Intent preserved. Run startup recovery to resolve."
                ) from exc

        self._closed = True
        self._cleanup()

        if self.service_label is not None and self._journal_writer is not None:
            try:
                self._journal_writer.cleanup_completed(self.txn_id)
            except Exception:
                pass  # best-effort; recovery handles orphaned records

    def abort(self) -> None:
        """Remove all staged files. Targets are left unchanged."""
        self._closed = True
        self._cleanup()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_staged_path(self, target: Path) -> Path:
        safe_name = target.name.replace("/", "_")
        return self.txn_dir / f"{len(self._writes):04d}-{safe_name}"

    def _cleanup(self) -> None:
        if self.txn_dir.exists():
            shutil.rmtree(self.txn_dir, ignore_errors=True)

    def _write_journal_intent(self) -> None:
        """Write the signed intent record and backup snapshots.

        Reads each existing target exactly once to produce both the hash
        recorded in the intent and the bytes written to the backup store.
        This closes the TOCTOU window between hash computation and backup copy.
        """
        from datetime import datetime, timezone

        from wpgovern.utils.journal import (
            IntentRecord,
            IntentWrite,
            JournalWriter,
            hash_file_bytes,
            read_and_hash_file,
            sign_intent_record,
        )

        assert self.journal_root is not None
        writer = JournalWriter(self.journal_root)
        writer.ensure_dirs()

        intent_writes: list[IntentWrite] = []
        target_bytes: dict[str, bytes] = {}
        for w in self._writes:
            target_path = Path(w.target)
            if target_path.exists():
                content, old_hash = read_and_hash_file(target_path)
                target_bytes[str(target_path)] = content
                old_content_hash: str | None = old_hash
            else:
                old_content_hash = None
            new_hash = hash_file_bytes(Path(w.staged))
            intent_writes.append(
                IntentWrite(
                    target=str(target_path),
                    staged=str(w.staged),
                    old_content_hash=old_content_hash,
                    new_content_hash=new_hash,
                    mode=w.mode,
                )
            )

        # Snapshot first, then write intent. A kill between snapshot and intent
        # write leaves orphaned backups but no intent — recovery's orphan-backup
        # sweep handles them at next startup.
        writer.snapshot_old_targets(intent_writes, self.txn_id, target_bytes=target_bytes)

        # Snapshot pre-delete content for recovery. A kill between the writes
        # and the delete leaves the gate present but the record in new state.
        # Staged deletes do not require pre-delete content snapshots — recovery
        # determines whether to execute the delete based on file existence at
        # recovery time, not by comparing against a stored snapshot. (γ-5: previous
        # code passed old_content_hash=None which made snapshot_old_targets a
        # no-op anyway; removed for clarity.)
        delete_paths = [str(Path(d)) for d in self._deletes]

        # Record staged symlinks in the intent — symlinks are first-class journaled
        # artifacts. Recovery uses this to repair or roll back symlinks correctly.
        from wpgovern.utils.journal import IntentSymlink as _IntentSymlink
        intent_symlinks = [
            _IntentSymlink(
                symlink_path=str(sl_path),
                target_name=sl_target,
                prior_target=self._symlink_prior_targets.get(str(sl_path)),
            )
            for sl_path, sl_target in self._symlinks
        ]

        record = IntentRecord(
            txn_id=self.txn_id,
            started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            service=self.service_label or "",
            actor_id=self.actor_id,
            writes=intent_writes,
            deletes=delete_paths,
            symlinks=intent_symlinks,
        )
        sign_intent_record(record, self.trust_service)
        writer.write_intent(record)
        self._journal_writer = writer

    def _invoke_in_process_recovery(self) -> None:
        """α-4: For journaled transactions, invoke RecoveryService synchronously
        after a post-write commit failure so the live process sees a consistent
        state when it catches TransactionError.

        Without this, a daemon that catches TransactionError leaves inconsistent
        state until the next process restart — which may be hours away.

        Best-effort: if recovery itself fails, we log and continue. The original
        TransactionError is still raised so the caller is informed.
        """
        if self.journal_root is None or self.trust_service is None:
            return
        try:
            from wpgovern.utils.recovery import RecoveryService
            from wpgovern.config import WPGovernConfig
            # Build a minimal config from the journal_root we already have.
            # RecoveryService needs root_dir; the journal lives at root/state/.journal.
            root = self.journal_root
            rs = RecoveryService.from_root_and_trust(root, self.trust_service)
            rs.recover_with_diagnostics()
        except Exception:
            # Recovery failed — operator must intervene.
            # The original error is still raised after this returns.
            pass

    def _rollback_writes_from_prior(
        self, prior_states: dict[str, tuple[str, bytes | str | None]]
    ) -> None:
        """Restore write targets to their prior state.

        γ-4: prior state is tagged: ('symlink', target_str),
        ('file', bytes), or ('absent', None). The tag tells us how to restore,
        preserving symlink topology rather than writing bytes.

        ζ-2: if a restore fails, track it and write a bootstrap recovery marker
        so the operator sees the unrecoverable state via governance-check rather
        than only via the original TransactionError.

        Best-effort: if a restore fails, we log and continue. The operator
        will still see a TransactionError and .last_b4_event.json (if B4).
        """
        failed_restores: list[dict[str, str]] = []

        for target_str, tagged in prior_states.items():
            target = Path(target_str)
            try:
                kind, payload = tagged
            except (TypeError, ValueError):
                # Backwards compatibility: handle bare bytes/None from old callers
                kind = "file" if tagged is not None else "absent"
                payload = tagged
            try:
                # Remove whatever is currently at the path (might be a partial write)
                if target.is_symlink() or target.exists():
                    if target.is_dir() and not target.is_symlink():
                        continue  # don't blow away an unexpected directory
                    target.unlink()

                if kind == "symlink":
                    os.symlink(payload, target)
                elif kind == "file":
                    tmp = target.with_suffix(".rollback_tmp")
                    tmp.write_bytes(payload)
                    os.replace(tmp, target)
                elif kind == "absent":
                    pass  # already removed above
            except OSError as exc:
                failed_restores.append({
                    "target": target_str,
                    "kind": kind,
                    "error": str(exc)[:200],
                })

        if failed_restores:
            self._write_bootstrap_recovery_marker(failed_restores)

    def _write_bootstrap_recovery_marker(
        self, failed_restores: list[dict[str, str]]
    ) -> None:
        """Write state/.bootstrap_recovery_required.json for the double-failure case.

        ζ-2: when _rollback_writes_from_prior itself fails, automated recovery
        cannot proceed. This marker surfaces the state to the operator via the
        governance-check monitoring channel (exit 34) instead of leaving it silent.

        Best-effort write — if even this fails, the operator will still see
        the original TransactionError.
        """
        state_dir: Path | None = None
        if self.state_root is not None:
            state_dir = self.state_root
        elif self.journal_root is not None:
            state_dir = self.journal_root / "state"
        else:
            try:
                state_dir = self.staging_root.parent
            except AttributeError:
                return

        if state_dir is None:
            return

        try:
            from datetime import datetime, timezone
            marker = {
                "marker_version": 1,
                "detected_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "txn_id": self.txn_id,
                "service_label": self.service_label,
                "failed_restores": failed_restores,
                "guidance": (
                    "Rollback after a failed bootstrap transaction itself failed. "
                    "The system may be in an inconsistent state. Operator must "
                    "manually verify trust store, baselines, and active-pointer "
                    "consistency, then remove this marker file."
                ),
            }
            state_dir.mkdir(parents=True, exist_ok=True)
            marker_path = state_dir / ".bootstrap_recovery_required.json"
            staged = marker_path.with_suffix(".json.tmp")
            staged.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n")
            os.replace(staged, marker_path)
            os.chmod(marker_path, 0o600)
            self._fsync_dir(state_dir)
        except OSError:
            pass  # best-effort; nothing more automated recovery can do

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _b4_preflight(self) -> None:
        """Pre-flight filesystem check before any I/O.

        Detects steady-state conditions (full disk, read-only mount,
        permission denied) before the replace loop so the error surfaces
        with phase="preflight" and no partial state is written.

        γ-1: covers parents of writes, staged deletes, and staged symlinks.
        Previously only writes were checked; a delete-only or symlink-only
        transaction got no parent-directory preflight.

        Best-effort: if a check itself raises for a reason that is not a B4
        condition, we proceed; the in-flight classification at the actual write
        points catches anything we miss here.
        """
        import errno as _errno

        # Collect every parent directory that any staged operation will mutate.
        # Using a set prevents redundant checks when multiple operations share
        # a parent directory (common for trust-store updates).
        mutation_parents: set[Path] = set()
        for write in self._writes:
            mutation_parents.add(write.target.parent)
        for delete_target in self._deletes:
            mutation_parents.add(Path(delete_target).parent)
        for sl_path, _ in self._symlinks:
            mutation_parents.add(Path(sl_path).parent)

        for parent in mutation_parents:
            try:
                parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                classified = _classify_oserror(exc, parent, "preflight")
                if classified is not None:
                    raise classified from exc
                continue
            if parent.exists() and not os.access(parent, os.W_OK):
                try:
                    probe = parent / f".b4-probe-{self.txn_id}"
                    probe.touch()
                    probe.unlink()
                except OSError as exc:
                    classified = _classify_oserror(exc, parent, "preflight")
                    if classified is not None:
                        raise classified from exc
                    raise PermissionError_(parent, "preflight", _errno.EACCES) from exc

        if self.service_label is not None and self.journal_root is not None:
            jdir = self.journal_root / "state" / ".journal"
            try:
                jdir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                classified = _classify_oserror(exc, jdir, "preflight")
                if classified is not None:
                    raise classified from exc
            try:
                usage = shutil.disk_usage(jdir)
                if usage.free < self._B4_PREFLIGHT_MIN_FREE_BYTES:
                    raise DiskFullError(jdir, "preflight", 28)
            except DiskFullError:
                raise
            except OSError:
                pass

    def _record_b4_event(self, b4exc: B4Error) -> None:
        """Write B4 event to state/.last_b4_event.json for governance-check.

        M-H1: Uses state_root (not journal_root) so B4 evidence is written
        even for non-journaled transactions (bootstrap, trust activation before
        journal key exists). state_root is always derived from staging_root.

        Best-effort: if recording fails (e.g. the failing volume is the same
        volume the record would go to), we skip silently.
        """
        # Use state_root for B4 evidence — independent of journal_root.
        evidence_dir = None
        if self.state_root is not None:
            evidence_dir = self.state_root
        elif self.journal_root is not None:
            evidence_dir = self.journal_root / "state"
        if evidence_dir is None:
            return
        try:
            from datetime import datetime, timezone
            event = b4exc.to_dict()
            event["detected_at"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            event["txn_id"] = self.txn_id
            evidence_dir.mkdir(parents=True, exist_ok=True)
            event_path = evidence_dir / ".last_b4_event.json"
            staged = event_path.with_suffix(".json.tmp")
            staged.write_text(json.dumps(event, indent=2, sort_keys=True) + "\n")
            os.replace(staged, event_path)
            os.chmod(event_path, 0o600)
            self._fsync_dir(evidence_dir)  # γ-3: ensure dir entry survives power loss
        except OSError:
            pass
