"""CLI: journal key management, transaction status, and recovery-replay commands."""
from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from wpgovern.audit.logger import AuditLogger
from wpgovern.cli._common import (
    ActorIdOption, ChangeTicketOption, ReasonOption,
    _actor_context, _config, _echo_json, _run_with_error_handling,
)
from wpgovern.core.trust import TrustService
from wpgovern.paths import build_paths

app = typer.Typer(add_completion=False)


@app.command("bootstrap-journal-key")
def bootstrap_journal_key(
    key_id: str = "journal-1",
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """First-time setup of the journal signing key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        from wpgovern.utils.locking import LockManager
        from wpgovern.utils.journal import list_intent_records, read_intent_record

        paths = build_paths(config)
        lock_manager = LockManager(locks_dir=paths.locks_dir)

        with lock_manager.acquire("recovery"):
            journal_dir = Path(paths.root) / "state" / ".journal"
            v1_intents = []
            for intent_path in list_intent_records(journal_dir):
                try:
                    intent = read_intent_record(intent_path)
                    if intent.schema_version == 1:
                        v1_intents.append(intent_path.stem)
                except Exception:
                    pass

            if v1_intents:
                lines = "\n  ".join(sorted(v1_intents))
                raise typer.BadParameter(
                    "Cannot bootstrap: schema_version=1 intents present in "
                    f"the journal:\n  {lines}\n\n"
                    "If you recognize these from your own operations, run\n"
                    "  wpgovern recovery-replay --acknowledge <txn_id>\n"
                    "to clear them. If you do NOT recognize them, delete the\n"
                    ".intent files directly from the journal directory, then\n"
                    "re-run bootstrap-journal-key."
                )

            service = TrustService(config)
            audit_logger = AuditLogger(config)
            service.generate_journal_key(key_id, audit_logger=audit_logger, actor_context=context)
            service.activate_journal_key(key_id, audit_logger=audit_logger, actor_context=context)
            typer.echo(key_id)

    _run_with_error_handling(_impl)


@app.command("journal-key-generate")
def journal_key_generate(
    key_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Generate a preactive journal trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.generate_journal_key(key_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("journal-key-activate")
def journal_key_activate(
    key_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Activate a journal trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.activate_journal_key(key_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("journal-key-revoke")
def journal_key_revoke(
    key_id: str,
    revoke_reason: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Revoke a journal trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or revoke_reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.revoke_journal_key(
            key_id, revoke_reason,
            audit_logger=audit_logger, actor_context=context,
        )
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("journal-trust-verify")
def journal_trust_verify() -> None:
    """Verify journal trust-store semantics."""
    def _impl() -> None:
        service = TrustService(_config())
        payload = service.verify_journal_trust()
        _echo_json(payload)
    _run_with_error_handling(_impl)


@app.command("journal-key-status")
def journal_key_status() -> None:
    """Inspect the journal trust store."""
    def _impl() -> None:
        from wpgovern.utils.journal import list_intent_records, read_intent_record
        config = _config()
        service = TrustService(config)
        store = service.get_journal_store()
        paths = build_paths(config)
        journal_dir = Path(paths.root) / "state" / ".journal"
        intent_counts: dict[str, int] = {}
        for intent_path in list_intent_records(journal_dir):
            try:
                intent = read_intent_record(intent_path)
                kid = intent.intent_signature_key_id or "(unsigned)"
                intent_counts[kid] = intent_counts.get(kid, 0) + 1
            except Exception:
                pass
        keys_payload = []
        for k in store.get("keys", []):
            keys_payload.append({
                "key_id": k.get("key_id"),
                "status": k.get("status"),
                "created_at": k.get("created_at"),
                "activated_at": k.get("activated_at"),
                "revoked_at": k.get("revoked_at"),
                "revocation_reason": k.get("revoke_reason"),
                "orphan_intent_count": intent_counts.get(k.get("key_id", ""), 0),
            })
        _echo_json({
            "active_key_id": store.get("active_key_id"),
            "keys": keys_payload,
            "total_orphan_intents": sum(intent_counts.values()),
        })
    _run_with_error_handling(_impl)


@app.command("transaction-status")
def transaction_status() -> None:
    """Report local transaction staging directory and journal state."""
    def _impl() -> None:
        from wpgovern.utils.journal import list_complete_records, list_intent_records
        config = _config()
        root = config.root_dir / "state" / ".transactions"
        pending = (
            sorted(path.name for path in root.glob("txn-*") if path.is_dir())
            if root.exists() else []
        )
        journal_dir = config.root_dir / "state" / ".journal"
        if journal_dir.exists():
            intent_paths = list_intent_records(journal_dir)
            complete_paths = list_complete_records(journal_dir)
            backups_dir = journal_dir / "backups"
            audit_emit_failures_dir = journal_dir / "audit-emit-failures"
            acknowledged_dir = journal_dir / "acknowledged"
            journal_status: dict = {
                "exists": True,
                "intent_count": len(intent_paths),
                "complete_count": len(complete_paths),
                "backup_dir_count": (
                    sum(1 for _ in backups_dir.iterdir()) if backups_dir.exists() else 0
                ),
                "audit_emit_failure_count": (
                    sum(1 for _ in audit_emit_failures_dir.iterdir())
                    if audit_emit_failures_dir.exists() else 0
                ),
                "acknowledged_intent_count": (
                    sum(1 for p in acknowledged_dir.iterdir() if p.suffix == ".intent")
                    if acknowledged_dir.exists() else 0
                ),
            }
        else:
            journal_status = {"exists": False}
        _echo_json({
            "staging_dir": str(root),
            "exists": root.exists(),
            "pending_transactions": pending,
            "pending_count": len(pending),
            "status": "clean" if not pending else "pending",
            "journal": journal_status,
        })
    _run_with_error_handling(_impl)


@app.command("recovery-replay")
def recovery_replay(
    txn_id: str = typer.Argument(None),
    list_intents: bool = typer.Option(False, "--list"),
    acknowledge: bool = typer.Option(False, "--acknowledge"),
) -> None:
    """Inspect or acknowledge orphaned intents left by a refused recovery."""
    def _impl() -> None:
        from wpgovern.utils.journal import (
            VERIFY_KEY_ID_MISSING, VERIFY_KEY_REVOKED, VERIFY_KEY_UNKNOWN,
            VERIFY_OK, VERIFY_SIGNATURE_INVALID, VERIFY_SIGNATURE_MISSING,
            list_complete_records, list_intent_records,
            read_intent_record, verify_intent_signature,
        )

        config = _config()
        root = config.root_dir
        journal_dir = root / "state" / ".journal"
        forensic_dir = journal_dir / "recovery-reports"
        acknowledged_dir = journal_dir / "acknowledged"

        if list_intents:
            if not journal_dir.exists():
                _echo_json({"intents": [], "journal_dir_exists": False})
                return
            try:
                trust_service = TrustService(config)
                store = trust_service.get_journal_store()
                active_kid = store.get("active_key_id")
            except Exception:
                trust_service = None
                active_kid = None

            intents_summary = []
            complete_ids = {p.stem for p in list_complete_records(journal_dir)}
            for intent_path in list_intent_records(journal_dir):
                tid = intent_path.stem
                try:
                    record = read_intent_record(intent_path)
                    summary = {
                        "txn_id": tid,
                        "service": record.service,
                        "started_at": record.started_at,
                        "actor_id": record.actor_id,
                        "writes": len(record.writes),
                        "has_complete_record": tid in complete_ids,
                        "intent_path": str(intent_path),
                        "schema_version": record.schema_version,
                        "signing_key_id": record.intent_signature_key_id or None,
                    }
                    if record.schema_version == 1:
                        summary["signature_status"] = "not_applicable_v1"
                    elif trust_service is None:
                        summary["signature_status"] = "trust_unavailable"
                    else:
                        sig_result = verify_intent_signature(record, trust_service)
                        if sig_result == VERIFY_OK:
                            summary["signature_status"] = (
                                "valid_active"
                                if record.intent_signature_key_id == active_kid
                                else "valid_retired"
                            )
                        else:
                            summary["signature_status"] = {
                                VERIFY_SIGNATURE_MISSING: "missing",
                                VERIFY_KEY_ID_MISSING: "key_id_missing",
                                VERIFY_KEY_UNKNOWN: "key_unknown",
                                VERIFY_KEY_REVOKED: "key_revoked",
                                VERIFY_SIGNATURE_INVALID: "invalid",
                            }.get(sig_result, sig_result)
                except Exception as exc:
                    summary = {
                        "txn_id": tid,
                        "error": f"could not read intent: {type(exc).__name__}: {exc}",
                        "intent_path": str(intent_path),
                    }
                intents_summary.append(summary)
            _echo_json({
                "intents": intents_summary,
                "intent_count": len(intents_summary),
                "journal_dir_exists": True,
            })
            return

        if not txn_id:
            typer.secho("ERROR: txn_id is required (or use --list to enumerate).",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(2)

        intent_path = journal_dir / f"{txn_id}.intent"
        forensic_path = forensic_dir / f"{txn_id}.json"

        if not intent_path.exists():
            typer.secho(f"ERROR: no intent record at {intent_path}.",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(2)

        if acknowledge:
            from wpgovern.utils.locking import LockManager
            paths = build_paths(config)
            lock_manager = LockManager(locks_dir=paths.locks_dir)
            with lock_manager.acquire("recovery"):
                if not intent_path.exists():
                    typer.secho(
                        f"ERROR: intent {txn_id} no longer exists (concurrent recovery).",
                        fg=typer.colors.RED, err=True,
                    )
                    raise typer.Exit(2)
                acknowledged_dir.mkdir(parents=True, exist_ok=True)
                try:
                    os.chmod(acknowledged_dir, 0o700)
                except OSError:
                    pass
                dest_intent = acknowledged_dir / intent_path.name
                os.replace(intent_path, dest_intent)
                try:
                    os.chmod(dest_intent, 0o600)
                except OSError:
                    pass
                if forensic_path.exists():
                    dest_forensic = acknowledged_dir / forensic_path.name
                    os.replace(forensic_path, dest_forensic)
                    try:
                        os.chmod(dest_forensic, 0o600)
                    except OSError:
                        pass
            _echo_json({"txn_id": txn_id, "acknowledged": True, "moved_to": str(acknowledged_dir)})
            return

        try:
            record = read_intent_record(intent_path)
            intent_summary = {
                "txn_id": record.txn_id,
                "service": record.service,
                "actor_id": record.actor_id,
                "started_at": record.started_at,
                "schema_version": record.schema_version,
                "writes": [
                    {
                        "target": w.target,
                        "old_content_hash": w.old_content_hash,
                        "new_content_hash": w.new_content_hash,
                    }
                    for w in record.writes
                ],
            }
        except Exception as exc:
            intent_summary = {"error": f"{type(exc).__name__}: {exc}"}

        forensic_summary = None
        if forensic_path.exists():
            try:
                forensic_summary = json.loads(forensic_path.read_text(encoding="utf-8"))
            except Exception as exc:
                forensic_summary = {"error": f"{type(exc).__name__}: {exc}"}

        _echo_json({
            "txn_id": txn_id,
            "intent": intent_summary,
            "forensic_file": str(forensic_path) if forensic_path.exists() else None,
            "forensic_report": forensic_summary,
            "next_steps": (
                "Use `wpgovern recovery-replay <txn_id> --acknowledge` "
                "after manually resolving the divergent state to allow "
                "the next startup to proceed."
            ),
        })

    _run_with_error_handling(_impl)


@app.command("key-compromise-journal")
def key_compromise_journal(
    compromised_key_id: str,
    reason: str,
    with_replacement: str = typer.Option(None, "--with-replacement"),
    actor_id: ActorIdOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Recover from a compromised journal-signing key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)

        with service.lock_manager.acquire("journal-trust"):
            store = service.get_journal_store()
            active_key_id = store.get("active_key_id")
            if compromised_key_id == active_key_id and not with_replacement:
                raise typer.BadParameter(
                    f"'{compromised_key_id}' is the active journal key; "
                    "you must pass --with-replacement <new_key_id>."
                )
            if with_replacement:
                service.generate_journal_key(with_replacement, audit_logger=audit_logger, actor_context=context)
                service.activate_journal_key(with_replacement, audit_logger=audit_logger, actor_context=context)
            service.revoke_journal_key(compromised_key_id, reason, audit_logger=audit_logger, actor_context=context)

            # Emit the headline compromise event so journal compromises have
            # the same audit visibility as runtime/release compromises.
            # Without this, BUILTIN_ALERT_TRIGGERS and REVIEW_HIGHLIGHT_EVENT_TYPES
            # both contain "key-compromise-journal" but it was never emitted —
            # auditors looking for "compromise" events would miss journal ones.
            audit_logger.emit(
                event_type="key-compromise-journal",
                actor=str(context.get("actor_id") or ""),
                outcome="success",
                details={
                    **context,
                    "key_id": compromised_key_id,
                    "domain": "journal",
                    "revoke_reason": reason,
                    "replacement_key_id": with_replacement,
                },
            )

        _echo_json({
            "compromised_key_id": compromised_key_id,
            "replacement_key_id": with_replacement,
            "revoked": True,
            "reason": reason,
        })
    _run_with_error_handling(_impl)


@app.command("prune-journal-key")
def prune_journal_key(
    key_id: str,
    confirm: bool = typer.Option(False, "--confirm"),
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Remove a retired-verify-only key from the journal trust store."""
    if not confirm:
        raise typer.BadParameter("Pruning is irreversible. Pass --confirm to proceed.")

    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)

        with service.lock_manager.acquire("journal-trust"):
            store = service.get_journal_store()
            keys = store.get("keys", [])
            target = next((k for k in keys if k.get("key_id") == key_id), None)
            if target is None:
                raise typer.BadParameter(f"Unknown journal key: {key_id}")
            status = target.get("status")
            if status == "active":
                raise typer.BadParameter(f"Cannot prune active key: {key_id}.")
            if status == "revoked":
                raise typer.BadParameter(f"Cannot prune revoked key: {key_id}.")

            from wpgovern.utils.journal import list_intent_records, read_intent_record
            paths = build_paths(config)
            journal_dir = Path(paths.root) / "state" / ".journal"
            for intent_path in list_intent_records(journal_dir):
                try:
                    intent = read_intent_record(intent_path)
                    if intent.intent_signature_key_id == key_id:
                        raise typer.BadParameter(
                            f"Cannot prune {key_id}: orphan intent {intent_path.stem} is signed by it."
                        )
                except Exception:
                    pass

            new_keys = [k for k in keys if k.get("key_id") != key_id]
            store["keys"] = new_keys
            paths_public = paths.journal_public_dir / f"{key_id}.pub"
            paths_private = paths.journal_private_dir / f"{key_id}.pem"
            for p in (paths_public, paths_private):
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass

            import json
            store_path = paths.journal_trust_store
            tmp_path = store_path.with_suffix(store_path.suffix + ".tmp")
            tmp_path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n")
            os.replace(tmp_path, store_path)

            audit_logger.emit(
                event_type="journal.key.pruned",
                actor=str(context.get("actor_id") or ""),
                outcome="success",
                details={**context, "key_id": key_id, "domain": "journal"},
            )

        _echo_json({"key_id": key_id, "pruned": True})
    _run_with_error_handling(_impl)


@app.command("migrate-journal-v1-to-v2")
def migrate_journal_v1_to_v2(
    txn_ids: list[str] = typer.Argument(None),
    migrate_without_review: bool = typer.Option(False, "--migrate-without-review"),
    reason: str = typer.Option(None, "--reason"),
    actor_id: ActorIdOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Convert v1 (unsigned) journal records to v2 (signed)."""
    if migrate_without_review and not reason:
        raise typer.BadParameter("--migrate-without-review requires --reason.")

    def _impl() -> None:
        from wpgovern.utils.journal import (
            JOURNAL_SCHEMA_VERSION,
            compute_intent_integrity_hash,
            list_intent_records,
            read_intent_record,
            sign_intent_record,
        )
        from wpgovern.utils.locking import LockManager

        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        paths = build_paths(config)
        lock_manager = LockManager(locks_dir=paths.locks_dir)
        trust = TrustService(config=config, lock_manager=lock_manager)
        audit_logger = AuditLogger(config)
        journal_dir = Path(paths.root) / "state" / ".journal"

        with lock_manager.acquire("recovery"), lock_manager.acquire("journal-trust"):
            candidates = []
            for intent_path in list_intent_records(journal_dir):
                try:
                    intent = read_intent_record(intent_path)
                    if intent.schema_version != 1:
                        continue
                    if txn_ids and intent.txn_id not in txn_ids:
                        continue
                    candidates.append((intent.txn_id, intent_path))
                except Exception:
                    pass

            if not candidates:
                _echo_json({"migrated": [], "skipped": [], "message": "No v1 records found."})
                return

            migrated = []
            skipped = []

            for txn_id, intent_path in candidates:
                if not migrate_without_review:
                    typer.echo(f"\n--- v1 intent: {txn_id} ---")
                    typer.echo(intent_path.read_text())
                    response = typer.prompt(f"Migrate {txn_id}? (yes/no/skip-all)", default="no")
                    if response == "skip-all":
                        skipped.append(txn_id)
                        break
                    if response.lower() not in ("y", "yes"):
                        skipped.append(txn_id)
                        continue

                intent = read_intent_record(intent_path)
                intent.schema_version = JOURNAL_SCHEMA_VERSION
                intent.intent_signature = ""
                intent.intent_signature_key_id = ""
                sign_intent_record(intent, trust)
                intent.intent_integrity_hash = compute_intent_integrity_hash(intent)

                staged_path = intent_path.with_suffix(intent_path.suffix + ".tmp")
                import json
                staged_path.write_text(json.dumps(intent.as_dict(), indent=2, sort_keys=True) + "\n")
                os.replace(staged_path, intent_path)

                audit_logger.emit(
                    event_type="journal.v1_migrated",
                    actor=str(context.get("actor_id") or ""),
                    outcome="success",
                    details={**context, "txn_id": txn_id, "without_review": migrate_without_review},
                )
                migrated.append(txn_id)

        _echo_json({"migrated": migrated, "skipped": skipped})
    _run_with_error_handling(_impl)
