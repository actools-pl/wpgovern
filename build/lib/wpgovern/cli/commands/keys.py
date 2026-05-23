"""CLI: key-compromise, trust-backup/restore, B4 event, and invariants commands."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import typer

from wpgovern.audit.logger import AuditLogger
from wpgovern.cli._common import (
    ActorIdOption, ChangeTicketOption, ReasonOption,
    _actor_context, _config, _echo_json, _run_with_error_handling,
)
from wpgovern.core.key_compromise import KeyCompromiseService
from wpgovern.errors import WPGovernError
from wpgovern.paths import build_paths

app = typer.Typer(add_completion=False)


@app.command("key-compromise-runtime")
def key_compromise_runtime(
    compromised_key_id: str,
    replacement_key_id: str,
    reason: str,
    actor_id: ActorIdOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Recover from a compromised runtime key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = KeyCompromiseService(config)
        audit_logger = AuditLogger(config)
        result = service.recover_runtime_key(
            compromised_key_id, replacement_key_id, reason,
            audit_logger=audit_logger, actor_context=context,
        )
        _echo_json({
            "compromise_id": result.compromise_id,
            "domain": result.domain,
            "compromised_key_id": result.compromised_key_id,
            "replacement_key_id": result.replacement_key_id,
            "report_path": str(result.report_path),
            "re_signed_artifacts": result.re_signed_artifacts,
            "failed_artifacts": result.failed_artifacts,
        })
    _run_with_error_handling(_impl)


@app.command("key-compromise-release")
def key_compromise_release(
    compromised_key_id: str,
    replacement_key_id: str,
    reason: str,
    actor_id: ActorIdOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Recover from a compromised release key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = KeyCompromiseService(config)
        audit_logger = AuditLogger(config)
        result = service.recover_release_key(
            compromised_key_id, replacement_key_id, reason,
            audit_logger=audit_logger, actor_context=context,
        )
        _echo_json({
            "compromise_id": result.compromise_id,
            "domain": result.domain,
            "compromised_key_id": result.compromised_key_id,
            "replacement_key_id": result.replacement_key_id,
            "report_path": str(result.report_path),
            "re_signed_artifacts": result.re_signed_artifacts,
            "failed_artifacts": result.failed_artifacts,
        })
    _run_with_error_handling(_impl)


@app.command("trust-backup")
def trust_backup(
    output: str = typer.Argument(...),
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Create an encrypted backup of the trust store."""
    def _impl() -> None:
        from wpgovern.core.trust_backup import TrustBackupError, create_trust_backup
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        trust_dir = config.root_dir / "trust"

        out_path = Path(output)
        if not str(out_path).endswith(".wpgov-trust-backup"):
            out_path = Path(str(out_path) + ".wpgov-trust-backup")

        typer.echo("Enter a passphrase to encrypt the backup.", err=True)
        passphrase = typer.prompt("Passphrase", hide_input=True, confirmation_prompt=True)
        if len(passphrase) < 12:
            raise typer.BadParameter("Passphrase must be at least 12 characters.")
        if any(ch in passphrase for ch in ("\n", "\r", "\x00")):
            raise typer.BadParameter(
                "Passphrase must not contain newlines, carriage returns, or NUL bytes."
            )

        try:
            result = create_trust_backup(trust_dir, out_path, passphrase)
        except TrustBackupError as exc:
            raise typer.BadParameter(str(exc))

        audit_logger = AuditLogger(config)
        audit_logger.emit(
            event_type="trust.backup.created",
            actor=str(context.get("actor_id") or ""),
            outcome="success",
            details={**context, "output_path": str(out_path), "size_bytes": result["size_bytes"], "algorithm": result["algorithm"]},
        )
        _echo_json(result)
    _run_with_error_handling(_impl)


@app.command("trust-restore")
def trust_restore(
    input_file: str = typer.Argument(...),
    confirm: bool = typer.Option(False, "--confirm"),
    force: bool = typer.Option(False, "--force"),
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Restore the trust store from an encrypted backup."""
    if not confirm:
        raise typer.BadParameter("Pass --confirm to acknowledge the restore operation.")
    if not reason:
        raise typer.BadParameter("--reason is required for the audit record.")

    def _impl() -> None:
        from wpgovern.core.trust_backup import TrustBackupError, restore_trust_backup
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        input_path = Path(input_file)
        passphrase = typer.prompt("Backup passphrase", hide_input=True)

        try:
            result = restore_trust_backup(input_path, config.root_dir, passphrase, force=force)
        except TrustBackupError as exc:
            raise typer.BadParameter(str(exc))

        audit_logger = AuditLogger(config)
        audit_logger.emit(
            event_type="trust.backup.restored",
            actor=str(context.get("actor_id") or ""),
            outcome="success",
            details={**context, "backup_source": result["backup_source"], "restored_to": result["restored_to"], "forced": force},
        )
        _echo_json(result)
    _run_with_error_handling(_impl)


@app.command("b4-status")
def b4_status() -> None:
    """Show the most recent B4 (filesystem) event, if any."""
    def _impl() -> None:
        config = _config()
        paths = build_paths(config)
        event_path = paths.root / "state" / ".last_b4_event.json"
        if not event_path.is_file():
            _echo_json({"status": "clean", "event": None})
            return
        try:
            payload = json.loads(event_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            _echo_json({"status": "unreadable", "error": f"{type(exc).__name__}: {exc}"})
            raise typer.Exit(33)
        if payload.get("resolved_at"):
            _echo_json({"status": "resolved", "event": payload})
            return
        _echo_json({"status": "active", "event": payload})
        cls = payload.get("class", "")
        exit_code = {"DiskFullError": 30, "ReadOnlyFilesystemError": 31,
                     "PermissionError_": 32, "ReadOnlyDuringRecoveryError": 33}.get(cls, 33)
        raise typer.Exit(exit_code)
    _run_with_error_handling(_impl)


@app.command("b4-clear")
def b4_clear(
    confirm: bool = typer.Option(False, "--confirm"),
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Mark the recorded B4 event as resolved."""
    if not confirm:
        raise typer.BadParameter("Pass --confirm to mark the B4 event as resolved.")
    if not reason:
        raise typer.BadParameter("--reason is required.")

    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        paths = build_paths(config)
        event_path = paths.root / "state" / ".last_b4_event.json"
        if not event_path.is_file():
            _echo_json({"status": "no_event", "message": "Nothing to clear."})
            return
        try:
            payload = json.loads(event_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            raise WPGovernError(f"Cannot read B4 event record: {exc}")
        if payload.get("resolved_at"):
            _echo_json({"status": "already_resolved", "event": payload})
            return
        payload["resolved_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload["resolved_by"] = str(context.get("actor_id") or "")
        payload["resolved_reason"] = reason
        staged = event_path.with_suffix(".json.tmp")
        staged.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        os.replace(staged, event_path)
        audit_logger = AuditLogger(config)
        audit_logger.emit(
            event_type="b4.cleared",
            actor=str(context.get("actor_id") or ""),
            outcome="success",
            details={**context, "b4_event": {
                "class": payload.get("class"),
                "errno_symbol": payload.get("errno_symbol"),
                "phase": payload.get("phase"),
                "path": payload.get("path"),
            }},
        )
        _echo_json({"status": "cleared", "event": payload})
    _run_with_error_handling(_impl)


@app.command("invariants-check")
def invariants_check() -> None:
    """Run the full on-disk invariant suite and surface any violations."""
    def _impl() -> None:
        from wpgovern.utils.invariants import check_all_invariants
        config = _config()
        violations = check_all_invariants(config)
        errors = [v for v in violations if v.severity == "error"]
        warnings = [v for v in violations if v.severity == "warning"]
        _echo_json({
            "status": "violations_found" if errors else "clean",
            "error_count": len(errors),
            "warning_count": len(warnings),
            "errors": [{"invariant_id": v.invariant_id, "description": v.description,
                        "details": v.details, "severity": v.severity} for v in errors],
            "warnings": [{"invariant_id": v.invariant_id, "description": v.description,
                          "details": v.details} for v in warnings],
        })
        if errors:
            raise typer.Exit(40)
    _run_with_error_handling(_impl)
