"""CLI: audit verification, review, checkpoints, filesystem hardening, and alerting."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import typer

from wpgovern.audit.fs_hardening import AuditFSHardener
from wpgovern.audit.logger import AuditLogger
from wpgovern.audit.verifier import AuditVerifier
from wpgovern.cli._common import (
    ActorIdOption, ChangeTicketOption, ReasonOption,
    _actor_context, _config, _echo_json, _run_with_error_handling,
)

app = typer.Typer(add_completion=False)


@app.command("audit-verify")
def audit_verify() -> None:
    """Verify audit-chain integrity."""
    def _impl() -> None:
        verifier = AuditVerifier(_config())
        result = verifier.verify()
        _echo_json({"ok": result.ok, "entries": result.entries, "message": result.message})
    _run_with_error_handling(_impl)


@app.command("audit-review")
def audit_review(
    auto_confirm: bool = typer.Option(False, "--auto-confirm"),
    status: str = typer.Option("clean", "--status"),
    json_output: bool = typer.Option(False, "--json", help="Emit only machine-readable JSON to stdout; suppress human review banner."),
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Conduct an attested audit review and record a checkpoint."""
    if auto_confirm and not reason:
        raise typer.BadParameter(
            "--auto-confirm requires --reason so the checkpoint record "
            "carries a meaningful attestation even without interactive review."
        )
    if status not in ("clean", "findings"):
        raise typer.BadParameter(f"Unknown status: {status!r}. Use 'clean' or 'findings'.")

    def _impl() -> None:
        from wpgovern.errors import IntegrityError

        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        verifier = AuditVerifier(config=config)
        audit_logger = AuditLogger(config)

        if verifier.paths.audit.exists():
            try:
                verifier.verify()
            except IntegrityError as exc:
                typer.secho(
                    f"ERROR: Audit chain integrity failure — cannot proceed "
                    f"with review until chain is repaired:\n  {exc}",
                    fg=typer.colors.RED, err=True,
                )
                raise typer.Exit(1)

        window = verifier.review_window()

        if not window.chain_ok:
            typer.secho(
                "ERROR: Audit chain integrity failure in review window:\n"
                + "\n".join(f"  {e}" for e in window.chain_errors),
                fg=typer.colors.RED, err=True,
            )
            raise typer.Exit(1)

        if window.records_in_window == 0:
            if not json_output:
                typer.echo(" Nothing to review \u2014 no records since last checkpoint.", err=True)
            _echo_json({"status": "nothing_to_review", "records": 0})
            return

        # Human-readable review banner — suppressed when --json is set.
        if not json_output:
            typer.echo(err=True)
            typer.echo("=" * 62, err=True)
            typer.echo(" WPGovern Audit Review", err=True)
            typer.echo("=" * 62, err=True)
            typer.echo(
                f" Period      : {window.period_start or '(empty)'}"
                f" \u2192 {window.period_end or '(empty)'}", err=True
            )
            typer.echo(f" Records     : {window.records_in_window}", err=True)
            typer.echo(f" Chain start : {window.start_hash[:16]}\u2026", err=True)
            typer.echo(f" Chain end   : {window.end_hash[:16]}\u2026", err=True)
            typer.echo(f" Chain OK    : {'\u2713' if window.chain_ok else '\u2717 BROKEN'}", err=True)
            typer.echo(err=True)

            if window.highlighted:
                typer.secho(
                    f" High-severity events ({len(window.highlighted)}):",
                    fg=typer.colors.YELLOW, err=True,
                )
                for ev in window.highlighted:
                    outcome_color = (
                        typer.colors.RED if ev["outcome"] == "failure"
                        else typer.colors.GREEN
                    )
                    typer.secho(
                        f"  [{ev['seq']:>5}] {ev['timestamp']}  "
                        f"{ev['event_type']:<35} actor={ev['actor']}",
                        fg=outcome_color, err=True,
                    )
                    if ev["details"]:
                        for k, v in ev["details"].items():
                            typer.echo(f"          {k}: {v}", err=True)
            else:
                typer.secho(
                    " No high-severity events in this period. \u2713",
                    fg=typer.colors.GREEN, err=True,
                )

            typer.echo(err=True)
            typer.echo("=" * 62, err=True)

        if not auto_confirm:
            if not json_output:
                typer.echo(
                    " Review the events above. Type 'yes' to sign off this period, or Ctrl+C to abort.",
                    err=True,
                )
            confirmation = typer.prompt("Sign off? (yes/no)", default="no")
            if confirmation.lower() not in ("y", "yes"):
                if not json_output:
                    typer.echo(" Review aborted. No checkpoint written.", err=True)
                raise typer.Exit(0)
        else:
            if not json_output:
                typer.echo(" --auto-confirm set. Recording checkpoint.", err=True)

        import uuid as _uuid
        checkpoint_id = f"cp-{_uuid.uuid4().hex[:12]}"
        checkpoint_details = {
            **context,
            "checkpoint_id": checkpoint_id,
            "review_period_start": window.period_start,
            "review_period_end": window.period_end,
            "records_reviewed": window.records_in_window,
            "highlighted_count": len(window.highlighted),
            "chain_start_hash": window.start_hash,
            "chain_end_hash": window.end_hash,
            "review_status": status,
        }
        record = audit_logger.emit(
            event_type="audit.review.checkpoint",
            actor=str(context.get("actor_id") or "operator"),
            outcome="success",
            details=checkpoint_details,
        )

        from wpgovern.core.trust import TrustService
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=config)
        try:
            sig = signing.sign_bytes(record.self_hash.encode("utf-8"), domain="runtime")
            audit_logger.emit(
                event_type="audit.checkpoint.signature",
                actor=str(context.get("actor_id") or "operator"),
                outcome="success",
                details={
                    "checkpoint_id": checkpoint_id,   # P1.4: explicit binding
                    "checkpoint_seq": record.seq,
                    "checkpoint_hash": record.self_hash,
                    "checkpoint_signature": sig,
                },
            )
            signed = True
        except Exception as exc:  # noqa: BLE001
            # Best-effort: if signing fails (e.g. no active runtime key),
            # the checkpoint is still written and hash-chained. Signing
            # failure is surfaced in the CLI output but does not abort.
            if not json_output:
                typer.secho(
                    f" ! Checkpoint written but signature failed: {exc}",
                    fg=typer.colors.YELLOW, err=True,
                )
            signed = False

        if not json_output:
            typer.echo(err=True)
            typer.secho(
                f" \u2713 Checkpoint written. Audit record seq={record.seq}, "
                f"hash={record.self_hash[:16]}\u2026"
                + (" [signed \u2713]" if signed else " [unsigned \u26a0]"),
                fg=typer.colors.GREEN if signed else typer.colors.YELLOW, err=True,
            )
            typer.echo(err=True)

        _echo_json({
            "checkpoint_written": True,
            "signed": signed,
            "seq": record.seq,
            "checkpoint_hash": record.self_hash,
            "review_period_start": window.period_start,
            "review_period_end": window.period_end,
            "records_reviewed": window.records_in_window,
            "review_status": status,
        })

    _run_with_error_handling(_impl)


@app.command("audit-checkpoints")
def audit_checkpoints() -> None:
    """List all attested audit review checkpoints in the chain."""
    def _impl() -> None:
        config = _config()
        from wpgovern.paths import build_paths
        ledger = build_paths(config).audit
        if not ledger.exists():
            _echo_json({"checkpoints": [], "message": "No audit log found."})
            return
        verifier = AuditVerifier(config)
        checkpoints = []
        with ledger.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("event_type") != "audit.review.checkpoint":
                        continue
                    d = record.get("details", {})
                    # Check for a companion signature record.
                    try:
                        signed = verifier.verify_checkpoint_signature(record)
                        sig_status = "signed" if signed else "unsigned"
                    except Exception as exc:
                        sig_status = f"signature_invalid: {exc}"
                    checkpoints.append({
                        "seq": record.get("seq"),
                        "reviewed_at": record.get("timestamp"),
                        "reviewed_by": record.get("actor"),
                        "review_period_start": d.get("review_period_start"),
                        "review_period_end": d.get("review_period_end"),
                        "records_reviewed": d.get("records_reviewed"),
                        "highlighted_count": d.get("highlighted_count"),
                        "review_status": d.get("review_status", "clean"),
                        "checkpoint_hash": record.get("self_hash", "")[:16] + "\u2026",
                        "signature_status": sig_status,
                    })
                except Exception:
                    pass
        _echo_json({"checkpoints": checkpoints, "total": len(checkpoints)})
    _run_with_error_handling(_impl)


@app.command("audit-fs-harden")
def audit_fs_harden(
    strict: bool = typer.Option(False, "--strict"),
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Apply filesystem hardening to the audit ledger."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        hardener = AuditFSHardener(build_paths(config).audit)
        audit_logger = AuditLogger(config)
        status = hardener.harden(
            strict=strict,
            audit_logger=audit_logger,
            actor_context=context,
        )
        _echo_json({
            "path": str(status.path),
            "exists": status.exists,
            "mode": status.mode,
            "append_only_supported": status.append_only_supported,
            "append_only_enabled": status.append_only_enabled,
        })
    _run_with_error_handling(_impl)


@app.command("audit-fs-status")
def audit_fs_status() -> None:
    """Report audit ledger filesystem hardening status."""
    def _impl() -> None:
        status = AuditFSHardener(build_paths(_config()).audit).status()
        _echo_json({
            "path": str(status.path),
            "exists": status.exists,
            "mode": status.mode,
            "append_only_supported": status.append_only_supported,
            "append_only_enabled": status.append_only_enabled,
        })
    _run_with_error_handling(_impl)


@app.command("alert-test")
def alert_test() -> None:
    """Fire a test alert through all configured sinks."""
    def _impl() -> None:
        from wpgovern.audit.alerter import alerter_from_config
        config = _config()
        alerter = alerter_from_config(config)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        alerter.maybe_alert(
            event_type="breakglass.approve",
            actor="alert-test",
            outcome="info",
            details={"reason": "operator-initiated test alert"},
            self_hash="test-" + "0" * 59,
            timestamp=timestamp,
        )
        _echo_json({
            "status": "test_alert_fired",
            "sinks": [s.get("type") for s in (
                getattr(config, "alert_sinks", None) or [{"type": "stderr"}]
            )],
        })
    _run_with_error_handling(_impl)


@app.command("alert-triggers")
def alert_triggers() -> None:
    """List the built-in alert triggers plus any configured extras."""
    def _impl() -> None:
        from wpgovern.audit.alerter import BUILTIN_ALERT_PREFIXES, BUILTIN_ALERT_TRIGGERS
        config = _config()
        extra = list(getattr(config, "alert_extra_triggers", None) or [])
        _echo_json({
            "builtin_exact": sorted(BUILTIN_ALERT_TRIGGERS),
            "builtin_prefixes": list(BUILTIN_ALERT_PREFIXES),
            "extra_configured": extra,
            "note": "builtin triggers cannot be removed; add extras via config",
        })
    _run_with_error_handling(_impl)
