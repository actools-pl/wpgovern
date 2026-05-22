"""CLI: rollback, breakglass, reconciliation, and approval commands."""
from __future__ import annotations

import typer

from wpgovern.audit.logger import AuditLogger
from wpgovern.cli._common import (
    ActorIdOption, ChangeTicketOption, ReasonOption,
    _actor_context, _config, _echo_json, _run_with_error_handling,
)
from wpgovern.policy.approval import ApprovalService
from wpgovern.policy.breakglass import BreakglassService
from wpgovern.policy.reconciliation import ReconciliationService
from wpgovern.policy.rollback import RollbackService

app = typer.Typer(add_completion=False)


@app.command("rollback-approve")
def rollback_approve(
    target_baseline_id: str,
    rollback_reason: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Approve rollback to a target baseline."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or rollback_reason, change_ticket)
        config = _config()
        service = RollbackService(config)
        audit_logger = AuditLogger(config)
        approval_id = service.approve(
            target_baseline_id, rollback_reason,
            approved_by=str(context["actor_id"]),
            audit_logger=audit_logger, actor_context=context,
        )
        typer.echo(approval_id)
    _run_with_error_handling(_impl)


@app.command("rollback-activate")
def rollback_activate(
    approval_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Execute a rollback using a rollback approval."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = RollbackService(config)
        audit_logger = AuditLogger(config)
        result = service.activate(
            approval_id,
            audit_logger=audit_logger, actor_context=context,
        )
        _echo_json({
            "rollback_id": result.rollback_id,
            "approval_id": approval_id,
            "rolled_back_from": result.rolled_back_from,
            "rolled_back_to": result.rolled_back_to,
        })
    _run_with_error_handling(_impl)


@app.command("breakglass-approve")
def breakglass_approve(
    incident_id: str,
    justification: str,
    ttl_minutes: int,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Create a break-glass approval."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or justification, change_ticket)
        config = _config()
        service = BreakglassService(config)
        audit_logger = AuditLogger(config)
        approval_id = service.approve(
            incident_id, justification, ttl_minutes,
            approved_by=str(context["actor_id"]),
            audit_logger=audit_logger, actor_context=context,
        )
        typer.echo(approval_id)
    _run_with_error_handling(_impl)


@app.command("breakglass-activate")
def breakglass_activate(
    approval_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Activate emergency state using a break-glass approval."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = BreakglassService(config)
        audit_logger = AuditLogger(config)
        result = service.activate(
            approval_id,
            audit_logger=audit_logger, actor_context=context,
        )
        _echo_json({
            "approval_id": approval_id,
            "emergency_id": result.emergency_id,
            "reconciliation_id": result.reconciliation_id,
        })
    _run_with_error_handling(_impl)


@app.command("breakglass-review")
def breakglass_review(
    emergency_id: str,
    outcome: str,
    findings: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Record break-glass review."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or findings, change_ticket)
        config = _config()
        service = BreakglassService(config)
        audit_logger = AuditLogger(config)
        review_id = service.review(
            emergency_id, outcome, findings,
            reviewed_by=str(context["actor_id"]),
            audit_logger=audit_logger, actor_context=context,
        )
        typer.echo(review_id)
    _run_with_error_handling(_impl)


@app.command("reconciliation-complete")
def reconciliation_complete(
    reconciliation_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Complete reconciliation after required review validation."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = ReconciliationService(config)
        audit_logger = AuditLogger(config)
        record = service.complete(
            reconciliation_id,
            audit_logger=audit_logger, actor_context=context,
        )
        _echo_json(record)
    _run_with_error_handling(_impl)


@app.command("approval-revoke")
def approval_revoke(
    approval_id: str,
    revoke_reason: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Revoke an approval."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or revoke_reason, change_ticket)
        config = _config()
        service = ApprovalService(config)
        audit_logger = AuditLogger(config)
        record = service.revoke(
            approval_id, revoke_reason,
            audit_logger=audit_logger, actor_context=context,
        )
        _echo_json(record)
    _run_with_error_handling(_impl)
