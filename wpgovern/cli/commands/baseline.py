"""CLI: baseline lifecycle and active-pointer commands."""
from __future__ import annotations

import typer

from wpgovern.audit.logger import AuditLogger
from wpgovern.cli._common import (
    ActorIdOption, ChangeTicketOption, ReasonOption,
    _actor_context, _config, _run_with_error_handling,
)
from wpgovern.core.baseline import BaselineService
from wpgovern.core.signing import SigningService

app = typer.Typer(add_completion=False)


@app.command("baseline-create")
def baseline_create(
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Create a signed draft baseline."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = BaselineService(config)
        audit_logger = AuditLogger(config)
        baseline_id = service.create_draft(audit_logger=audit_logger, actor_context=context)
        typer.echo(baseline_id)
    _run_with_error_handling(_impl)


@app.command("baseline-submit")
def baseline_submit(
    baseline_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Submit a draft baseline."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = BaselineService(config)
        audit_logger = AuditLogger(config)
        service.submit(baseline_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(baseline_id)
    _run_with_error_handling(_impl)


@app.command("baseline-approve")
def baseline_approve(
    baseline_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Approve a submitted baseline."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = BaselineService(config)
        audit_logger = AuditLogger(config)
        approval_id = service.approve(
            baseline_id,
            approved_by=str(context["actor_id"]),
            audit_logger=audit_logger,
            actor_context=context,
        )
        typer.echo(approval_id)
    _run_with_error_handling(_impl)


@app.command("baseline-activate")
def baseline_activate(
    baseline_id: str,
    approval_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Activate an approved baseline."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = BaselineService(config)
        audit_logger = AuditLogger(config)
        service.activate(
            baseline_id, approval_id,
            audit_logger=audit_logger, actor_context=context,
        )
        typer.echo(baseline_id)
    _run_with_error_handling(_impl)


@app.command("active-verify")
def active_verify() -> None:
    """Verify active-pointer integrity."""
    def _impl() -> None:
        service = SigningService(_config())
        service.verify_active_pointer()
        typer.echo("Active pointer OK")
    _run_with_error_handling(_impl)
