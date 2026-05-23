"""CLI: trust and release key lifecycle commands."""
from __future__ import annotations

import typer
from pathlib import Path

from wpgovern.audit.logger import AuditLogger
from wpgovern.cli._common import (
    ActorIdOption, ChangeTicketOption, ReasonOption,
    _actor_context, _config, _echo_json, _run_with_error_handling,
)
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService

app = typer.Typer(add_completion=False)


@app.command("trust-key-generate")
def trust_key_generate(
    key_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Generate a preactive runtime trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.generate_runtime_key(key_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("trust-key-activate")
def trust_key_activate(
    key_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Activate a runtime trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.activate_runtime_key(key_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("trust-key-revoke")
def trust_key_revoke(
    key_id: str,
    revoke_reason: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Revoke a runtime trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or revoke_reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.revoke_runtime_key(key_id, revoke_reason, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("trust-verify")
def trust_verify() -> None:
    """Verify runtime trust-store semantics."""
    def _impl() -> None:
        service = TrustService(_config())
        payload = service.verify_runtime_trust()
        _echo_json(payload)
    _run_with_error_handling(_impl)


@app.command("release-key-generate")
def release_key_generate(
    key_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Generate a preactive release trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.generate_release_key(key_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("release-key-activate")
def release_key_activate(
    key_id: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Activate a release trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.activate_release_key(key_id, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("release-key-revoke")
def release_key_revoke(
    key_id: str,
    revoke_reason: str,
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Revoke a release trust key."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason or revoke_reason, change_ticket)
        config = _config()
        service = TrustService(config)
        audit_logger = AuditLogger(config)
        service.revoke_release_key(key_id, revoke_reason, audit_logger=audit_logger, actor_context=context)
        typer.echo(key_id)
    _run_with_error_handling(_impl)


@app.command("release-trust-verify")
def release_trust_verify() -> None:
    """Verify release trust-store semantics."""
    def _impl() -> None:
        service = TrustService(_config())
        payload = service.verify_release_trust()
        _echo_json(payload)
    _run_with_error_handling(_impl)


@app.command("release-sign")
def release_sign(
    version: str,
    dist_dir: str = "dist",
    actor_id: ActorIdOption = None,
    reason: ReasonOption = None,
    change_ticket: ChangeTicketOption = None,
) -> None:
    """Sign release artifacts."""
    def _impl() -> None:
        context = _actor_context(actor_id, reason, change_ticket)
        context["version"] = version
        context["source"] = str(Path(dist_dir))
        config = _config()
        service = SigningService(config)
        audit_logger = AuditLogger(config)
        manifest_path = service.sign_release(
            version, Path(dist_dir),
            audit_logger=audit_logger, actor_context=context,
        )
        typer.echo(str(manifest_path))
    _run_with_error_handling(_impl)


@app.command("release-verify")
def release_verify(dist_dir: str = "dist") -> None:
    """Verify release artifacts."""
    def _impl() -> None:
        service = SigningService(_config())
        service.verify_release(Path(dist_dir))
        typer.echo("Release verification OK")
    _run_with_error_handling(_impl)
