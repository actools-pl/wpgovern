"""Shared helpers for all CLI command modules."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from wpgovern.config import DEFAULT_CONFIG, WPGovernConfig
from wpgovern.core.actor import resolve_actor_context
from wpgovern.errors import WPGovernError

ActorIdOption = Annotated[str | None, typer.Option("--actor-id", help="Explicit governance actor ID.")]
ReasonOption = Annotated[str | None, typer.Option("--reason", help="Governance reason for the operation.")]
ChangeTicketOption = Annotated[str | None, typer.Option("--change-ticket", help="External change ticket reference.")]


def _config() -> WPGovernConfig:
    return DEFAULT_CONFIG


def _echo_json(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=False))


def _default_actor() -> str:
    return os.environ.get("WPGOVERN_ACTOR_ID") or os.environ.get("USER") or "python-control-plane"


def _actor_context(
    actor_id: str | None = None,
    reason: str | None = None,
    change_ticket: str | None = None,
) -> dict[str, str | None]:
    return resolve_actor_context(actor_id or _default_actor(), reason, change_ticket)


def _resolve_bash_script() -> Path:
    env_path = os.environ.get("WPGOVERN_BASH_SCRIPT")
    candidates = [
        Path(env_path) if env_path else None,
        Path("/usr/local/bin/wpgovern.sh"),
        Path.cwd() / "wpgovern.sh",
        Path(sys.argv[0]).resolve().parent / "wpgovern.sh",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Unable to locate wpgovern.sh. Set WPGOVERN_BASH_SCRIPT or install the Bash wrapper."
    )


def _delegate_to_bash(args: list[str]) -> None:
    script = _resolve_bash_script()
    cmd = [str(script), *args]
    result = subprocess.run(cmd, check=False)
    raise typer.Exit(result.returncode)


def _run_with_error_handling(func) -> None:
    try:
        func()
    except FileNotFoundError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    except WPGovernError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    except subprocess.CalledProcessError as exc:
        typer.secho(
            f"ERROR: command failed with exit code {exc.returncode}: {exc.cmd}",
            fg=typer.colors.RED, err=True,
        )
        raise typer.Exit(exc.returncode or 1) from exc
