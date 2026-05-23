"""
WPGovern CLI — command assembler.

Imports each commands/*.py sub-module and registers its commands on the
shared Typer application. The entry point registered in pyproject.toml is
``wpgovern.cli:main``.

Startup recovery hook: ``main()`` runs ``RecoveryService.recover()`` before
dispatching any governance command. If recovery refuses any orphaned intent,
the process exits with an error. This enforces the fatal-on-refused contract
from design §5.3.

Skipped for help/version/fresh and no-args invocations — those don't touch
governance state and should work on bootstrapping paths.
"""

from __future__ import annotations

import sys

import typer

from wpgovern import __version__
from wpgovern.cli.commands import audit, baseline, journal, keys, misc, policy, status, trust

app = typer.Typer(
    add_completion=False,
    help="WPGovern governance control plane",
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Register all command sub-apps
for _sub in (misc.app, baseline.app, trust.app, policy.app, audit.app, status.app, journal.app, keys.app):
    for _cmd in _sub.registered_commands:
        app.registered_commands.append(_cmd)


def _should_skip_startup_recovery(argv: list[str]) -> bool:
    """Return True for invocations that should bypass the startup recovery hook."""
    if len(argv) <= 1:
        return True
    user_args = argv[1:]
    for arg in user_args:
        if arg in ("--help", "-h", "--version"):
            return True
    SKIP_COMMANDS = {"version", "fresh", "--install-completion", "--show-completion"}
    first = user_args[0] if user_args else ""
    return first in SKIP_COMMANDS


def _run_startup_recovery() -> None:
    """Run crash-recovery before any governance command."""
    from wpgovern.utils.recovery import RecoveryRefusedError, RecoveryService
    from wpgovern.config import DEFAULT_CONFIG

    try:
        config = DEFAULT_CONFIG
    except Exception:
        return  # bootstrap path: no config yet

    try:
        RecoveryService(config).recover()
    except RecoveryRefusedError as exc:
        typer.secho(f"ERROR: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    except Exception as exc:  # noqa: BLE001
        typer.secho(
            f"ERROR: startup recovery failed before command dispatch: {exc}\n"
            "Refusing to run any governance command until this is resolved.",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)


def main() -> None:
    """Entry point registered in pyproject.toml."""
    if not _should_skip_startup_recovery(sys.argv):
        _run_startup_recovery()
    app()


if __name__ == "__main__":
    main()
