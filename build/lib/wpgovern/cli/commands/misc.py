"""CLI: version and platform delegation commands."""
from __future__ import annotations

import typer

from wpgovern import __version__
from wpgovern.cli._common import _delegate_to_bash, _run_with_error_handling

app = typer.Typer(add_completion=False)


@app.command("version")
def cmd_version() -> None:
    """Print the CLI version."""
    typer.echo(__version__)


@app.command("fresh")
def fresh() -> None:
    """Delegate first-time platform/bootstrap installation to Bash."""
    _delegate_to_bash(["fresh"])


@app.command("update")
def update() -> None:
    """Delegate managed platform update to Bash."""
    _delegate_to_bash(["update"])


@app.command("repair")
def repair() -> None:
    """Delegate runtime invariant repair to Bash."""
    _delegate_to_bash(["repair"])


@app.command("status")
def platform_status() -> None:
    """Delegate platform status output to Bash."""
    _delegate_to_bash(["status"])


@app.command("logs")
def logs() -> None:
    """Delegate platform log streaming to Bash."""
    _delegate_to_bash(["logs"])


@app.command("restart")
def restart() -> None:
    """Delegate service restart to Bash."""
    _delegate_to_bash(["restart"])


@app.command("backup")
def backup() -> None:
    """Delegate backup execution to Bash."""
    _delegate_to_bash(["backup"])
