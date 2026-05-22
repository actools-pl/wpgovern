"""CLI: governance-check and governance-report commands."""
from __future__ import annotations

import typer

from wpgovern.cli._common import _config, _echo_json, _run_with_error_handling
from wpgovern.status.checker import GovernanceChecker
from wpgovern.status.reporter import GovernanceReporter

app = typer.Typer(add_completion=False)


@app.command("governance-check")
def governance_check() -> None:
    """Return deterministic governance status for automation."""
    def _impl() -> None:
        checker = GovernanceChecker(_config())
        result = checker.check()
        _echo_json(result.as_dict())
        raise typer.Exit(result.exit_code)
    _run_with_error_handling(_impl)


@app.command("governance-report")
def governance_report() -> None:
    """Return structured governance status."""
    def _impl() -> None:
        reporter = GovernanceReporter(_config())
        _echo_json(reporter.report())
    _run_with_error_handling(_impl)
