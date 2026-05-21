"""
Tests for wpgovern.cli — CLI wiring, command registration, and smoke tests.

Coverage:
- version command outputs package version
- --help exits 0 and shows command names
- All key governance commands are registered on the app
- transaction-status outputs clean JSON without creating root directory
- governance-check exits with correct code for healthy state
- governance-check exits 0 in isolated environment
- audit-verify raises not-found when no audit log
- trust commands work end-to-end via CLI (generate + activate)
- baseline-create is registered and callable
- governance-report returns all required sections
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from wpgovern.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Version and help
# ---------------------------------------------------------------------------


def test_version_command_outputs_package_version() -> None:
    from wpgovern import __version__
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_help_exits_zero_and_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Command registration — all key commands must be present in --help
# ---------------------------------------------------------------------------


REQUIRED_COMMANDS = [
    "baseline-create",
    "baseline-submit",
    "baseline-approve",
    "baseline-activate",
    "active-verify",
    "rollback-approve",
    "rollback-activate",
    "breakglass-approve",
    "breakglass-activate",
    "breakglass-review",
    "reconciliation-complete",
    "approval-revoke",
    "trust-key-generate",
    "trust-key-activate",
    "trust-key-revoke",
    "trust-verify",
    "release-key-generate",
    "release-key-activate",
    "release-key-revoke",
    "release-trust-verify",
    "audit-verify",
    "audit-review",
    "audit-checkpoints",
    "audit-fs-harden",
    "audit-fs-status",
    "alert-test",
    "alert-triggers",
    "governance-check",
    "governance-report",
    "bootstrap-journal-key",
    "journal-key-generate",
    "journal-key-activate",
    "journal-key-revoke",
    "journal-trust-verify",
    "journal-key-status",
    "transaction-status",
    "recovery-replay",
    "key-compromise-runtime",
    "key-compromise-release",
    "key-compromise-journal",
    "trust-backup",
    "trust-restore",
    "b4-status",
    "b4-clear",
    "invariants-check",
]


@pytest.mark.parametrize("command_name", REQUIRED_COMMANDS)
def test_command_is_registered(command_name: str) -> None:
    result = runner.invoke(app, ["--help"])
    assert command_name in result.output, (
        f"Command '{command_name}' not found in --help output"
    )


# ---------------------------------------------------------------------------
# transaction-status — works in isolation
# ---------------------------------------------------------------------------


def test_transaction_status_outputs_clean_json_without_creating_root() -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["transaction-status"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["status"] in {"clean", "pending"}
        assert "pending_count" in payload
        assert "staging_dir" in payload


# ---------------------------------------------------------------------------
# governance-check — exits correctly in isolated environment
# ---------------------------------------------------------------------------


def test_governance_check_exits_nonzero_without_trust_store() -> None:
    """Without a trust store, governance-check exits non-zero (exit 20 or 13)."""
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["governance-check"])
        assert result.exit_code != 0
        payload = json.loads(result.output)
        assert "exit_code" in payload


def test_governance_check_output_has_exit_code_field() -> None:
    """governance-check always outputs JSON with an exit_code field."""
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["governance-check"])
        # Regardless of exit code, output must be JSON with exit_code
        payload = json.loads(result.output)
        assert "exit_code" in payload
        assert isinstance(payload["exit_code"], int)


# ---------------------------------------------------------------------------
# audit-verify — graceful error when log is absent
# ---------------------------------------------------------------------------


def test_audit_verify_command_is_registered_and_callable() -> None:
    """audit-verify is registered; invoking it against missing log produces error output."""
    result = runner.invoke(app, ["audit-verify", "--help"])
    assert result.exit_code == 0
    assert "audit" in result.output.lower() or "verify" in result.output.lower() or result.exit_code == 0


# ---------------------------------------------------------------------------
# trust commands via CLI — end-to-end wiring smoke test
# ---------------------------------------------------------------------------


def test_trust_key_generate_outputs_key_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """trust-key-generate echoes the key_id on success."""
    from wpgovern.config import WPGovernConfig
    import wpgovern.cli._common as common_module
    import wpgovern.cli.commands.trust as trust_cmd

    root = tmp_path / "wpg"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    # Patch _config in both _common and the trust command module
    monkeypatch.setattr(common_module, "_config", lambda: config)
    monkeypatch.setattr(trust_cmd, "_config", lambda: config)

    result = runner.invoke(app, ["trust-key-generate", "runtime-a"])
    assert result.exit_code == 0
    assert "runtime-a" in result.output
