"""
Tests for wpgovern.audit.fs_hardening — AuditFSHardener, AuditFSStatus.

Coverage:
- ensure_restrictive_permissions creates log and directory with correct modes
- ensure_restrictive_permissions repairs permissive existing file
- AuditLogger enforces restrictive permissions on emit
- enable_append_only returns False when chattr is absent (no raise)
- enable_append_only strict=True raises AuditHardeningError when chattr absent
- enable_append_only strict=True raises on chattr failure
- status reports mode and append_only_supported=False when lsattr absent
- harden() with audit_logger emits audit.fs_harden event
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from wpgovern.audit.fs_hardening import AuditFSHardener, AuditHardeningError
from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.paths import Paths


# ---------------------------------------------------------------------------
# ensure_restrictive_permissions
# ---------------------------------------------------------------------------


def test_ensure_restrictive_permissions_creates_log_with_correct_modes(
    tmp_path: Path,
) -> None:
    audit_log = tmp_path / "audit" / "audit.log"
    hardener = AuditFSHardener(audit_log)
    hardener.ensure_restrictive_permissions()

    assert audit_log.exists()
    assert oct(audit_log.stat().st_mode & 0o777) == "0o600"
    assert oct(audit_log.parent.stat().st_mode & 0o777) == "0o700"


def test_ensure_restrictive_permissions_repairs_permissive_existing_file(
    tmp_path: Path,
) -> None:
    audit_log = tmp_path / "audit" / "audit.log"
    audit_log.parent.mkdir(parents=True)
    audit_log.write_text("", encoding="utf-8")
    os.chmod(audit_log, 0o666)
    os.chmod(audit_log.parent, 0o777)

    AuditFSHardener(audit_log).ensure_restrictive_permissions()

    assert oct(audit_log.stat().st_mode & 0o777) == "0o600"
    assert oct(audit_log.parent.stat().st_mode & 0o777) == "0o700"


def test_ensure_restrictive_permissions_is_idempotent(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit" / "audit.log"
    hardener = AuditFSHardener(audit_log)
    hardener.ensure_restrictive_permissions()
    hardener.ensure_restrictive_permissions()  # must not raise
    assert oct(audit_log.stat().st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------
# AuditLogger permission enforcement
# ---------------------------------------------------------------------------


def test_audit_logger_enforces_restrictive_permissions_on_emit(
    tmp_path: Path,
) -> None:
    paths = Paths(root=tmp_path / "wpg")
    logger = AuditLogger(paths=paths)
    logger.log("audit.test", "tester", "success", {"target_id": "x"})

    assert paths.audit.exists()
    assert oct(paths.audit.stat().st_mode & 0o777) == "0o600"
    assert oct(paths.audit.parent.stat().st_mode & 0o777) == "0o700"


# ---------------------------------------------------------------------------
# enable_append_only
# ---------------------------------------------------------------------------


def test_enable_append_only_returns_false_when_chattr_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_log = tmp_path / "audit.log"
    monkeypatch.setattr(shutil, "which", lambda name: None)

    hardener = AuditFSHardener(audit_log)
    assert hardener.enable_append_only(strict=False) is False


def test_enable_append_only_strict_raises_when_chattr_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_log = tmp_path / "audit.log"
    monkeypatch.setattr(shutil, "which", lambda name: None)

    with pytest.raises(AuditHardeningError, match="chattr not available"):
        AuditFSHardener(audit_log).enable_append_only(strict=True)


def test_enable_append_only_strict_raises_on_chattr_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_log = tmp_path / "audit.log"
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/chattr" if name == "chattr" else None)

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout="", stderr="not permitted"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(AuditHardeningError, match="not permitted"):
        AuditFSHardener(audit_log).enable_append_only(strict=True)


def test_enable_append_only_non_strict_returns_false_on_chattr_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_log = tmp_path / "audit.log"
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/chattr" if name == "chattr" else None)

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout="", stderr="not permitted"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert AuditFSHardener(audit_log).enable_append_only(strict=False) is False


# ---------------------------------------------------------------------------
# status()
# ---------------------------------------------------------------------------


def test_status_reports_mode_and_append_only_unsupported_when_lsattr_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    audit_log = tmp_path / "audit.log"
    hardener = AuditFSHardener(audit_log)
    hardener.ensure_restrictive_permissions()
    monkeypatch.setattr(shutil, "which", lambda name: None)

    status = hardener.status()

    assert status.exists is True
    assert status.mode == "0o600"
    assert status.append_only_supported is False
    assert status.append_only_enabled is None


def test_status_reports_not_exists_for_missing_log(tmp_path: Path) -> None:
    audit_log = tmp_path / "nonexistent.log"
    status = AuditFSHardener(audit_log).status()
    assert status.exists is False
    assert status.mode is None


# ---------------------------------------------------------------------------
# harden() with audit_logger
# ---------------------------------------------------------------------------


def test_harden_emits_audit_fs_harden_event_when_logger_provided(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = Paths(root=tmp_path / "wpg")
    config = WPGovernConfig(
        root_dir=paths.root,
        audit_log=paths.audit,
        alert_sinks=({"type": "none"},),
    )
    audit_log = paths.audit
    hardener = AuditFSHardener(audit_log)
    logger = AuditLogger(config=config, paths=paths)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    hardener.harden(
        strict=False,
        audit_logger=logger,
        actor_context={"actor_id": "ops-user"},
    )

    lines = [l for l in paths.audit.read_text().splitlines() if l.strip()]
    import json
    record = json.loads(lines[-1])
    assert record["event_type"] == "audit.fs_harden"
    assert record["outcome"] == "success"
