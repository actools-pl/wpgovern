"""
Tests for wpgovern.utils.transaction — AtomicTransaction, TransactionError, StagedWrite.

Coverage:
- Commit writes all staged files to their targets
- Abort on exception preserves existing target unchanged
- Context exit without commit aborts
- Staging write failure preserves target
- Commit failure cleans staging and raises TransactionError
- Committed file has restrictive mode
- stage_text writes text content correctly
- Double-commit raises TransactionError
- service_label without trust_service raises ValueError at construction
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wpgovern.utils.transaction import AtomicTransaction, StagedWrite, TransactionError


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_commit_writes_all_staged_json_files_to_targets(tmp_path: Path) -> None:
    staging = tmp_path / "state" / ".transactions"
    target_a = tmp_path / "state" / "a.json"
    target_b = tmp_path / "state" / "nested" / "b.json"

    with AtomicTransaction(staging) as txn:
        txn.stage_json(target_a, {"name": "a"})
        txn.stage_json(target_b, {"name": "b"})
        txn.commit()

    assert json.loads(target_a.read_text()) == {"name": "a"}
    assert json.loads(target_b.read_text()) == {"name": "b"}
    assert not any(staging.glob("txn-*"))


def test_commit_writes_staged_text_file_to_target(tmp_path: Path) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "out.txt"

    with AtomicTransaction(staging) as txn:
        txn.stage_text(target, "hello governance\n")
        txn.commit()

    assert target.read_text() == "hello governance\n"


def test_committed_file_has_restrictive_mode(tmp_path: Path) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "secure.json"

    with AtomicTransaction(staging) as txn:
        txn.stage_json(target, {"secure": True}, mode=0o600)
        txn.commit()

    assert oct(target.stat().st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------
# Abort / rollback
# ---------------------------------------------------------------------------


def test_abort_on_exception_preserves_existing_target(tmp_path: Path) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "target.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    with pytest.raises(RuntimeError):
        with AtomicTransaction(staging) as txn:
            txn.stage_json(target, {"new": True})
            raise RuntimeError("simulate failure before commit")

    assert json.loads(target.read_text()) == {"old": True}
    assert not any(staging.glob("txn-*"))


def test_context_exit_without_commit_aborts_and_leaves_target_unchanged(
    tmp_path: Path,
) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "target.json"

    with AtomicTransaction(staging) as txn:
        txn.stage_json(target, {"new": True})
        # no commit()

    assert not target.exists()
    assert not any(staging.glob("txn-*"))


def test_staging_write_failure_preserves_existing_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "target.json"
    target.write_text('{"old": true}\n', encoding="utf-8")

    original_open = Path.open

    def failing_open(self: Path, *args: object, **kwargs: object) -> object:
        if str(self).startswith(str(staging)):
            raise OSError("simulated staging write failure")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)

    with pytest.raises(OSError):
        with AtomicTransaction(staging) as txn:
            txn.stage_json(target, {"new": True})

    assert json.loads(target.read_text()) == {"old": True}


def test_commit_failure_cleans_staging_and_raises_transaction_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "target.json"

    monkeypatch.setattr(os, "replace", lambda src, dst: (_ for _ in ()).throw(OSError("simulated replace failure")))

    with pytest.raises(TransactionError, match="commit failed"):
        with AtomicTransaction(staging) as txn:
            txn.stage_json(target, {"new": True})
            txn.commit()

    assert not target.exists()
    assert not any(staging.glob("txn-*"))


# ---------------------------------------------------------------------------
# Error conditions
# ---------------------------------------------------------------------------


def test_double_commit_raises_transaction_error(tmp_path: Path) -> None:
    staging = tmp_path / ".transactions"
    target = tmp_path / "target.json"

    with AtomicTransaction(staging) as txn:
        txn.stage_json(target, {"x": 1})
        txn.commit()
        with pytest.raises(TransactionError, match="already closed"):
            txn.commit()


def test_service_label_without_trust_service_raises_value_error(tmp_path: Path) -> None:
    staging = tmp_path / ".transactions"
    with pytest.raises(ValueError, match="trust_service"):
        AtomicTransaction(staging, service_label="SomeService.activate")
