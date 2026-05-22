"""
Tests for wpgovern.utils.locking — LockManager, LOCK_ORDER, LockError, LockTimeoutError.

Coverage:
- Lock directory creation
- Acquire / release via context manager
- acquire_many: deduplication, canonical ordering, all locks held inside block
- Name validation: empty, slash, double-dot, backslash
- sorted_lock_names rejects unknown names
- LockTimeoutError on contention
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from wpgovern.utils.locking import (
    LOCK_ORDER,
    LockError,
    LockHandle,
    LockManager,
    LockTimeoutError,
)


@pytest.fixture()
def lock_manager(tmp_path: Path) -> LockManager:
    return LockManager(
        locks_dir=tmp_path / "locks",
        lock_order=LOCK_ORDER,
        default_timeout=2.0,
        poll_interval=0.01,
    )


# ---------------------------------------------------------------------------
# Basic construction and acquire
# ---------------------------------------------------------------------------


def test_lock_manager_creates_locks_dir_on_construction(tmp_path: Path) -> None:
    locks_dir = tmp_path / "new_locks"
    assert not locks_dir.exists()
    LockManager(locks_dir=locks_dir)
    assert locks_dir.exists()


def test_acquire_returns_lock_handle(lock_manager: LockManager) -> None:
    with lock_manager.acquire("governance") as handle:
        assert isinstance(handle, LockHandle)
        assert handle.name == "governance"


def test_acquire_releases_lock_on_context_exit(lock_manager: LockManager) -> None:
    with lock_manager.acquire("governance"):
        pass
    # Should be re-acquirable immediately after exit
    with lock_manager.acquire("governance", timeout=0.5):
        pass


# ---------------------------------------------------------------------------
# acquire_many
# ---------------------------------------------------------------------------


def test_acquire_many_holds_all_locks_inside_block(lock_manager: LockManager) -> None:
    with lock_manager.acquire_many(["governance", "baselines"]) as handles:
        assert len(handles) == 2
        names = {h.name for h in handles}
        assert names == {"governance", "baselines"}


def test_acquire_many_deduplicates_repeated_names(lock_manager: LockManager) -> None:
    with lock_manager.acquire_many(["governance", "governance"]) as handles:
        assert len(handles) == 1
        assert handles[0].name == "governance"


def test_acquire_many_returns_handles_in_lock_order(lock_manager: LockManager) -> None:
    # Request in reverse LOCK_ORDER — should come back in canonical order.
    with lock_manager.acquire_many(["baselines", "governance"]) as handles:
        names = [h.name for h in handles]
        assert names.index("governance") < names.index("baselines")


def test_acquire_many_releases_all_locks_on_exit(lock_manager: LockManager) -> None:
    with lock_manager.acquire_many(["governance", "baselines"]):
        pass
    # Both locks must be re-acquirable immediately.
    with lock_manager.acquire_many(["governance", "baselines"], timeout=0.5):
        pass


# ---------------------------------------------------------------------------
# Name validation
# ---------------------------------------------------------------------------


def test_validate_lock_name_rejects_empty_string(lock_manager: LockManager) -> None:
    with pytest.raises(LockError):
        with lock_manager.acquire(""):
            pass


def test_validate_lock_name_rejects_forward_slash(lock_manager: LockManager) -> None:
    with pytest.raises(LockError):
        with lock_manager.acquire("some/name"):
            pass


def test_validate_lock_name_rejects_double_dot(lock_manager: LockManager) -> None:
    with pytest.raises(LockError):
        with lock_manager.acquire("../escape"):
            pass


def test_validate_lock_name_rejects_backslash(lock_manager: LockManager) -> None:
    with pytest.raises(LockError):
        with lock_manager.acquire("some\\name"):
            pass


def test_sorted_lock_names_rejects_unknown_name(lock_manager: LockManager) -> None:
    with pytest.raises(LockError, match="Unknown lock name"):
        lock_manager.sorted_lock_names(["governance", "nonexistent-lock"])


def test_sorted_lock_names_returns_known_names_in_order(lock_manager: LockManager) -> None:
    # Request a subset in arbitrary order.
    result = lock_manager.sorted_lock_names(["baselines", "recovery", "audit"])
    expected_positions = [LOCK_ORDER.index(n) for n in result]
    assert expected_positions == sorted(expected_positions)


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


def test_acquire_timeout_raises_locktimeouterror(tmp_path: Path) -> None:
    mgr = LockManager(locks_dir=tmp_path / "locks", default_timeout=0.1, poll_interval=0.01)
    acquired = threading.Event()
    release = threading.Event()

    def hold_lock() -> None:
        with mgr.acquire("governance"):
            acquired.set()
            release.wait(timeout=2.0)

    t = threading.Thread(target=hold_lock, daemon=True)
    t.start()
    acquired.wait(timeout=2.0)
    try:
        with pytest.raises(LockTimeoutError):
            with mgr.acquire("governance", timeout=0.1):
                pass
    finally:
        release.set()
        t.join(timeout=2.0)
