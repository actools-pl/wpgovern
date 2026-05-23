"""
Advisory file locking for the WPGovern governance control plane.

``LockManager`` provides single-node advisory locks using ``fcntl.flock``.

KNOWN_LIMITS: ``fcntl.flock`` is advisory and not NFS-safe. Two processes on
different hosts can hold the same lock simultaneously over NFS. WPGovern is a
single-node tool; distributed locking is outside scope.

Deadlock avoidance: ``acquire_many()`` always acquires locks in ``LOCK_ORDER``
regardless of the order the caller specifies. Any call site that acquires more
than one lock must use ``acquire_many()`` — never nest ``acquire()`` calls
manually.
"""

from __future__ import annotations

import fcntl
import os
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

from wpgovern.errors import WPGovernError


class LockError(WPGovernError):
    """Raised for lock configuration or validation errors."""


class LockTimeoutError(LockError):
    """Raised when a lock cannot be acquired within the timeout."""


@dataclass(frozen=True)
class LockHandle:
    """Token representing a held lock. Returned by ``LockManager.acquire()``."""
    name: str
    path: Path
    fd: int


LOCK_ORDER: list[str] = [
    "recovery",
    "governance",
    "runtime-trust",
    "release-trust",
    "journal-trust",
    "approvals",
    "baselines",
    "active-state",
    "emergency",
    "reconciliation",
    "audit",
]


class LockManager:
    """Manages advisory file locks for WPGovern governance operations.

    All lock files are created under ``locks_dir`` with a ``.lock`` suffix.
    The directory is created on construction if it does not exist.

    KNOWN_LIMITS: Uses fcntl.flock (advisory, not NFS-safe).

    Args:
        locks_dir: Directory for lock files.
        lock_order: Acquisition order for acquire_many(). Defaults to LOCK_ORDER.
        default_timeout: Seconds to wait before raising LockTimeoutError.
        poll_interval: Polling interval in seconds while waiting.
    """

    def __init__(
        self,
        locks_dir: Path | str = "/opt/wpgovern/locks",
        lock_order: Sequence[str] | None = None,
        default_timeout: float = 10.0,
        poll_interval: float = 0.1,
    ) -> None:
        self.locks_dir = Path(locks_dir)
        self.locks_dir.mkdir(parents=True, exist_ok=True)
        self.lock_order = list(lock_order or LOCK_ORDER)
        self.default_timeout = default_timeout
        self.poll_interval = poll_interval

    def sorted_lock_names(self, names: Sequence[str]) -> list[str]:
        """Return names deduplicated and sorted into acquisition order.

        Raises:
            LockError: if any name is invalid or not in lock_order.
        """
        seen: set[str] = set()
        unique: list[str] = []
        for name in names:
            self._validate_lock_name(name)
            if name not in seen:
                seen.add(name)
                unique.append(name)
        order_index = {name: idx for idx, name in enumerate(self.lock_order)}
        unknown = [name for name in unique if name not in order_index]
        if unknown:
            raise LockError(f"Unknown lock name(s): {', '.join(sorted(unknown))}")
        return sorted(unique, key=lambda name: order_index[name])

    @contextmanager
    def acquire(self, name: str, timeout: float | None = None) -> Iterator[LockHandle]:
        """Acquire a single named lock for the duration of the with-block."""
        self._validate_lock_name(name)
        timeout = self.default_timeout if timeout is None else timeout
        path = self.locks_dir / f"{name}.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        acquired = False
        start = time.monotonic()
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except BlockingIOError:
                    if time.monotonic() - start >= timeout:
                        raise LockTimeoutError(
                            f"Could not acquire lock '{name}' within {timeout:.1f}s"
                        )
                    time.sleep(self.poll_interval)
            yield LockHandle(name, path, fd)
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextmanager
    def acquire_many(
        self, names: Sequence[str], timeout: float | None = None
    ) -> Iterator[list[LockHandle]]:
        """Acquire multiple named locks in canonical order.

        Deduplicates names, sorts them into lock_order, and acquires in sequence.
        All locks are released on exit.
        """
        with ExitStack() as stack:
            handles = [
                stack.enter_context(self.acquire(name, timeout=timeout))
                for name in self.sorted_lock_names(names)
            ]
            yield handles

    def _validate_lock_name(self, name: str) -> None:
        if not name or "/" in name or "\\" in name or ".." in name:
            raise LockError(f"Invalid lock name '{name}'")
