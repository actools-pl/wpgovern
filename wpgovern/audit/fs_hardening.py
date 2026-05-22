"""
Filesystem hardening for the WPGovern audit ledger.

``AuditFSHardener`` enforces restrictive filesystem permissions on the audit
log and optionally applies the Linux append-only immutable flag via ``chattr``.

Behavior when ``chattr``/``lsattr`` are absent (test environments and non-Linux
systems): all chattr operations degrade gracefully — ``enable_append_only()``
returns ``False`` (or raises ``AuditHardeningError`` when ``strict=True``);
``status()`` reports ``append_only_supported=False``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from wpgovern.errors import WPGovernError


class AuditHardeningError(WPGovernError):
    """Raised when audit filesystem hardening fails."""


@dataclass(frozen=True)
class AuditFSStatus:
    """Snapshot of the audit log's filesystem state."""

    path: Path
    exists: bool
    mode: str | None
    append_only_supported: bool
    append_only_enabled: bool | None


class AuditFSHardener:
    """Filesystem hardening helper for the WPGovern audit ledger.

    Enforces:
    - Audit directory mode 0700.
    - Audit log mode 0600.
    - Optional Linux append-only flag via ``chattr +a`` where supported.

    Args:
        audit_log: Path to the audit log file.
    """

    def __init__(self, audit_log: Path) -> None:
        self.audit_log = Path(audit_log)

    def ensure_restrictive_permissions(self) -> None:
        """Create the audit directory and log (if missing) and enforce modes.

        Sets the audit directory to mode 0700 and the log file to mode 0600.
        Idempotent — safe to call on every audit write.
        """
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.audit_log.parent, 0o700)

        if not self.audit_log.exists():
            with self.audit_log.open("a", encoding="utf-8") as fh:
                fh.flush()
                os.fsync(fh.fileno())

        os.chmod(self.audit_log, 0o600)
        self._fsync_dir(self.audit_log.parent)

    def enable_append_only(self, strict: bool = False) -> bool:
        """Apply the Linux append-only flag (``chattr +a``) to the audit log.

        Args:
            strict: When ``True``, raise ``AuditHardeningError`` if ``chattr``
                is unavailable or the operation fails. When ``False`` (default),
                return ``False`` instead.

        Returns:
            ``True`` if the flag was successfully applied, ``False`` otherwise.
        """
        chattr = shutil.which("chattr")
        if chattr is None:
            if strict:
                raise AuditHardeningError(
                    "chattr not available; cannot enable append-only audit log"
                )
            return False

        self.ensure_restrictive_permissions()
        result = subprocess.run(
            [chattr, "+a", str(self.audit_log)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            if strict:
                raise AuditHardeningError(
                    "Failed to enable append-only audit log: "
                    + (result.stderr.strip() or result.stdout.strip())
                )
            return False
        return True

    def disable_append_only(self, strict: bool = False) -> bool:
        """Remove the Linux append-only flag (``chattr -a``) from the audit log.

        Args:
            strict: When ``True``, raise on failure. When ``False``, return
                ``False``.

        Returns:
            ``True`` if the flag was successfully removed, ``False`` otherwise.
        """
        chattr = shutil.which("chattr")
        if chattr is None:
            if strict:
                raise AuditHardeningError(
                    "chattr not available; cannot disable append-only audit log"
                )
            return False

        result = subprocess.run(
            [chattr, "-a", str(self.audit_log)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            if strict:
                raise AuditHardeningError(
                    "Failed to disable append-only audit log: "
                    + (result.stderr.strip() or result.stdout.strip())
                )
            return False
        return True

    def harden(
        self,
        strict: bool = False,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> "AuditFSStatus":
        """Apply all hardening steps and return the resulting filesystem status.

        Composes three operations:
        1. ``ensure_restrictive_permissions()``
        2. ``enable_append_only(strict=strict)``
        3. ``status()``

        When ``audit_logger`` and ``actor_context`` are provided, emits an
        ``audit.fs_harden`` audit record with the final status detail.

        Returns:
            The ``AuditFSStatus`` after hardening.
        """
        self.ensure_restrictive_permissions()
        append_only = self.enable_append_only(strict=strict)
        current_status = self.status()

        if audit_logger is not None and actor_context is not None:
            audit_logger.emit(
                event_type="audit.fs_harden",
                actor=str(actor_context.get("actor_id") or ""),
                outcome="success",
                details={
                    **actor_context,
                    "target_id": str(current_status.path),
                    "status": "append_only" if append_only else "restricted_permissions",
                },
            )

        return current_status

    def status(self) -> AuditFSStatus:
        """Return the current filesystem state of the audit log."""
        exists = self.audit_log.exists()
        mode = oct(self.audit_log.stat().st_mode & 0o777) if exists else None

        lsattr = shutil.which("lsattr")
        append_only_supported = lsattr is not None
        append_only_enabled: bool | None = None

        if exists and lsattr is not None:
            result = subprocess.run(
                [lsattr, "-d", str(self.audit_log)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if result.returncode == 0:
                flags = (
                    result.stdout.split(maxsplit=1)[0]
                    if result.stdout.strip()
                    else ""
                )
                append_only_enabled = "a" in flags

        return AuditFSStatus(
            path=self.audit_log,
            exists=exists,
            mode=mode,
            append_only_supported=append_only_supported,
            append_only_enabled=append_only_enabled,
        )

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
