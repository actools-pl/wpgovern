"""
Exception hierarchy for the WPGovern governance control plane.

WPGovernError
├── IntegrityError              — governance integrity check failed
├── NotFoundError               — required governance artifact missing
├── ValidationError             — supplied input or state is invalid
├── PolicyError                 — governance policy rule violated
└── B4Error                     — filesystem write failure mid-operation
    ├── DiskFullError                   (ENOSPC)
    ├── ReadOnlyFilesystemError         (EROFS / EIO / ESTALE / ETIMEDOUT)
    ├── PermissionError_                (EACCES)
    └── ReadOnlyDuringRecoveryError     (B4 during recovery — stuck state)

B4Errors classify OSError conditions that occur during write operations into
operator-actionable categories. They extend WPGovernError so callers catching
the wide handler still see filesystem events; specific catches let callers
branch on disk-full vs read-only-fs vs permission.

Use ``_classify_oserror()`` to convert an OSError at an I/O point into the
appropriate B4Error subclass. Use ``_classify_during_recovery()`` inside the
recovery loop — it produces a ``ReadOnlyDuringRecoveryError`` so that the
caller can distinguish a stuck-state from a plain operation failure.

KNOWN_LIMITS: ``FileLock`` uses ``fcntl.flock`` which is advisory and not
NFS-safe. See the phase plan KNOWN_LIMITS table for the full list of carried-
forward limitations.
"""

from __future__ import annotations


class WPGovernError(RuntimeError):
    """Base exception for WPGovern Python control-plane failures."""


class IntegrityError(WPGovernError):
    """Raised when a governance integrity check fails."""


class JournalSchemaError(WPGovernError):
    """Raised when a journal record has a missing or unsupported schema_version.

    β-3: Previously, records with no schema_version silently defaulted to the
    current version, causing confusing downstream errors. This exception names
    the actual problem explicitly for operator clarity.
    """


class NotFoundError(WPGovernError):
    """Raised when a required governance artifact is missing."""


class ValidationError(WPGovernError):
    """Raised when supplied input or state is invalid."""


class PolicyError(WPGovernError):
    """Raised when a governance policy rule is violated."""


# ---------------------------------------------------------------------------
# B4 — filesystem write failure mid-operation
#
# These exceptions classify OSError-during-write events into operator-
# actionable categories. The classification table:
#
#   errno 28  (ENOSPC)                → DiskFullError
#   errno 30  (EROFS)                 → ReadOnlyFilesystemError
#   errno  5  (EIO)                   → ReadOnlyFilesystemError
#   errno 116 (ESTALE)                → ReadOnlyFilesystemError
#   errno 110 (ETIMEDOUT)             → ReadOnlyFilesystemError
#   errno 13  (EACCES)                → PermissionError_
#
# When a B4 condition is encountered inside the recovery loop itself, use
# _classify_during_recovery() instead — it wraps the classified error in
# ReadOnlyDuringRecoveryError, signalling a stuck-state to the CLI.
# ---------------------------------------------------------------------------

_B4_ERRNO_TO_SYMBOL: dict[int, str] = {
    28: "ENOSPC",
    30: "EROFS",
    13: "EACCES",
    5: "EIO",
    116: "ESTALE",
    110: "ETIMEDOUT",
}


class B4Error(WPGovernError):
    """Base for filesystem-mid-operation classified errors.

    Carries the path that triggered the failure, the pipeline phase in
    which it was detected, and the original errno. Subclasses distinguish
    operator playbooks: free space (DiskFullError), investigate volume
    (ReadOnlyFilesystemError), check ownership (PermissionError_), or
    stuck-state (ReadOnlyDuringRecoveryError).

    The string representation is operator-readable: it includes the
    classification, errno symbol, path, phase, and (best-effort) the
    volume hosting the path.
    """

    operator_action: str = "Investigate filesystem state."

    def __init__(
        self,
        path: object,
        phase: str,
        errno_classified: int,
        message: str | None = None,
    ) -> None:
        self.path = path
        self.phase = phase
        self.errno_classified = errno_classified
        self.errno_symbol = _B4_ERRNO_TO_SYMBOL.get(errno_classified, "UNKNOWN")
        self.volume = self._compute_volume(path)
        if message is None:
            message = (
                f"{type(self).__name__} during {phase}: "
                f"{self.errno_symbol}({errno_classified}) on {path}. "
                f"Volume: {self.volume or 'unknown'}. "
                f"Operator action: {self.operator_action}"
            )
        super().__init__(message)

    @staticmethod
    def _compute_volume(path: object) -> str | None:
        """Best-effort: walk up to find the mount point hosting path."""
        try:
            from pathlib import Path
            import os as _os

            p = Path(str(path)).resolve()
            while p != p.parent:
                if _os.path.ismount(str(p)):
                    return str(p)
                p = p.parent
            return str(p)  # filesystem root
        except Exception:  # noqa: BLE001
            return None

    def to_dict(self) -> dict[str, object]:
        """Forensic / audit serialization."""
        return {
            "class": type(self).__name__,
            "errno": self.errno_classified,
            "errno_symbol": self.errno_symbol,
            "path": str(self.path),
            "volume": self.volume,
            "phase": self.phase,
            "operator_action": self.operator_action,
        }


class DiskFullError(B4Error):
    """ENOSPC: the volume hosting this path has no free space.

    Operator action: free space on the volume, then retry the operation.
    """

    operator_action = (
        "Disk full on the volume hosting this path. Free space and retry."
    )


class ReadOnlyFilesystemError(B4Error):
    """EROFS / EIO / ESTALE / ETIMEDOUT: the filesystem is unwritable.

    Could be an intentional read-only mount, hardware fault, NFS partition,
    or filesystem-detected corruption.

    Operator action: investigate the volume's health. Remount r/w if
    intentional, replace hardware if EIO, restore network connectivity if NFS.
    Does not self-heal; operator intervention required.
    """

    operator_action = (
        "Volume mounted read-only or unavailable. "
        "Remount r/w, check hardware, or restore connectivity."
    )


class PermissionError_(B4Error):
    """EACCES on a path that should be writable.

    Distinct from EROFS: the volume is healthy but the process lacks
    permission. Operator action: check ownership / mode / MAC label on
    the path and its parent directories.
    """

    operator_action = (
        "Permission denied on a path that should be writable. "
        "Check ownership, mode, and MAC labels."
    )


class ReadOnlyDuringRecoveryError(B4Error):
    """B4 condition encountered inside the recovery loop itself.

    Recovery's job is to restore consistency; if recovery cannot write,
    the system is in a partial-commit stuck state requiring operator
    intervention. The CLI startup hook surfaces exit code 33 for this.

    The underlying B4 class (DiskFullError, ReadOnlyFilesystemError, or
    PermissionError_) is preserved in ``underlying_class``.
    """

    operator_action = (
        "Recovery cannot proceed; system is in a partial-commit stuck "
        "state. Resolve the underlying filesystem condition and re-run."
    )

    def __init__(
        self,
        path: object,
        phase: str,
        errno_classified: int,
        underlying_class: str,
        message: str | None = None,
    ) -> None:
        self.underlying_class = underlying_class
        super().__init__(path, phase, errno_classified, message)

    def to_dict(self) -> dict[str, object]:
        d = super().to_dict()
        d["underlying_class"] = self.underlying_class
        return d


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------


def _classify_oserror(exc: OSError, path: object, phase: str) -> B4Error | None:
    """Classify an OSError into a B4Error subclass, or return None.

    Returns None if the errno does not match a B4 condition; the caller
    should re-raise the original OSError in that case.

    Usage::

        try:
            os.replace(staged, final)
        except OSError as exc:
            classified = _classify_oserror(exc, final, "target_replace")
            if classified is not None:
                raise classified from exc
            raise  # not a B4 condition; propagate as-is

    The ``raise classified from exc`` preserves the original OSError as
    ``__cause__`` so deep diagnosis remains possible.
    """
    errno = getattr(exc, "errno", None)
    if errno is None:
        return None
    if errno == 28:  # ENOSPC
        return DiskFullError(path, phase, errno)
    if errno in (30, 5, 116, 110):  # EROFS, EIO, ESTALE, ETIMEDOUT
        return ReadOnlyFilesystemError(path, phase, errno)
    if errno == 13:  # EACCES
        return PermissionError_(path, phase, errno)
    return None


def _classify_during_recovery(
    exc: OSError, path: object, phase: str
) -> ReadOnlyDuringRecoveryError | None:
    """Like ``_classify_oserror`` but produces a ReadOnlyDuringRecoveryError.

    Use inside the recovery loop. Returns None if the errno is not a B4
    condition (caller should re-raise the original OSError regardless —
    recovery cannot proceed either way, but the audit story differs).
    """
    base = _classify_oserror(exc, path, phase)
    if base is None:
        return None
    return ReadOnlyDuringRecoveryError(
        path,
        phase,
        base.errno_classified,
        underlying_class=type(base).__name__,
    )
