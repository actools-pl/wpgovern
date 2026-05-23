"""
WPGovern canonical filesystem layout.

``Paths`` is a frozen dataclass whose properties derive every filesystem path
from a single ``root``.  All services accept a ``Paths`` instance rather than
constructing paths ad-hoc, so the layout can be overridden in tests by passing
a ``tmp_path``-rooted ``Paths``.

Three trust domains share the same layout convention:

    trust/<domain>/private/   — private key material (mode 0700)
    trust/<domain>/public/    — trust store JSON + public keys (mode 0755)

Domains: ``runtime``, ``release``, ``journal``.

Aliases (``approvals``, ``rollbacks``, ``audit_log``, …) are retained for
CLI/shell-era compatibility.  They return the same ``Path`` object as their
canonical counterpart and are defined once here — never re-derived elsewhere.

``WPGovernPaths`` is a module-level alias for ``Paths`` retained for
compatibility.  It is not a separate class.

``build_paths(config)`` constructs a ``Paths`` from any of: ``None``, an
existing ``Paths`` instance, a ``str`` or ``Path`` root, or a config object
with a ``root_dir`` or ``root`` attribute.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Paths:
    """Canonical filesystem layout for the WPGovern control plane."""

    root: Path = Path("/opt/wpgovern")

    # ------------------------------------------------------------------
    # Root alias
    # ------------------------------------------------------------------

    @property
    def root_dir(self) -> Path:
        return self.root

    # ------------------------------------------------------------------
    # Trust domain directories — runtime
    # ------------------------------------------------------------------

    @property
    def runtime_private_dir(self) -> Path:
        return self.root / "trust" / "runtime" / "private"

    @property
    def runtime_public_dir(self) -> Path:
        return self.root / "trust" / "runtime" / "public"

    @property
    def trust_runtime_private(self) -> Path:
        """Alias for runtime_private_dir."""
        return self.runtime_private_dir

    @property
    def trust_runtime_public(self) -> Path:
        """Alias for runtime_public_dir."""
        return self.runtime_public_dir

    @property
    def runtime_trust_store(self) -> Path:
        return self.runtime_public_dir / "trusted-runtime-keys.json"

    @property
    def runtime_active_private_key(self) -> Path:
        return self.runtime_private_dir / "runtime-active.pem"

    # ------------------------------------------------------------------
    # Trust domain directories — release
    # ------------------------------------------------------------------

    @property
    def release_private_dir(self) -> Path:
        return self.root / "trust" / "release" / "private"

    @property
    def release_public_dir(self) -> Path:
        return self.root / "trust" / "release" / "public"

    @property
    def trust_release_private(self) -> Path:
        """Alias for release_private_dir."""
        return self.release_private_dir

    @property
    def trust_release_public(self) -> Path:
        """Alias for release_public_dir."""
        return self.release_public_dir

    @property
    def release_trust_store(self) -> Path:
        return self.release_public_dir / "trusted-release-keys.json"

    @property
    def release_active_private_key(self) -> Path:
        return self.release_private_dir / "release-active.pem"

    # ------------------------------------------------------------------
    # Trust domain directories — journal
    # ------------------------------------------------------------------

    @property
    def journal_private_dir(self) -> Path:
        return self.root / "trust" / "journal" / "private"

    @property
    def journal_public_dir(self) -> Path:
        return self.root / "trust" / "journal" / "public"

    @property
    def journal_trust_store(self) -> Path:
        return self.journal_public_dir / "trusted-journal-keys.json"

    @property
    def journal_active_private_key(self) -> Path:
        return self.journal_private_dir / "journal-active.pem"

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    @property
    def baselines_dir(self) -> Path:
        return self.root / "baselines"

    @property
    def baselines(self) -> Path:
        """Alias for baselines_dir."""
        return self.baselines_dir

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    @property
    def approvals_dir(self) -> Path:
        return self.root / "approvals"

    @property
    def approvals(self) -> Path:
        """Alias for approvals_dir."""
        return self.approvals_dir

    # ------------------------------------------------------------------
    # State tree
    # ------------------------------------------------------------------

    @property
    def state_dir(self) -> Path:
        return self.root / "state"

    @property
    def active_pointer(self) -> Path:
        return self.state_dir / "active.json"

    @property
    def state_supersessions(self) -> Path:
        return self.state_dir / "supersessions"

    @property
    def supersessions(self) -> Path:
        """Alias for state_supersessions."""
        return self.state_supersessions

    @property
    def state_rollbacks(self) -> Path:
        return self.state_dir / "rollbacks"

    @property
    def rollbacks(self) -> Path:
        """Alias for state_rollbacks."""
        return self.state_rollbacks

    @property
    def state_emergency(self) -> Path:
        return self.state_dir / "emergency"

    @property
    def emergency(self) -> Path:
        """Alias for state_emergency."""
        return self.state_emergency

    @property
    def state_emergency_reviews(self) -> Path:
        return self.state_dir / "emergency-reviews"

    @property
    def emergency_reviews(self) -> Path:
        """Alias for state_emergency_reviews."""
        return self.state_emergency_reviews

    @property
    def state_reconciliation(self) -> Path:
        return self.state_dir / "reconciliation"

    @property
    def reconciliation(self) -> Path:
        """Alias for state_reconciliation."""
        return self.state_reconciliation

    @property
    def reconciliation_required(self) -> Path:
        return self.state_reconciliation / "required"

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    @property
    def audit(self) -> Path:
        return self.root / "audit" / "audit.log"

    @property
    def audit_log(self) -> Path:
        """Alias for audit."""
        return self.audit

    # ------------------------------------------------------------------
    # Locks
    # ------------------------------------------------------------------

    @property
    def locks_dir(self) -> Path:
        return self.root / "locks"


# Module-level alias retained for compatibility.
WPGovernPaths = Paths


def build_paths(config: Any | None = None) -> Paths:
    """Construct a ``Paths`` instance from various input forms.

    Accepted inputs:

    * ``None`` — returns ``Paths()`` (default root ``/opt/wpgovern``)
    * an existing ``Paths`` instance — returned as-is
    * a ``str`` or ``Path`` — treated as the root directory
    * any object with a ``root_dir`` or ``root`` attribute (e.g. ``WPGovernConfig``)

    If none of the above apply, returns ``Paths()`` with the default root.
    """
    if config is None:
        return Paths()
    if isinstance(config, Paths):
        return config
    if isinstance(config, (str, Path)):
        return Paths(root=Path(config))
    root = getattr(config, "root_dir", None) or getattr(config, "root", None)
    if root is None:
        return Paths()
    return Paths(root=Path(root))
