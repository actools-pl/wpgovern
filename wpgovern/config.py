"""
WPGovern runtime configuration.

``WPGovernConfig`` is a frozen dataclass that holds every tuneable parameter
for the governance control plane. It is instantiated once and passed to
services as a dependency; services never modify it.

``DEFAULT_CONFIG`` is the out-of-the-box configuration. Tests and operators
create ``WPGovernConfig(root_dir=tmp_path, ...)`` to override specific fields
without affecting the singleton.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WPGovernConfig:
    # ------------------------------------------------------------------
    # Core filesystem paths
    #
    # IMPORTANT: ``Paths`` (see paths.py) is the authoritative layout
    # source for all filesystem locations.  It derives every path from
    # ``root_dir``.  The individual path fields below (``install_dir``,
    # ``runtime_trust_store``, ``release_trust_store``, ``active_pointer``,
    # ``audit_log``) are *informational* — they reflect the default layout
    # for documentation purposes but are NOT read by ``Paths`` or by any
    # service.  Overriding them in a ``WPGovernConfig(...)`` call has no
    # effect on the actual runtime paths; override ``root_dir`` instead.
    #
    # This is tracked as a known limit (R4 from external review round-4 review).
    # A future pass will make ``build_paths`` honour explicit overrides.
    # ------------------------------------------------------------------

    root_dir: Path = Path("/opt/wpgovern")
    """Root of the WPGovern state tree.  This is the *only* path field
    that affects runtime behaviour; all other paths are derived from it
    by ``Paths``."""

    install_dir: Path = Path("/opt/wpgovern-install")
    """Location of the installed WPGovern release artefacts.

    H.0-A: This field is now functional — ``BaselineService.create_draft()``
    reads config files relative to this path to compute SHA-256 hashes for
    the config-file hash manifest. ``governance-check`` also reads from this
    path when verifying hashes against the active baseline.

    Operators override by passing ``install_dir=Path(...)`` to
    ``WPGovernConfig``. The default ``/opt/wpgovern-install`` matches the
    v1.1 stack layout. Do NOT derive other path fields from install_dir here;
    that is R4 scope (deferred)."""

    runtime_trust_store: Path = Path(
        "/opt/wpgovern/trust/runtime/public/trusted-runtime-keys.json"
    )
    """Informational: canonical runtime trust store path.  Derived from
    ``root_dir`` by ``Paths``; this field is not read by any service."""

    release_trust_store: Path = Path(
        "/opt/wpgovern/trust/release/public/trusted-release-keys.json"
    )
    """Informational: canonical release trust store path.  Derived from
    ``root_dir`` by ``Paths``; this field is not read by any service."""

    active_pointer: Path = Path("/opt/wpgovern/state/active.json")
    """Informational: path of the active-baseline pointer file.  Derived
    from ``root_dir`` by ``Paths``; this field is not read by any service."""

    audit_log: Path = Path("/opt/wpgovern/audit/audit.log")
    """Informational: path of the hash-chained audit log.  Derived from
    ``root_dir`` by ``Paths``; this field is not read by any service.
    All audit-log consumers use ``paths.audit`` (layout-derived)."""

    # ------------------------------------------------------------------
    # Journal / crash-recovery
    # ------------------------------------------------------------------

    journal_staleness_warn_seconds: int | None = 3600
    """Emit a warning when an unmatched intent record is older than this.
    ``None`` disables the warning threshold."""

    journal_staleness_enforce_seconds: int | None = None
    """Block startup when an unmatched intent record is older than this.
    ``None`` (default) means no enforcement — warn only."""

    # ------------------------------------------------------------------
    # Audit alerting
    # ------------------------------------------------------------------

    alert_sinks: tuple[dict[str, Any], ...] | None = None
    """Sequence of sink configuration dicts.  Each dict has a ``"type"`` key
    and type-specific parameters::

        {"type": "webhook", "url": "https://...", "timeout": 5}
        {"type": "file",    "path": "/var/log/wpgovern/alerts.log"}
        {"type": "syslog"}
        {"type": "stderr"}   # default when list is empty or None
        {"type": "none"}     # silence — useful in tests

    The built-in alert trigger set (see ``AuditAlerter``) cannot be reduced
    through this field.
    """

    alert_extra_triggers: tuple[str, ...] | None = None
    """Additional ``event_type`` strings to alert on, beyond the built-in set.
    Operators may extend but never reduce the minimum safe trigger set."""

    # ------------------------------------------------------------------
    # Audit review checkpoint
    # ------------------------------------------------------------------

    review_max_age_days: int | None = None
    """When set, ``governance-check`` surfaces exit code 50 if no attested
    audit-review checkpoint exists within this many days.  ``None`` (default)
    means no enforcement — operators may run ``audit-review`` manually but
    are not required to by automated checks."""


DEFAULT_CONFIG = WPGovernConfig()
