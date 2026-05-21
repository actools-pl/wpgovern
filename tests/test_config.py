"""
Tests for wpgovern.config.WPGovernConfig and DEFAULT_CONFIG.

Coverage:
- Default instantiation and field types
- Frozen (immutable) enforcement
- Each logical field group: core paths, journal, alerting, review
- DEFAULT_CONFIG is a valid instance
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from wpgovern.config import DEFAULT_CONFIG, WPGovernConfig


def test_default_instantiation_succeeds() -> None:
    cfg = WPGovernConfig()
    assert cfg is not None


def test_default_config_is_wpgovernconfig_instance() -> None:
    assert isinstance(DEFAULT_CONFIG, WPGovernConfig)


def test_core_path_fields_are_path_instances() -> None:
    cfg = WPGovernConfig()
    assert isinstance(cfg.root_dir, Path)
    assert isinstance(cfg.install_dir, Path)
    assert isinstance(cfg.runtime_trust_store, Path)
    assert isinstance(cfg.release_trust_store, Path)
    assert isinstance(cfg.active_pointer, Path)
    assert isinstance(cfg.audit_log, Path)


def test_journal_staleness_warn_default_is_3600() -> None:
    cfg = WPGovernConfig()
    assert cfg.journal_staleness_warn_seconds == 3600


def test_journal_staleness_enforce_default_is_none() -> None:
    cfg = WPGovernConfig()
    assert cfg.journal_staleness_enforce_seconds is None


def test_alert_sinks_default_is_none() -> None:
    cfg = WPGovernConfig()
    assert cfg.alert_sinks is None


def test_alert_extra_triggers_default_is_none() -> None:
    cfg = WPGovernConfig()
    assert cfg.alert_extra_triggers is None


def test_review_max_age_days_default_is_none() -> None:
    cfg = WPGovernConfig()
    assert cfg.review_max_age_days is None


def test_config_is_frozen() -> None:
    cfg = WPGovernConfig()
    with pytest.raises((FrozenInstanceError, AttributeError)):
        cfg.review_max_age_days = 30  # type: ignore[misc]


def test_config_accepts_custom_root_dir(tmp_path: Path) -> None:
    cfg = WPGovernConfig(root_dir=tmp_path)
    assert cfg.root_dir == tmp_path


def test_journal_staleness_accepts_none_for_both_fields() -> None:
    cfg = WPGovernConfig(
        journal_staleness_warn_seconds=None,
        journal_staleness_enforce_seconds=None,
    )
    assert cfg.journal_staleness_warn_seconds is None
    assert cfg.journal_staleness_enforce_seconds is None


def test_alert_sinks_accepts_tuple_of_sink_dicts() -> None:
    sinks = ({"type": "none"},)
    cfg = WPGovernConfig(alert_sinks=sinks)
    assert cfg.alert_sinks == sinks


def test_alert_extra_triggers_accepts_tuple_of_strings() -> None:
    triggers = ("custom.event.one", "custom.event.two")
    cfg = WPGovernConfig(alert_extra_triggers=triggers)
    assert cfg.alert_extra_triggers == triggers


def test_review_max_age_days_accepts_positive_integer() -> None:
    cfg = WPGovernConfig(review_max_age_days=30)
    assert cfg.review_max_age_days == 30


# ---------------------------------------------------------------------------
# R4 documentation tests — path fields are informational; root_dir is authority
# ---------------------------------------------------------------------------


def test_audit_log_field_is_informational_paths_derives_from_root(
    tmp_path: Path,
) -> None:
    """R4 regression: the audit_log config field is informational. Setting it
    to a non-default path has no effect on where the audit logger writes.
    AuditLogger uses paths.audit (derived from root_dir), not config.audit_log.

    This test documents the known limit explicitly so future engineers
    understand the constraint rather than discovering it by debugging.
    The R4 fix (making build_paths honour explicit overrides) is tracked
    for a future hardening pass."""
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.paths import build_paths
    from wpgovern.config import WPGovernConfig
    from wpgovern.core.trust import TrustService

    root = tmp_path / "root"
    non_default_log = tmp_path / "custom_audit.log"

    cfg = WPGovernConfig(
        root_dir=root,
        audit_log=non_default_log,    # set a non-default path
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        alert_sinks=({"type": "none"},),
    )
    TrustService(config=cfg)
    logger = AuditLogger(cfg)
    logger.emit("baseline.create", "alice", "success")

    # The logger writes to paths.audit (layout-derived), not config.audit_log.
    paths = build_paths(cfg)
    assert paths.audit.exists(), "Logger must write to paths.audit (root_dir-derived)"
    assert not non_default_log.exists(), (
        "config.audit_log override is not honoured — this is the documented "
        "known limit (R4). A future pass will make build_paths honour overrides."
    )


def test_root_dir_is_the_effective_path_authority(tmp_path: Path) -> None:
    """Positive: changing root_dir changes all derived paths. root_dir is
    the only config field that affects runtime filesystem behaviour."""
    from wpgovern.paths import build_paths
    from wpgovern.config import WPGovernConfig

    root_a = tmp_path / "root_a"
    root_b = tmp_path / "root_b"

    cfg_a = WPGovernConfig(root_dir=root_a)
    cfg_b = WPGovernConfig(root_dir=root_b)

    assert build_paths(cfg_a).audit == root_a / "audit" / "audit.log"
    assert build_paths(cfg_b).audit == root_b / "audit" / "audit.log"
    assert build_paths(cfg_a).audit != build_paths(cfg_b).audit
