"""
Tests for wpgovern.paths.Paths, WPGovernPaths alias, and build_paths().

Coverage:
- Default instantiation
- root_dir alias
- All three trust domains (runtime, release, journal) — store paths and dir paths
- State subtree paths and their aliases
- Audit log alias
- WPGovernPaths is Paths
- build_paths() with all accepted input forms
- Custom root propagates to all derived paths
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.paths import Paths, WPGovernPaths, build_paths


def test_default_paths_instantiates() -> None:
    p = Paths()
    assert p is not None


def test_root_dir_alias_equals_root() -> None:
    p = Paths()
    assert p.root_dir == p.root


def test_runtime_trust_store_under_runtime_public() -> None:
    p = Paths()
    assert p.runtime_trust_store == p.runtime_public_dir / "trusted-runtime-keys.json"


def test_release_trust_store_under_release_public() -> None:
    p = Paths()
    assert p.release_trust_store == p.release_public_dir / "trusted-release-keys.json"


def test_journal_trust_store_under_journal_public() -> None:
    p = Paths()
    assert p.journal_trust_store == p.journal_public_dir / "trusted-journal-keys.json"


def test_active_pointer_under_state_dir() -> None:
    p = Paths()
    assert p.active_pointer == p.state_dir / "active.json"


def test_audit_log_alias_equals_audit() -> None:
    p = Paths()
    assert p.audit_log == p.audit


def test_approvals_alias_equals_approvals_dir() -> None:
    p = Paths()
    assert p.approvals == p.approvals_dir


def test_rollbacks_alias_equals_state_rollbacks() -> None:
    p = Paths()
    assert p.rollbacks == p.state_rollbacks


def test_supersessions_alias_equals_state_supersessions() -> None:
    p = Paths()
    assert p.supersessions == p.state_supersessions


def test_emergency_alias_equals_state_emergency() -> None:
    p = Paths()
    assert p.emergency == p.state_emergency


def test_emergency_reviews_alias_equals_state_emergency_reviews() -> None:
    p = Paths()
    assert p.emergency_reviews == p.state_emergency_reviews


def test_reconciliation_alias_equals_state_reconciliation() -> None:
    p = Paths()
    assert p.reconciliation == p.state_reconciliation


def test_trust_runtime_private_alias_equals_runtime_private_dir() -> None:
    p = Paths()
    assert p.trust_runtime_private == p.runtime_private_dir


def test_trust_release_public_alias_equals_release_public_dir() -> None:
    p = Paths()
    assert p.trust_release_public == p.release_public_dir


def test_wpgovernpaths_is_paths_class() -> None:
    assert WPGovernPaths is Paths


def test_build_paths_none_returns_default_paths() -> None:
    p = build_paths(None)
    assert isinstance(p, Paths)
    assert p.root == Paths().root


def test_build_paths_existing_paths_returns_same_object() -> None:
    original = Paths(root=Path("/some/root"))
    result = build_paths(original)
    assert result is original


def test_build_paths_string_uses_as_root() -> None:
    p = build_paths("/custom/root")
    assert p.root == Path("/custom/root")


def test_build_paths_path_object_uses_as_root(tmp_path: Path) -> None:
    p = build_paths(tmp_path)
    assert p.root == tmp_path


def test_build_paths_config_uses_root_dir(tmp_path: Path) -> None:
    cfg = WPGovernConfig(root_dir=tmp_path)
    p = build_paths(cfg)
    assert p.root == tmp_path


def test_custom_root_propagates_to_all_derived_paths(tmp_path: Path) -> None:
    p = Paths(root=tmp_path)
    assert str(p.runtime_trust_store).startswith(str(tmp_path))
    assert str(p.release_trust_store).startswith(str(tmp_path))
    assert str(p.journal_trust_store).startswith(str(tmp_path))
    assert str(p.active_pointer).startswith(str(tmp_path))
    assert str(p.audit_log).startswith(str(tmp_path))
    assert str(p.baselines_dir).startswith(str(tmp_path))
    assert str(p.approvals_dir).startswith(str(tmp_path))
    assert str(p.locks_dir).startswith(str(tmp_path))
