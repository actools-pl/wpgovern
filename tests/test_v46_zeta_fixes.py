"""
Regression tests for Phase ζ fixes.

ζ-1 — governance-check integrates check_all_invariants (exit 21)
ζ-2 — Bootstrap recovery marker for double-failure (exit 34)
"""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
from unittest import mock

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService


@pytest.fixture()
def env(tmp_path: Path):
    root = tmp_path / "root"
    cfg = WPGovernConfig(
        root_dir=root, install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    trust = TrustService(config=cfg)
    trust.generate_runtime_key("runtime-1")
    trust.activate_runtime_key("runtime-1")
    trust.generate_release_key("release-1")
    trust.activate_release_key("release-1")
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")
    return cfg, trust


def _make_active_pointer(cfg, trust) -> None:
    """Create a minimal active pointer so governance-check runs invariants."""
    import json as _json
    from wpgovern.core.signing import SigningService
    from wpgovern.core.baseline import BaselineService

    signing = SigningService(config=cfg)
    baselines_dir = cfg.root_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    b_path = baselines_dir / "baseline-1.json"
    payload = {"baseline_id": "baseline-1", "status": "active",
               "wp_version": "6.5", "plugins": [], "themes": [],
               "created_at": "2026-01-01T00:00:00Z"}
    b_path.write_text(_json.dumps(payload))
    signing.sign_runtime_artifact(b_path)

    cfg.active_pointer.parent.mkdir(parents=True, exist_ok=True)
    cfg.active_pointer.write_text(_json.dumps({"baseline_id": "baseline-1"}))
    signing.sign_runtime_artifact(cfg.active_pointer)


# ---------------------------------------------------------------------------
# ζ-1 — governance-check integrates check_all_invariants
# ---------------------------------------------------------------------------

def test_zeta1_governance_check_fires_on_invariant_violation(env) -> None:
    """ζ-1: governance-check must return exit 21 when check_all_invariants
    reports violations.

    Pre-fix: governance-check returned 0 ok while check_all_invariants
    reported I-T-4 violations. The two enforcement sites disagreed.
    """
    from wpgovern.status.checker import GovernanceChecker
    cfg, trust = env
    _make_active_pointer(cfg, trust)
    trust.generate_runtime_key("runtime-2")

    # Delete preactive private key — I-T-4 fires (missing private key for preactive)
    (cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem").unlink()

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 21, (
        f"governance-check must return 21 (invariant violation) when I-T-4 fires. "
        f"Got {result.exit_code} with reason '{result.reason}'"
    )
    assert "I-T" in result.reason or "invariants_violated" in result.reason


def test_zeta1_governance_check_clean_state_returns_ok(env) -> None:
    """ζ-1: governance-check must still return 0 when no violations exist."""
    from wpgovern.status.checker import GovernanceChecker
    cfg, trust = env
    _make_active_pointer(cfg, trust)

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 0, (
        f"governance-check must return 0 ok on clean state. "
        f"Got {result.exit_code} with reason '{result.reason}'"
    )


def test_zeta1_invariant_runner_crash_surfaces_distinctly(env, monkeypatch) -> None:
    """ζ-1: if check_all_invariants crashes, governance-check reports the error."""
    from wpgovern.status.checker import GovernanceChecker
    import wpgovern.utils.invariants as inv_mod
    cfg, trust = env
    _make_active_pointer(cfg, trust)

    def crashing_check(_config):
        raise RuntimeError("simulated invariant runner crash")

    monkeypatch.setattr(inv_mod, "check_all_invariants", crashing_check)

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 21
    assert "invariant_runner_error" in result.reason


def test_zeta1_trust_corruption_returns_20_not_21(env) -> None:
    """ζ-1: corrupt trust store returns exit 20 (not 21 from invariants).
    Trust check runs before invariant check in the priority hierarchy.
    """
    from wpgovern.status.checker import GovernanceChecker
    cfg, trust = env
    _make_active_pointer(cfg, trust)

    store_path = cfg.root_dir / "trust" / "runtime" / "public" / "trusted-runtime-keys.json"
    store_path.write_text("{not valid json")

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 20, (
        f"Corrupt trust store must produce exit 20, not invariant exit 21. "
        f"Got {result.exit_code} with reason '{result.reason}'"
    )


# ---------------------------------------------------------------------------
# ζ-2 — Bootstrap recovery marker
# ---------------------------------------------------------------------------

def test_zeta2_marker_written_on_rollback_failure(env, monkeypatch) -> None:
    """ζ-2: when _rollback_writes_from_prior fails, the bootstrap recovery
    marker must be written so governance-check can surface it.

    Pre-fix: the OSError was silently swallowed. Operator saw the original
    TransactionError but had no signal that rollback also failed.
    """
    from wpgovern.utils.transaction import AtomicTransaction, TransactionError

    cfg, _ = env
    target = cfg.root_dir / "state" / "data.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"v": 1}')

    gate = cfg.root_dir / "state" / "gate.lock"
    gate.write_text("locked")

    staging = cfg.root_dir / "state" / ".staging"
    staging.mkdir(parents=True, exist_ok=True)

    real_unlink = Path.unlink
    real_replace = os.replace
    fail_count = {"unlink": 0}
    rollback_triggered = {"v": False}

    def failing_unlink(self, *args, **kwargs):
        if str(self).endswith("gate.lock") and fail_count["unlink"] == 0:
            fail_count["unlink"] += 1
            rollback_triggered["v"] = True
            raise OSError(errno.EACCES, "fail delete — triggers rollback")
        return real_unlink(self, *args, **kwargs)

    def failing_replace(src, dst, *args, **kwargs):
        # Only fail the rollback restore (which writes .rollback_tmp → data.json)
        # Don't fail the initial staged write (src is in .staging, not .rollback_tmp)
        if rollback_triggered["v"] and str(src).endswith(".rollback_tmp") and "data.json" in str(dst):
            raise OSError(errno.EACCES, "fail rollback restore")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises((Exception,)):
        with AtomicTransaction(staging, service_label=None, actor_id=None) as txn:
            txn.stage_text(target, '{"v": 2}')
            txn.stage_delete(gate)
            txn.commit()

    monkeypatch.undo()

    marker_path = cfg.root_dir / "state" / ".bootstrap_recovery_required.json"
    assert marker_path.is_file(), (
        "Bootstrap recovery marker must be written when rollback fails. "
        "Pre-fix: the restore OSError was silently swallowed."
    )
    marker = json.loads(marker_path.read_text())
    assert marker["marker_version"] == 1
    assert "failed_restores" in marker
    assert len(marker["failed_restores"]) >= 1


def test_zeta2_governance_check_surfaces_marker(env) -> None:
    """ζ-2: governance-check must return exit 34 when the marker file exists."""
    from wpgovern.status.checker import GovernanceChecker
    cfg, _ = env

    marker_path = cfg.root_dir / "state" / ".bootstrap_recovery_required.json"
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(json.dumps({
        "marker_version": 1,
        "detected_at": "2026-05-10T12:00:00Z",
        "txn_id": "test-txn",
        "service_label": None,
        "failed_restores": [{"target": "/tmp/x", "kind": "file", "error": "test"}],
        "guidance": "test marker",
    }))

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 34
    assert result.reason == "bootstrap_recovery_required"


def test_zeta2_marker_takes_priority_over_invariants(env) -> None:
    """ζ-2: bootstrap marker surfaces before invariant check (exit 34, not 21)."""
    from wpgovern.status.checker import GovernanceChecker
    cfg, trust = env
    _make_active_pointer(cfg, trust)
    trust.generate_runtime_key("runtime-2")

    # Delete preactive key (triggers I-T-4) AND plant marker
    (cfg.root_dir / "trust" / "runtime" / "private" / "runtime-2.pem").unlink()

    marker_path = cfg.root_dir / "state" / ".bootstrap_recovery_required.json"
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    marker_path.write_text(json.dumps({
        "marker_version": 1, "detected_at": "2026-05-10T12:00:00Z",
        "txn_id": "test", "service_label": None,
        "failed_restores": [], "guidance": "test",
    }))

    result = GovernanceChecker(config=cfg).check()
    assert result.exit_code == 34, (
        f"Bootstrap marker must take priority over invariant violations. "
        f"Got {result.exit_code} with reason '{result.reason}'"
    )
