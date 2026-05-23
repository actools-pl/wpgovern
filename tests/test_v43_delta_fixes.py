"""
Regression tests for Phase δ fixes.

δ-1 — BreakglassService.approve uses stage_signed_json (atomic JSON + signature)
δ-2 — RollbackService.approve uses stage_signed_json (atomic JSON + signature)

After Phase δ, no method anywhere writes JSON then signs as two separate steps.
The JSON-then-sign defect class is fully eliminated from the codebase.
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# δ-1 — BreakglassService.approve atomicity
# ---------------------------------------------------------------------------

def test_delta1_breakglass_approve_atomicity_on_sign_failure(env) -> None:
    """BreakglassService.approve must not leave stale-signature approval on disk
    when signing fails mid-write.

    Pre-fix: _atomic_write_json wrote JSON, then sign_runtime_artifact was called
    separately. A crash between the two left an unsigned approval.
    Post-fix: stage_signed_json commits both atomically — signing failure means
    neither JSON nor signature file appears.
    """
    from wpgovern.core.signing import SigningService
    from wpgovern.policy.breakglass import BreakglassService

    cfg, trust = env
    S = SigningService(config=cfg)
    B = BreakglassService(config=cfg, signing=S)

    approvals_dir = cfg.root_dir / "approvals"
    approvals_before = set(approvals_dir.glob("*.json")) if approvals_dir.exists() else set()

    def failing_sign_staged(staged, final, domain="runtime"):
        raise RuntimeError("simulated signing failure mid-approve")

    with mock.patch.object(S, "sign_staged", failing_sign_staged):
        with pytest.raises(Exception):
            B.approve(
                incident_id="INC-delta1-001",
                justification="testing δ-1 atomicity",
                ttl_minutes=5,
            )

    approvals_after = set(approvals_dir.glob("*.json")) if approvals_dir.exists() else set()
    new_approvals = approvals_after - approvals_before
    assert not new_approvals, (
        f"breakglass.approve must not leave approval JSON when signing fails. "
        f"Found: {new_approvals}"
    )


def test_delta1_breakglass_approve_happy_path_leaves_signed_pair(env) -> None:
    """BreakglassService.approve must produce both JSON and signature on success."""
    from wpgovern.core.signing import SigningService
    from wpgovern.policy.breakglass import BreakglassService

    cfg, trust = env
    S = SigningService(config=cfg)
    B = BreakglassService(config=cfg, signing=S)

    approval_id = str(B.approve(
        incident_id="INC-delta1-002",
        justification="happy path test",
        ttl_minutes=30,
    ))

    approval_path = cfg.root_dir / "approvals" / f"{approval_id}.json"
    sig_path = Path(str(approval_path) + ".sig.json")

    assert approval_path.exists(), "Approval JSON must exist after successful approve"
    assert sig_path.exists(), "Approval signature must exist after successful approve"

    # Verify the signature is valid
    S.verify_runtime_artifact(approval_path)  # must not raise


# ---------------------------------------------------------------------------
# δ-2 — RollbackService.approve atomicity
# ---------------------------------------------------------------------------

def _create_active_baseline(cfg, trust, tmp_path) -> str:
    """Create and activate a minimal baseline so RollbackService has a target."""
    import json
    from wpgovern.core.signing import SigningService

    signing = SigningService(config=cfg)
    baselines_dir = cfg.root_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)

    baseline_id = "baseline-delta2-001"
    b_path = baselines_dir / f"{baseline_id}.json"
    payload = {
        "baseline_id": baseline_id,
        "created_at": "2026-01-01T00:00:00Z",
        "status": "active",
        "wp_version": "6.5",
        "plugins": [],
        "themes": [],
    }
    b_path.write_text(json.dumps(payload))
    signing.sign_runtime_artifact(b_path)

    # Write an active pointer
    active_ptr = cfg.root_dir / "state" / "active.json"
    active_ptr.parent.mkdir(parents=True, exist_ok=True)
    active_ptr.write_text(json.dumps({"baseline_id": baseline_id}))
    signing.sign_runtime_artifact(active_ptr)

    return baseline_id


def test_delta2_rollback_approve_atomicity_on_sign_failure(env, tmp_path) -> None:
    """RollbackService.approve must not leave stale-signature approval on disk
    when signing fails mid-write.

    Pre-fix: same JSON-then-sign split as breakglass. Post-fix: stage_signed_json.
    """
    from wpgovern.core.signing import SigningService
    from wpgovern.policy.rollback import RollbackService

    cfg, trust = env
    S = SigningService(config=cfg)
    R = RollbackService(config=cfg, signing=S)

    target_baseline_id = _create_active_baseline(cfg, trust, tmp_path)

    approvals_dir = cfg.root_dir / "approvals"
    approvals_before = set(approvals_dir.glob("*.json")) if approvals_dir.exists() else set()

    def failing_sign_staged(staged, final, domain="runtime"):
        raise RuntimeError("simulated signing failure mid-approve")

    with mock.patch.object(S, "sign_staged", failing_sign_staged):
        with pytest.raises(Exception):
            R.approve(
                target_baseline_id=target_baseline_id,
                reason="testing δ-2 atomicity",
            )

    approvals_after = set(approvals_dir.glob("*.json")) if approvals_dir.exists() else set()
    new_approvals = approvals_after - approvals_before
    assert not new_approvals, (
        f"rollback.approve must not leave approval JSON when signing fails. "
        f"Found: {new_approvals}"
    )


def test_delta2_rollback_approve_happy_path_leaves_signed_pair(env, tmp_path) -> None:
    """RollbackService.approve must produce both JSON and signature on success."""
    from wpgovern.core.signing import SigningService
    from wpgovern.policy.rollback import RollbackService

    cfg, trust = env
    S = SigningService(config=cfg)
    R = RollbackService(config=cfg, signing=S)

    target_baseline_id = _create_active_baseline(cfg, trust, tmp_path)

    approval_id = str(R.approve(
        target_baseline_id=target_baseline_id,
        reason="happy path rollback approval",
    ))

    approval_path = cfg.root_dir / "approvals" / f"{approval_id}.json"
    sig_path = Path(str(approval_path) + ".sig.json")

    assert approval_path.exists(), "Rollback approval JSON must exist on success"
    assert sig_path.exists(), "Rollback approval signature must exist on success"

    S.verify_runtime_artifact(approval_path)  # must not raise


# ---------------------------------------------------------------------------
# Structural guard — no JSON-then-sign anywhere in codebase
# ---------------------------------------------------------------------------

def test_no_json_then_sign_split_anywhere() -> None:
    """After Phase δ, no method should write JSON and then sign as two separate steps.

    This structural test greps for the pattern: _atomic_write_json on one line
    followed by sign_runtime_artifact on the adjacent line. Both must be absent
    from production code after this phase.
    """
    import re
    from pathlib import Path

    repo_root = Path(__file__).parent.parent
    violations = []

    for fpath in sorted(repo_root.rglob("*.py")):
        if any(s in str(fpath) for s in ["venv", ".pytest_cache", "__pycache__", "tests/"]):
            continue
        try:
            text = fpath.read_text(encoding="utf-8")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if "_atomic_write_json" in line and "def _atomic_write_json" not in line:
                # Check the next few lines for a sign call
                context = "\n".join(lines[i:i + 4])
                if "sign_runtime_artifact" in context or "sign_release_artifact" in context:
                    violations.append(
                        f"{fpath.relative_to(repo_root)}:{i+1}: "
                        f"JSON-then-sign split pattern detected"
                    )

    assert not violations, (
        "JSON-then-sign split patterns found — use stage_signed_json instead:\n"
        + "\n".join(f"  {v}" for v in violations)
    )
