"""
Regression tests for external review findings F1-F5.

F1 — verify_active_pointer checks referenced baseline has status == "active"
F2 — consume/revoke/check_expiry write JSON + signature atomically
F3 — consume/revoke acquire "approvals" lock before check-then-mutate
F4 — create_draft writes baseline JSON + signature atomically
F5 — sign/verify use private temp dirs (no symlink race window in governed dirs)
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.errors import PolicyError


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


def _make_services(cfg, trust):
    from wpgovern.core.signing import SigningService
    from wpgovern.core.baseline import BaselineService
    from wpgovern.policy.approval import ApprovalService
    signing = SigningService(config=cfg)
    baselines = BaselineService(config=cfg, signing=signing)
    approvals = ApprovalService(config=cfg, signing=signing)
    return signing, baselines, approvals


# ---------------------------------------------------------------------------
# F1 — verify_active_pointer checks baseline status
# ---------------------------------------------------------------------------

def test_f1_active_pointer_with_inactive_baseline_raises(env) -> None:
    """verify_active_pointer must raise IntegrityError if the referenced
    baseline is not in 'active' status.

    Pre-fix: only existence was checked; a pointer referencing a draft/approved
    baseline would pass, allowing a corrupted audit trail.
    """
    from wpgovern.core.signing import SigningService
    from wpgovern.errors import IntegrityError
    cfg, trust = env
    signing = SigningService(config=cfg)

    # Create a minimal active pointer JSON pointing to a non-existent-but-faked
    # baseline with status "draft"
    baselines_dir = cfg.root_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    fake_baseline = baselines_dir / "baseline-fake-001.json"
    fake_baseline.write_text(json.dumps({
        "baseline_id": "baseline-fake-001",
        "status": "draft",
        "wp_version": "6.5",
        "plugins": [],
        "themes": [],
    }))
    signing.sign_runtime_artifact(fake_baseline)

    # Write an active pointer to the draft baseline
    active_pointer = cfg.root_dir / "state" / "active.json"
    active_pointer.parent.mkdir(parents=True, exist_ok=True)
    active_pointer.write_text(json.dumps({"baseline_id": "baseline-fake-001"}))
    signing.sign_runtime_artifact(active_pointer)

    with pytest.raises(IntegrityError, match="status.*draft|not.*active|inactive"):
        signing.verify_active_pointer()


def test_f1_active_pointer_with_active_baseline_passes(env) -> None:
    """verify_active_pointer must succeed when referenced baseline is 'active'."""
    from wpgovern.core.signing import SigningService
    cfg, trust = env
    signing = SigningService(config=cfg)

    baselines_dir = cfg.root_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    fake_baseline = baselines_dir / "baseline-active-001.json"
    fake_baseline.write_text(json.dumps({
        "baseline_id": "baseline-active-001",
        "status": "active",
        "wp_version": "6.5",
        "plugins": [],
        "themes": [],
    }))
    signing.sign_runtime_artifact(fake_baseline)

    active_pointer = cfg.root_dir / "state" / "active.json"
    active_pointer.parent.mkdir(parents=True, exist_ok=True)
    active_pointer.write_text(json.dumps({"baseline_id": "baseline-active-001"}))
    signing.sign_runtime_artifact(active_pointer)

    signing.verify_active_pointer()  # must not raise


# ---------------------------------------------------------------------------
# F2 — consume/revoke are atomic (JSON + sig written together)
# ---------------------------------------------------------------------------

def _make_approval(cfg, signing, approval_id: str = "approval-f2-001") -> None:
    """Write a minimal approved approval with signature sidecar."""
    from wpgovern.policy.approval import ApprovalService
    approvals_dir = cfg.root_dir / "approvals"
    approvals_dir.mkdir(parents=True, exist_ok=True)
    path = approvals_dir / f"{approval_id}.json"
    payload = {
        "approval_id": approval_id,
        "type": "baseline",
        "status": "approved",
        "approved_at": "2026-01-01T00:00:00Z",
    }
    path.write_text(json.dumps(payload))
    signing.sign_runtime_artifact(path)


def test_f2_consume_writes_json_and_sig_together(env) -> None:
    """consume() must write JSON and signature atomically.
    Both files must exist after a successful consume."""
    cfg, trust = env
    signing, baselines, approvals = _make_services(cfg, trust)
    _make_approval(cfg, signing)

    approvals.consume("approval-f2-001")

    ap_path = cfg.root_dir / "approvals" / "approval-f2-001.json"
    sig_path = Path(str(ap_path) + ".sig.json")
    assert ap_path.exists(), "Approval JSON must exist after consume"
    assert sig_path.exists(), "Approval sig must exist after consume"

    content = json.loads(ap_path.read_text())
    assert content["status"] == "consumed"


def test_f2_revoke_writes_json_and_sig_together(env) -> None:
    """revoke() must write JSON and signature atomically."""
    cfg, trust = env
    signing, baselines, approvals = _make_services(cfg, trust)
    _make_approval(cfg, signing, "approval-f2-002")

    approvals.revoke("approval-f2-002", reason="test revoke")

    ap_path = cfg.root_dir / "approvals" / "approval-f2-002.json"
    sig_path = Path(str(ap_path) + ".sig.json")
    assert ap_path.exists()
    assert sig_path.exists()
    content = json.loads(ap_path.read_text())
    assert content["status"] == "revoked"


# ---------------------------------------------------------------------------
# F3 — consume/revoke acquire lock (prevent double-spend race)
# ---------------------------------------------------------------------------

def test_f3_consume_under_lock_prevents_double_consume(env) -> None:
    """Two concurrent consume calls must not both succeed on the same approval.
    The second must see status == 'consumed' and raise PolicyError."""
    cfg, trust = env
    signing, _, approvals = _make_services(cfg, trust)
    _make_approval(cfg, signing, "approval-f3-001")

    results = []
    errors = []

    def do_consume():
        try:
            approvals.consume("approval-f3-001")
            results.append("success")
        except PolicyError:
            errors.append("policy_error")

    t1 = threading.Thread(target=do_consume)
    t2 = threading.Thread(target=do_consume)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Exactly one must succeed; the other must get PolicyError
    assert len(results) == 1, f"Exactly one consume must succeed, got: {results}"
    assert len(errors) == 1, f"Exactly one consume must fail, got: {errors}"


def test_f3_revoke_is_serialized(env) -> None:
    """revoke() acquires the approvals lock — verify no exception on normal call."""
    cfg, trust = env
    signing, _, approvals = _make_services(cfg, trust)
    _make_approval(cfg, signing, "approval-f3-002")

    # Simple smoke: revoke must succeed and serialize correctly
    approvals.revoke("approval-f3-002", reason="revoked in test")

    # Second revoke must fail with PolicyError (already revoked)
    with pytest.raises(PolicyError, match="revoked"):
        approvals.revoke("approval-f3-002", reason="double revoke")


# ---------------------------------------------------------------------------
# F4 — create_draft is atomic
# ---------------------------------------------------------------------------

def test_f4_create_draft_leaves_signed_artifact(env) -> None:
    """create_draft must produce both baseline JSON and its signature sidecar."""
    cfg, trust = env
    signing, baselines, _ = _make_services(cfg, trust)

    with (mock.patch.object(baselines, "_wp_json_list", return_value=[]),
          mock.patch.object(baselines, "_wp_text", return_value="6.5")):
        baseline_id = str(baselines.create_draft())

    path = cfg.root_dir / "baselines" / f"{baseline_id}.json"
    sig_path = Path(str(path) + ".sig.json")

    assert path.exists()
    assert sig_path.exists()
    signing.verify_runtime_artifact(path)  # must not raise


def test_f4_create_draft_no_orphaned_unsigned_baseline(env) -> None:
    """If signing fails, no orphan unsigned baseline should persist."""
    from wpgovern.core.signing import SigningService
    cfg, trust = env
    signing, baselines, _ = _make_services(cfg, trust)

    def fail_sign(*args, **kwargs):
        raise OSError("Simulated signing failure")

    with (mock.patch.object(baselines, "_wp_json_list", return_value=[]),
          mock.patch.object(baselines, "_wp_text", return_value="6.5"),
          mock.patch.object(type(signing), "sign_staged", fail_sign)):
        with pytest.raises(Exception):
            baselines.create_draft()

    baselines_dir = cfg.root_dir / "baselines"
    if baselines_dir.exists():
        unsigned = [
            f for f in baselines_dir.glob("*.json")
            if not Path(str(f) + ".sig.json").exists()
        ]
        assert not unsigned, f"No unsigned baseline JSON should persist: {unsigned}"


# ---------------------------------------------------------------------------
# F5 — sign/verify use private temp dirs (no symlink race in governed dirs)
# ---------------------------------------------------------------------------

def test_f5_sign_file_no_raw_in_governed_dir(env) -> None:
    """sign_file must not leave .sig.raw files in the governed directory."""
    from wpgovern.core.signing import SigningService
    cfg, trust = env
    signing = SigningService(config=cfg)

    # Create a small artifact to sign
    artifact_dir = cfg.root_dir / "baselines"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact = artifact_dir / "test-f5.json"
    artifact.write_text(json.dumps({"test": "f5"}))

    signing.sign_file(artifact)

    # No .sig.raw file should remain in the governed directory
    raw_files = list(artifact_dir.glob("*.sig.raw")) + list(artifact_dir.glob(".*.sig.raw"))
    assert not raw_files, (
        f"No .sig.raw temp files should remain in governed directory after signing: {raw_files}"
    )


def test_f5_verify_file_no_raw_in_governed_dir(env) -> None:
    """verify_file must not leave .verify.raw files in the governed directory."""
    from wpgovern.core.signing import SigningService
    cfg, trust = env
    signing = SigningService(config=cfg)

    artifact_dir = cfg.root_dir / "baselines"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact = artifact_dir / "test-f5-verify.json"
    artifact.write_text(json.dumps({"test": "f5-verify"}))
    signing.sign_file(artifact)

    signing.verify_file(artifact)

    # No .verify.raw file should remain
    raw_files = (list(artifact_dir.glob("*.verify.raw")) +
                 list(artifact_dir.glob(".*.verify.raw")))
    assert not raw_files, (
        f"No .verify.raw temp files should remain after verify: {raw_files}"
    )
