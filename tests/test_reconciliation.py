"""
Tests for wpgovern.policy.reconciliation — ReconciliationService.

Coverage:
- complete: non-breakglass reconciliation succeeds and clears gate
- complete: breakglass reconciliation fails when emergency not reviewed
- complete: breakglass reconciliation fails when review record missing
- complete: breakglass reconciliation fails when emergency unsigned/tampered
- complete: breakglass reconciliation fails when review unsigned/tampered
- complete: breakglass reconciliation fails on review/emergency ID mismatch
- complete: breakglass reconciliation succeeds with valid full review chain
- complete emits reconciliation.complete audit record when logger provided
- baseline.activate blocked when gate exists (enforcement integration)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import PolicyError
from wpgovern.policy import breakglass as breakglass_module
from wpgovern.policy.breakglass import BreakglassService
from wpgovern.policy.reconciliation import ReconciliationError, ReconciliationService


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_env(tmp_path: Path) -> tuple[
    ReconciliationService, BreakglassService, SigningService, WPGovernConfig
]:
    root = tmp_path / "wpg"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")
    signing = SigningService(config=config, trust_service=trust)
    recon_service = ReconciliationService(config=config)
    bg_service = BreakglassService(config=config)
    return recon_service, bg_service, signing, config


def _seed_active_pointer(signing: SigningService, config: WPGovernConfig) -> None:
    bp = config.root_dir / "baselines" / "baseline-a.json"
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_text(
        json.dumps({"baseline_id": "baseline-a", "status": "active"}, indent=2) + "\n"
    )
    signing.sign_file(bp)
    config.active_pointer.parent.mkdir(parents=True, exist_ok=True)
    config.active_pointer.write_text(
        json.dumps({
            "baseline_id": "baseline-a",
            "activated_at": "2026-01-01T00:00:00Z",
            "previous_baseline_id": None,
        }, indent=2) + "\n"
    )
    signing.sign_file(config.active_pointer)


def _write_and_sign(signing: SigningService, path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    signing.sign_file(path)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_full_breakglass(
    bg: BreakglassService,
    recon: ReconciliationService,
    signing: SigningService,
    config: WPGovernConfig,
    monkeypatch: pytest.MonkeyPatch,
    *,
    do_review: bool = True,
) -> tuple[str, str, str]:
    """Run approve→activate→(optionally review). Return (approval_id, emergency_id, recon_id)."""
    monkeypatch.setattr(breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    from wpgovern.policy import approval as _amod
    monkeypatch.setattr(_amod, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    approval_id = bg.approve("INC-1", "urgent patch", 30)
    activation = bg.activate(approval_id)
    if do_review:
        monkeypatch.setattr(
            breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:10:00Z"
        )
        bg.review(activation.emergency_id, "accepted", "documented findings")
    return approval_id, activation.emergency_id, activation.reconciliation_id


# ---------------------------------------------------------------------------
# Non-breakglass reconciliation
# ---------------------------------------------------------------------------


def test_complete_non_breakglass_reconciliation_succeeds_and_clears_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, _, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)

    recon_path = config.root_dir / "state" / "reconciliation" / "recon-manual.json"
    _write_and_sign(
        signing, recon_path,
        {"reconciliation_id": "recon-manual", "source": "manual", "status": "required"},
    )
    gate = config.root_dir / "state" / "reconciliation" / "required"
    gate.parent.mkdir(parents=True, exist_ok=True)
    gate.write_text("recon-manual\n", encoding="utf-8")

    result = recon.complete("recon-manual")

    assert result["status"] == "completed"
    assert not gate.exists()
    signing.verify_file(recon_path)


# ---------------------------------------------------------------------------
# Breakglass enforcement
# ---------------------------------------------------------------------------


def test_complete_breakglass_fails_when_emergency_not_reviewed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, _, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=False
    )
    with pytest.raises(ReconciliationError, match="not been reviewed"):
        recon.complete(recon_id)


def test_complete_breakglass_fails_when_review_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, emergency_id, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=True
    )

    # Remove the review file
    emergency_path = config.root_dir / "state" / "emergency" / f"{emergency_id}.json"
    em = _read_json(emergency_path)
    review_id = em["review_id"]
    (config.root_dir / "state" / "emergency-reviews" / f"{review_id}.json").unlink()
    (config.root_dir / "state" / "emergency-reviews" / f"{review_id}.json.sig.json").unlink(missing_ok=True)

    with pytest.raises(ReconciliationError, match="not found"):
        recon.complete(recon_id)


def test_complete_breakglass_fails_when_emergency_unsigned_or_tampered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, emergency_id, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=True
    )

    # Tamper the emergency signature
    emergency_path = config.root_dir / "state" / "emergency" / f"{emergency_id}.json"
    sig_path = emergency_path.with_name(emergency_path.name + ".sig.json")
    sig = _read_json(sig_path)
    sig["value_b64"] = "dGFtcGVyZWQ="
    sig_path.write_text(json.dumps(sig, indent=2) + "\n")

    from wpgovern.errors import IntegrityError
    with pytest.raises((ReconciliationError, IntegrityError, PolicyError)):
        recon.complete(recon_id)


def test_complete_breakglass_fails_when_review_unsigned_or_tampered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, emergency_id, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=True
    )

    emergency_path = config.root_dir / "state" / "emergency" / f"{emergency_id}.json"
    em = _read_json(emergency_path)
    review_id = em["review_id"]
    review_path = config.root_dir / "state" / "emergency-reviews" / f"{review_id}.json"
    sig_path = review_path.with_name(review_path.name + ".sig.json")
    sig = _read_json(sig_path)
    sig["value_b64"] = "dGFtcGVyZWQ="
    sig_path.write_text(json.dumps(sig, indent=2) + "\n")

    from wpgovern.errors import IntegrityError
    with pytest.raises((ReconciliationError, IntegrityError, PolicyError)):
        recon.complete(recon_id)


def test_complete_breakglass_fails_on_review_emergency_id_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, emergency_id, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=True
    )

    emergency_path = config.root_dir / "state" / "emergency" / f"{emergency_id}.json"
    em = _read_json(emergency_path)
    review_id = em["review_id"]
    review_path = config.root_dir / "state" / "emergency-reviews" / f"{review_id}.json"
    rv = _read_json(review_path)
    rv["emergency_id"] = "wrong-emergency-id"
    _write_and_sign(signing, review_path, rv)

    with pytest.raises(ReconciliationError, match="emergency ID"):
        recon.complete(recon_id)


def test_complete_breakglass_succeeds_with_valid_full_review_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, _, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=True
    )

    result = recon.complete(recon_id)

    assert result["status"] == "completed"
    gate = config.root_dir / "state" / "reconciliation" / "required"
    assert not gate.exists()


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_complete_emits_reconciliation_complete_audit_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)
    _, _, recon_id = _run_full_breakglass(
        bg, recon, signing, config, monkeypatch, do_review=True
    )

    audit_logger = AuditLogger(config=config)
    actor = {"actor_id": "alice", "reason": None, "change_ticket": None}
    recon.complete(recon_id, audit_logger=audit_logger, actor_context=actor)

    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    last = json.loads(lines[-1])
    assert last["event_type"] == "reconciliation.complete"
    assert last["outcome"] == "success"
    assert last["details"]["reconciliation_id"] == recon_id


# ---------------------------------------------------------------------------
# Enforcement integration: baseline.activate blocked when gate exists
# ---------------------------------------------------------------------------


def test_baseline_activate_blocked_by_breakglass_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Activation blocked when breakglass reconciliation gate is present."""
    from wpgovern.core.baseline import BaselineService
    from wpgovern.core import baseline as baseline_module

    recon, bg, signing, config = _make_env(tmp_path)
    _seed_active_pointer(signing, config)

    monkeypatch.setattr(breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    from wpgovern.policy import approval as _amod
    monkeypatch.setattr(_amod, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    approval_id = bg.approve("INC-1", "urgent patch", 30)
    bg.activate(approval_id)

    assert (config.root_dir / "state" / "reconciliation" / "required").exists()

    # Now try a rollback — it should be blocked by the gate.
    # First create a target baseline and approval so the code reaches the gate check.
    from wpgovern.policy.rollback import RollbackService
    rollback = RollbackService(config=config)

    target_path = config.root_dir / "baselines" / "baseline-target.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-target", "status": "active"}
    )
    rb_approval_id = rollback.approve("baseline-target", "revert")

    with pytest.raises(PolicyError, match="reconciliation required"):
        rollback.activate(rb_approval_id)
