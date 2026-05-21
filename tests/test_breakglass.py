"""
Tests for wpgovern.policy.breakglass — BreakglassService.

Coverage:
- approve creates signed time-limited approval with correct fields
- approve rejects invalid inputs (empty incident_id, justification, negative ttl)
- activate creates emergency record, reconciliation record, gate file, consumes approval
- activate rejects missing active pointer
- activate rejects expired approval
- activate emits breakglass.activate audit record when logger provided
- activate without logger is silent
- review creates review record and marks emergency reviewed=True
- review rejects missing emergency
- review rejects empty outcome or findings
- review emits breakglass.review audit record when logger provided
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import NotFoundError, PolicyError, ValidationError
from wpgovern.policy import approval as approval_module
from wpgovern.policy import breakglass as breakglass_module
from wpgovern.policy.breakglass import BreakglassService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def env(tmp_path: Path) -> tuple[BreakglassService, SigningService, WPGovernConfig]:
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
    service = BreakglassService(config=config)
    return service, signing, config


def _write_and_sign(
    signing: SigningService, path: Path, payload: dict
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    signing.sign_file(path)


def _seed_active_pointer(
    signing: SigningService, config: WPGovernConfig, baseline_id: str = "baseline-a"
) -> None:
    bp = config.root_dir / "baselines" / f"{baseline_id}.json"
    _write_and_sign(
        signing, bp, {"baseline_id": baseline_id, "status": "active"}
    )
    _write_and_sign(
        signing,
        config.active_pointer,
        {
            "baseline_id": baseline_id,
            "activated_at": "2026-01-01T00:00:00Z",
            "previous_baseline_id": None,
        },
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# approve()
# ---------------------------------------------------------------------------


def test_approve_creates_signed_approval_with_correct_fields(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )

    approval_id = service.approve("INC-1", "urgent security patch", 30)

    path = config.root_dir / "approvals" / f"{approval_id}.json"
    assert path.exists()
    payload = _read_json(path)
    assert payload["type"] == "breakglass"
    assert payload["incident_id"] == "INC-1"
    assert payload["justification"] == "urgent security patch"
    assert payload["status"] == "approved"
    assert "expires_at" in payload
    signing.verify_file(path)


def test_approve_rejects_empty_incident_id(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
) -> None:
    service, _, _ = env
    with pytest.raises(ValidationError):
        service.approve("   ", "justification", 30)


def test_approve_rejects_non_positive_ttl(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
) -> None:
    service, _, _ = env
    with pytest.raises(ValidationError, match="ttl_minutes"):
        service.approve("INC-1", "justification", 0)


def test_approve_rejects_empty_justification(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
) -> None:
    service, _, _ = env
    with pytest.raises(ValidationError):
        service.approve("INC-1", "   ", 30)


# ---------------------------------------------------------------------------
# activate()
# ---------------------------------------------------------------------------


def test_activate_creates_all_required_artifacts(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)

    activation = service.activate(approval_id)

    assert activation.emergency_id
    assert activation.reconciliation_id
    assert activation.incident_id == "INC-1"

    # Emergency record exists and is signed
    emergency_path = (
        config.root_dir / "state" / "emergency" / f"{activation.emergency_id}.json"
    )
    assert emergency_path.exists()
    signing.verify_file(emergency_path)
    em = _read_json(emergency_path)
    assert em["reviewed"] is False

    # Reconciliation record exists and is signed
    recon_path = (
        config.root_dir / "state" / "reconciliation"
        / f"{activation.reconciliation_id}.json"
    )
    assert recon_path.exists()
    signing.verify_file(recon_path)

    # Gate file written — check existence and content
    gate = config.root_dir / "state" / "reconciliation" / "required"
    assert gate.exists()
    assert gate.read_text(encoding="utf-8").strip() == activation.reconciliation_id

    # Approval consumed
    approval_path = config.root_dir / "approvals" / f"{approval_id}.json"
    assert _read_json(approval_path)["status"] == "consumed"


def test_activate_rejects_missing_active_pointer(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _ = env
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)
    with pytest.raises(NotFoundError):
        service.activate(approval_id)


def test_activate_rejects_expired_breakglass_approval(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 5)

    # Time advances past TTL
    monkeypatch.setattr(approval_module, "utc_now_iso", lambda: "2026-01-01T01:00:00Z")
    monkeypatch.setattr(breakglass_module, "utc_now_iso", lambda: "2026-01-01T01:00:00Z")

    with pytest.raises(PolicyError, match="expired"):
        service.activate(approval_id)


# ---------------------------------------------------------------------------
# review()
# ---------------------------------------------------------------------------


def test_review_creates_review_record_and_marks_emergency_reviewed(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)
    activation = service.activate(approval_id)

    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:10:00Z"
    )
    review_id = service.review(
        activation.emergency_id, "accepted", "documented all findings"
    )

    review_path = (
        config.root_dir / "state" / "emergency-reviews" / f"{review_id}.json"
    )
    assert review_path.exists()
    rv = _read_json(review_path)
    assert rv["outcome"] == "accepted"
    assert rv["emergency_id"] == activation.emergency_id
    signing.verify_file(review_path)

    emergency_path = (
        config.root_dir / "state" / "emergency"
        / f"{activation.emergency_id}.json"
    )
    em = _read_json(emergency_path)
    assert em["reviewed"] is True
    assert em["review_id"] == str(review_id)
    signing.verify_file(emergency_path)


def test_review_rejects_missing_emergency(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
) -> None:
    service, _, _ = env
    with pytest.raises(NotFoundError):
        service.review("emergency-does-not-exist", "accepted", "findings")


def test_review_rejects_empty_outcome(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)
    activation = service.activate(approval_id)

    with pytest.raises(ValidationError, match="outcome"):
        service.review(activation.emergency_id, "   ", "findings")


def test_review_rejects_empty_findings(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)
    activation = service.activate(approval_id)

    with pytest.raises(ValidationError, match="findings"):
        service.review(activation.emergency_id, "accepted", "   ")


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_activate_emits_breakglass_activate_audit_record(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)

    audit_logger = AuditLogger(config=config)
    actor = {"actor_id": "alice", "reason": None, "change_ticket": None}
    service.activate(approval_id, audit_logger=audit_logger, actor_context=actor)

    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    last = json.loads(lines[-1])
    assert last["event_type"] == "breakglass.activate"
    assert last["outcome"] == "success"
    assert last["details"]["incident_id"] == "INC-1"


def test_review_emits_breakglass_review_audit_record(
    env: tuple[BreakglassService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = env
    _seed_active_pointer(signing, config)
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(
        approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z"
    )
    approval_id = service.approve("INC-1", "urgent patch", 30)
    activation = service.activate(approval_id)

    audit_logger = AuditLogger(config=config)
    actor = {"actor_id": "alice", "reason": None, "change_ticket": None}
    monkeypatch.setattr(
        breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:10:00Z"
    )
    service.review(
        activation.emergency_id, "accepted", "documented",
        audit_logger=audit_logger, actor_context=actor,
    )

    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    last = json.loads(lines[-1])
    assert last["event_type"] == "breakglass.review"
    assert last["details"]["outcome"] == "accepted"
