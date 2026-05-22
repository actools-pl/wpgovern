"""
Tests for wpgovern.policy.approval — ApprovalService, ApprovalRecord.

Coverage:
- load() verifies signature before returning record
- load() raises NotFoundError when approval missing
- load_untrusted_for_inspection_only() reads without verification
- require_approved() accepts matching approved record
- require_approved() rejects consumed approval
- require_approved() rejects revoked approval
- require_approved() rejects expired approval (after TTL)
- require_approved() rejects type mismatch
- consume() transitions to consumed, re-signs, raises on re-use
- revoke() transitions to revoked with reason
- revoke() rejects empty reason
- revoke() rejects consumed approval
- prepare_consume() returns path+payload without writing
- invalid status in file raises ValidationError on load
- path-traversal approval_id rejected
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import NotFoundError, PolicyError, ValidationError
from wpgovern.policy import approval as approval_module
from wpgovern.policy.approval import ApprovalService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def services(tmp_path: Path) -> tuple[ApprovalService, SigningService, WPGovernConfig]:
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
    approval = ApprovalService(config=config)
    return approval, signing, config


def _create_signed_approval(
    signing: SigningService,
    config: WPGovernConfig,
    approval_id: str,
    *,
    approval_type: str = "baseline",
    status: str = "approved",
    expires_at: str | None = None,
) -> Path:
    payload: dict = {
        "approval_id": approval_id,
        "type": approval_type,
        "status": status,
        "approved_at": "2026-01-01T00:00:00Z",
    }
    if expires_at is not None:
        payload["expires_at"] = expires_at
    path = config.root_dir / "approvals" / f"{approval_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    signing.sign_file(path)
    return path


# ---------------------------------------------------------------------------
# load()
# ---------------------------------------------------------------------------


def test_load_returns_record_with_correct_fields(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1", approval_type="baseline")
    record = approval.load("approval-1")
    assert record.approval_id == "approval-1"
    assert record.type == "baseline"
    assert record.status == "approved"


def test_load_raises_not_found_when_approval_missing(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, _, _ = services
    with pytest.raises(NotFoundError):
        approval.load("does-not-exist")


def test_load_raises_on_tampered_signature(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    path = _create_signed_approval(signing, config, "approval-1")
    sig_path = path.with_name(path.name + ".sig.json")
    sig_payload = json.loads(sig_path.read_text())
    sig_payload["value_b64"] = "dGFtcGVyZWQ="  # not the real sig
    sig_path.write_text(json.dumps(sig_payload, indent=2) + "\n")
    from wpgovern.errors import IntegrityError
    with pytest.raises(IntegrityError):
        approval.load("approval-1")


def test_load_untrusted_reads_without_verification(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    path = _create_signed_approval(signing, config, "approval-1")
    sig_path = path.with_name(path.name + ".sig.json")
    sig_payload = json.loads(sig_path.read_text())
    sig_payload["value_b64"] = "dGFtcGVyZWQ="  # tampered sig
    sig_path.write_text(json.dumps(sig_payload, indent=2) + "\n")
    # Must not raise even with tampered signature
    record = approval.load_untrusted_for_inspection_only("approval-1")
    assert record.approval_id == "approval-1"


# ---------------------------------------------------------------------------
# require_approved()
# ---------------------------------------------------------------------------


def test_require_approved_accepts_matching_approved_record(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1", approval_type="baseline")
    record = approval.require_approved("approval-1", expected_type="baseline")
    assert record.status == "approved"


def test_require_approved_rejects_consumed_approval(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1", status="consumed")
    with pytest.raises(PolicyError, match="already consumed"):
        approval.require_approved("approval-1")


def test_require_approved_rejects_revoked_approval(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1", status="revoked")
    with pytest.raises(PolicyError, match="has been revoked"):
        approval.require_approved("approval-1")


def test_require_approved_rejects_type_mismatch(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1", approval_type="breakglass")
    with pytest.raises(PolicyError, match="expected 'baseline'"):
        approval.require_approved("approval-1", expected_type="baseline")


def test_require_approved_expires_and_rejects_past_ttl(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approval, signing, config = services
    path = _create_signed_approval(
        signing, config, "approval-1", expires_at="2026-01-01T00:00:00Z"
    )
    monkeypatch.setattr(approval_module, "utc_now_iso", lambda: "2026-01-01T00:01:00Z")
    with pytest.raises(PolicyError, match="has expired"):
        approval.check_expiry("approval-1")
    payload = json.loads(path.read_text())
    assert payload["status"] == "expired"
    assert payload["expired_at"] == "2026-01-01T00:01:00Z"


# ---------------------------------------------------------------------------
# consume()
# ---------------------------------------------------------------------------


def test_consume_transitions_to_consumed_and_resigns(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    path = _create_signed_approval(signing, config, "approval-1", approval_type="rollback")
    record = approval.consume("approval-1", expected_type="rollback")
    assert record.status == "consumed"
    payload = json.loads(path.read_text())
    assert payload["status"] == "consumed"
    assert "consumed_at" in payload
    signing.verify_file(path)


def test_consume_prevents_reuse(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1")
    approval.consume("approval-1")
    with pytest.raises(PolicyError, match="already consumed"):
        approval.require_approved("approval-1")


# ---------------------------------------------------------------------------
# revoke()
# ---------------------------------------------------------------------------


def test_revoke_transitions_to_revoked_and_resigns(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    path = _create_signed_approval(signing, config, "approval-1")
    record = approval.revoke("approval-1", "operator cancelled")
    assert record.status == "revoked"
    payload = json.loads(path.read_text())
    assert payload["revoke_reason"] == "operator cancelled"
    assert "revoked_at" in payload
    signing.verify_file(path)


def test_revoke_rejects_empty_reason(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1")
    with pytest.raises(ValidationError, match="must not be empty"):
        approval.revoke("approval-1", "   ")


def test_revoke_rejects_consumed_approval(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    _create_signed_approval(signing, config, "approval-1", status="consumed")
    with pytest.raises(PolicyError, match="cannot be revoked"):
        approval.revoke("approval-1", "late change")


# ---------------------------------------------------------------------------
# prepare_consume()
# ---------------------------------------------------------------------------


def test_prepare_consume_returns_path_and_payload_without_writing(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    path = _create_signed_approval(signing, config, "approval-1")
    original_content = path.read_text()

    final_path, consumed_payload = approval.prepare_consume("approval-1", expected_type="baseline")

    assert consumed_payload["status"] == "consumed"
    assert "consumed_at" in consumed_payload
    # Disk must be unchanged
    assert path.read_text() == original_content


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_load_rejects_invalid_status_in_file(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, signing, config = services
    path = config.root_dir / "approvals" / "approval-bad.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"approval_id":"approval-bad","status":"invalid","type":"baseline"}\n')
    signing.sign_file(path)
    with pytest.raises(ValidationError, match="invalid status"):
        approval.load("approval-bad")


def test_load_rejects_path_traversal_approval_id(
    services: tuple[ApprovalService, SigningService, WPGovernConfig],
) -> None:
    approval, _, _ = services
    with pytest.raises(ValidationError):
        approval.load("../escape")
