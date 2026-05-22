"""
Tests for wpgovern.policy.rollback — RollbackService.

Coverage:
- approve creates signed bound rollback approval
- approve rejects non-existent or unsigned target baseline
- activate happy path: four files committed, all signed
- activate blocked when reconciliation gate exists
- activate rejects wrong approval type
- activate rejects missing target baseline after approval
- activate emits audit record when logger provided
- activate is silent without logger
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import NotFoundError, PolicyError
from wpgovern.policy import rollback as rollback_module
from wpgovern.policy.rollback import RollbackService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def env(tmp_path: Path) -> tuple[RollbackService, SigningService, WPGovernConfig]:
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
    service = RollbackService(config=config)
    return service, signing, config


def _write_and_sign(
    signing: SigningService, path: Path, payload: dict
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    signing.sign_file(path)


def _seed_active_baseline(
    signing: SigningService, config: WPGovernConfig, baseline_id: str
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


def test_approve_creates_signed_bound_rollback_approval(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    target_path = config.root_dir / "baselines" / "baseline-target.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-target", "status": "active"}
    )

    approval_id = service.approve("baseline-target", "revert bad deploy")

    approval_path = config.root_dir / "approvals" / f"{approval_id}.json"
    assert approval_path.exists()
    payload = _read_json(approval_path)
    assert payload["type"] == "rollback"
    assert payload["target_baseline_id"] == "baseline-target"
    assert payload["status"] == "approved"
    signing.verify_file(approval_path)


def test_approve_rejects_nonexistent_target_baseline(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, _, _ = env
    with pytest.raises(NotFoundError, match="not found"):
        service.approve("does-not-exist", "revert")


def test_approve_rejects_empty_reason(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    target_path = config.root_dir / "baselines" / "baseline-t.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-t", "status": "active"}
    )
    from wpgovern.policy.rollback import RollbackError
    with pytest.raises(RollbackError, match="cannot be empty"):
        service.approve("baseline-t", "   ")


# ---------------------------------------------------------------------------
# activate()
# ---------------------------------------------------------------------------


def test_activate_happy_path_four_files_all_signed(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    _seed_active_baseline(signing, config, "baseline-current")

    target_path = config.root_dir / "baselines" / "baseline-target.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-target", "status": "active"}
    )

    approval_id = service.approve("baseline-target", "revert")
    result = service.activate(approval_id)

    assert result.rolled_back_from == "baseline-current"
    assert result.rolled_back_to == "baseline-target"

    active = _read_json(config.active_pointer)
    assert active["baseline_id"] == "baseline-target"
    assert active["rollback"] is True
    signing.verify_active_pointer()

    approval_path = config.root_dir / "approvals" / f"{approval_id}.json"
    assert _read_json(approval_path)["status"] == "consumed"
    signing.verify_file(approval_path)

    rollbacks = [
        p for p in (config.root_dir / "state" / "rollbacks").glob("rollback-*.json")
        if not p.name.endswith(".sig.json")
    ]
    assert len(rollbacks) == 1
    signing.verify_file(rollbacks[0])


def test_activate_blocked_when_reconciliation_gate_exists(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    _seed_active_baseline(signing, config, "baseline-current")

    target_path = config.root_dir / "baselines" / "baseline-target.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-target", "status": "active"}
    )
    approval_id = service.approve("baseline-target", "revert")

    gate = config.root_dir / "state" / "reconciliation" / "required"
    gate.parent.mkdir(parents=True, exist_ok=True)
    gate.write_text("recon-123\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="reconciliation required"):
        service.activate(approval_id)


def test_activate_rejects_wrong_approval_type(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    _seed_active_baseline(signing, config, "baseline-current")

    wrong_path = config.root_dir / "approvals" / "approval-wrong.json"
    _write_and_sign(
        signing, wrong_path,
        {"approval_id": "approval-wrong", "type": "baseline",
         "status": "approved", "approved_at": "2026-01-01T00:00:00Z"},
    )

    with pytest.raises(PolicyError):
        service.activate("approval-wrong")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_activate_emits_rollback_activate_audit_record(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    _seed_active_baseline(signing, config, "baseline-current")
    target_path = config.root_dir / "baselines" / "baseline-target.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-target", "status": "active"}
    )
    approval_id = service.approve("baseline-target", "revert")

    audit_logger = AuditLogger(config=config)
    actor = {"actor_id": "alice", "reason": "revert bad deploy", "change_ticket": None}
    service.activate(approval_id, audit_logger=audit_logger, actor_context=actor)

    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    last = json.loads(lines[-1])
    assert last["event_type"] == "rollback.activate"
    assert last["outcome"] == "success"
    assert last["details"]["to"] == "baseline-target"


def test_activate_without_logger_does_not_create_audit_log(
    env: tuple[RollbackService, SigningService, WPGovernConfig],
) -> None:
    service, signing, config = env
    _seed_active_baseline(signing, config, "baseline-current")
    target_path = config.root_dir / "baselines" / "baseline-target.json"
    _write_and_sign(
        signing, target_path, {"baseline_id": "baseline-target", "status": "active"}
    )
    approval_id = service.approve("baseline-target", "revert")
    service.activate(approval_id)
    assert not config.audit_log.exists()
