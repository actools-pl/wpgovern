"""
Tests for wpgovern.core.baseline — BaselineService, BaselineRecord.

Coverage:
- create_draft captures WP state and produces signed draft baseline
- submit transitions draft → submitted, re-signs
- submit rejects non-draft baseline
- approve transitions submitted → approved, creates bound signed approval
- approve rejects non-submitted baseline
- activate transitions approved → active, consumes approval, writes active pointer
  and supersession record, all four files signed atomically
- activate rejects mismatched approval (approval bound to different baseline)
- activate is blocked when reconciliation_required file exists
- activate with audit_logger emits baseline.activate record
- activate without audit_logger is silent (no audit log created)
- baseline signature verified before activation
- approval signature verified before activation
- atomic commit: mid-commit failure followed by recovery restores pre-activation state
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.core import baseline as baseline_module
from wpgovern.core.baseline import BaselineService
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import NotFoundError, PolicyError
from wpgovern.utils.transaction import TransactionError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def services(tmp_path: Path) -> tuple[BaselineService, SigningService, WPGovernConfig]:
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
    service = BaselineService(config=config)
    return service, signing, config


def _fake_wp_json(self: BaselineService, args: list[str]) -> list:
    return [{"name": args[0], "status": "active"}]


def _fake_wp_text(self: BaselineService, args: list[str]) -> str:
    return "6.8.1"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# create_draft
# ---------------------------------------------------------------------------


def test_create_draft_produces_signed_baseline_with_correct_fields(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = services
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")

    baseline_id = service.create_draft()

    # Fix 2: baseline IDs now include a UUID4 suffix for collision resistance.
    # The format is: baseline-YYYYMMDDHHMMSS-{8 hex chars}
    assert baseline_id.startswith("baseline-20260101000000-")
    assert len(baseline_id) == len("baseline-20260101000000-") + 8
    path = config.root_dir / "baselines" / f"{baseline_id}.json"
    payload = _read_json(path)
    assert payload["baseline_id"] == baseline_id
    assert payload["status"] == "draft"
    assert payload["wp_version"] == "6.8.1"
    signing.verify_file(path)


# ---------------------------------------------------------------------------
# submit
# ---------------------------------------------------------------------------


def test_submit_transitions_draft_to_submitted_and_resigns(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = services
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")
    baseline_id = service.create_draft()

    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:05:00Z")
    service.submit(baseline_id)

    path = config.root_dir / "baselines" / f"{baseline_id}.json"
    payload = _read_json(path)
    assert payload["status"] == "submitted"
    assert payload["submitted_at"] == "2026-01-01T00:05:00Z"
    signing.verify_file(path)


def test_submit_rejects_non_draft_baseline(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _ = services
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")
    baseline_id = service.create_draft()
    service.submit(baseline_id)

    with pytest.raises(PolicyError, match="cannot be submitted"):
        service.submit(baseline_id)


# ---------------------------------------------------------------------------
# approve
# ---------------------------------------------------------------------------


def test_approve_creates_bound_signed_approval(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = services
    times = iter(["2026-01-01T00:00:00Z"] * 2 + ["2026-01-01T00:10:00Z"] * 5)
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: next(times))
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")

    baseline_id = service.create_draft()
    service.submit(baseline_id)
    approval_id = service.approve(baseline_id)

    # Fix 2: approval IDs now include a UUID4 suffix for collision resistance.
    assert approval_id.startswith("approval-20260101001000-")
    assert len(approval_id) == len("approval-20260101001000-") + 8
    approval_path = config.root_dir / "approvals" / f"{approval_id}.json"
    payload = _read_json(approval_path)
    assert payload["type"] == "baseline"
    assert payload["baseline_id"] == baseline_id
    assert payload["status"] == "approved"
    signing.verify_file(approval_path)


def test_approve_rejects_non_submitted_baseline(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _ = services
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")
    baseline_id = service.create_draft()

    with pytest.raises(PolicyError, match="cannot be approved"):
        service.approve(baseline_id)


# ---------------------------------------------------------------------------
# activate
# ---------------------------------------------------------------------------


def _run_full_lifecycle(
    service: BaselineService,
    monkeypatch: pytest.MonkeyPatch,
    *,
    start_time: str = "2026-01-01T00:00:00Z",
) -> tuple[str, str]:
    """Helper: create → submit → approve, return (baseline_id, approval_id)."""
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: start_time)
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")
    baseline_id = service.create_draft()
    service.submit(baseline_id)
    approval_id = service.approve(baseline_id)
    return str(baseline_id), approval_id


def test_activate_commits_all_four_files_and_all_are_signed(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = services
    baseline_id, approval_id = _run_full_lifecycle(service, monkeypatch)

    service.activate(baseline_id, approval_id)

    baseline_path = config.root_dir / "baselines" / f"{baseline_id}.json"
    approval_path = config.root_dir / "approvals" / f"{approval_id}.json"
    assert _read_json(baseline_path)["status"] == "active"
    assert _read_json(approval_path)["status"] == "consumed"
    assert config.active_pointer.exists()
    active_payload = _read_json(config.active_pointer)
    assert active_payload["baseline_id"] == baseline_id

    signing.verify_file(baseline_path)
    signing.verify_file(approval_path)
    signing.verify_active_pointer()


def test_activate_writes_supersession_record(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = services

    # Set up an existing active baseline
    old_path = config.root_dir / "baselines" / "baseline-old.json"
    _write_json(old_path, {"baseline_id": "baseline-old", "status": "active"})
    signing.sign_file(old_path)
    _write_json(config.active_pointer, {
        "baseline_id": "baseline-old",
        "activated_at": "2025-12-31T00:00:00Z",
        "previous_baseline_id": None,
    })
    signing.sign_file(config.active_pointer)

    baseline_id, approval_id = _run_full_lifecycle(
        service, monkeypatch, start_time="2026-01-01T00:15:00Z"
    )
    service.activate(baseline_id, approval_id)

    active_payload = _read_json(config.active_pointer)
    assert active_payload["previous_baseline_id"] == "baseline-old"

    supersessions = [
        p for p in
        (config.root_dir / "state" / "supersessions").glob("supersession-*.json")
        if not p.name.endswith(".sig.json")
    ]
    assert len(supersessions) == 1
    s_payload = _read_json(supersessions[0])
    assert s_payload["superseded_baseline_id"] == "baseline-old"
    assert s_payload["replacement_baseline_id"] == baseline_id
    signing.verify_file(supersessions[0])


def test_activate_rejects_mismatched_approval(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _ = services
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")

    baseline_a = service.create_draft()
    service.submit(baseline_a)
    approval_a = service.approve(baseline_a)

    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:20:00Z")
    baseline_b = service.create_draft()
    service.submit(baseline_b)

    with pytest.raises(PolicyError, match="does not match baseline"):
        service.activate(str(baseline_b), approval_a)


def test_activate_blocked_when_reconciliation_required(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, config = services
    baseline_id, approval_id = _run_full_lifecycle(service, monkeypatch)

    required = config.root_dir / "state" / "reconciliation" / "required"
    required.parent.mkdir(parents=True, exist_ok=True)
    required.write_text("recon-123\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="reconciliation required"):
        service.activate(baseline_id, approval_id)


def test_activate_raises_when_baseline_signature_missing(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, config = services
    baseline_id, approval_id = _run_full_lifecycle(service, monkeypatch)

    sig_path = config.root_dir / "baselines" / f"{baseline_id}.json.sig.json"
    sig_path.unlink()

    with pytest.raises(NotFoundError, match="Signature file missing"):
        service.activate(baseline_id, approval_id)


# ---------------------------------------------------------------------------
# Audit emission
# ---------------------------------------------------------------------------


def test_activate_emits_audit_record_when_logger_provided(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, config = services
    baseline_id, approval_id = _run_full_lifecycle(service, monkeypatch)

    audit_logger = AuditLogger(config=config)
    actor_context = {
        "actor_id": "alice",
        "reason": "regression test",
        "change_ticket": "CHG-1234",
    }
    service.activate(
        baseline_id, approval_id,
        audit_logger=audit_logger, actor_context=actor_context,
    )

    lines = [
        l for l in config.audit_log.read_text().splitlines() if l.strip()
    ]
    last = json.loads(lines[-1])
    assert last["event_type"] == "baseline.activate"
    assert last["outcome"] == "success"
    assert last["actor"] == "alice"
    assert last["details"]["baseline_id"] == baseline_id
    assert last["details"]["approval_id"] == approval_id


def test_activate_without_audit_logger_does_not_create_audit_log(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, config = services
    baseline_id, approval_id = _run_full_lifecycle(service, monkeypatch)
    service.activate(baseline_id, approval_id)
    assert not config.audit_log.exists()


# ---------------------------------------------------------------------------
# Atomic commit + recovery
# ---------------------------------------------------------------------------


def test_activate_mid_commit_failure_followed_by_recovery_restores_pre_activation_state(
    services: tuple[BaselineService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, signing, config = services
    baseline_id, approval_id = _run_full_lifecycle(service, monkeypatch)

    baseline_path = config.root_dir / "baselines" / f"{baseline_id}.json"
    approval_path = config.root_dir / "approvals" / f"{approval_id}.json"
    pre_baseline = _read_json(baseline_path)
    pre_approval = _read_json(approval_path)

    real_replace = os.replace
    journal_dir = str(config.root_dir / "state" / ".journal")
    count = {"n": 0}

    def flaky_replace(src: str, dst: str) -> None:
        if not str(dst).startswith(journal_dir):
            count["n"] += 1
            if count["n"] >= 2:
                raise OSError("simulated mid-commit failure")
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(TransactionError, match="commit failed"):
        service.activate(baseline_id, approval_id)

    monkeypatch.setattr(os, "replace", real_replace)

    from wpgovern.utils.recovery import RecoveryService
    result = RecoveryService(config).recover()
    assert result.outcomes[0].event_type == "recovery.rolled_back"
    assert not result.any_refused

    assert _read_json(baseline_path) == pre_baseline
    assert _read_json(approval_path) == pre_approval
