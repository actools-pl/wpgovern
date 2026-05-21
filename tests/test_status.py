"""
Tests for wpgovern.status.checker and wpgovern.status.reporter.

Coverage:
- Exit code 0: healthy state
- Exit code 10: reconciliation required
- Exit code 11: expired unreviewed break-glass approval
- Exit code 11: pending emergency review
- Exit code 12: journal staleness exceeded enforcement threshold
- Exit code 13: journal signing key unavailable
- Exit code 20: corrupt trust store
- Exit code 20: corrupt active pointer signature
- Exit code 33: unresolved B4 event
- Exit code 33: resolved B4 event does not fire
- Exit code 50: audit review overdue (no checkpoint)
- Exit code 50: audit review overdue (checkpoint too old)
- Exit code 50: not fired when review_max_age_days not configured
- Exit code 51: audit chain integrity failure (S-2)
- Exit code 51 is distinct from 50
- Reconciliation gate has higher priority than journal staleness
- GovernanceReporter.report() returns all required sections
- report() summary section reflects check result
- report() trust section includes store presence and active_key_id
- report() reconciliation section reflects gate file
- report() audit section reflects chain status
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.policy import breakglass as breakglass_module
from wpgovern.policy import approval as approval_module
from wpgovern.policy.breakglass import BreakglassService
from wpgovern.status.checker import GovernanceChecker
from wpgovern.status.reporter import GovernanceReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config(root: Path, *, review_max_age_days: int | None = None) -> WPGovernConfig:
    return WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
        review_max_age_days=review_max_age_days,
    )


@pytest.fixture()
def healthy_env(tmp_path: Path) -> tuple[WPGovernConfig, TrustService, SigningService]:
    """A fully healthy governance environment."""
    root = tmp_path / "wpg"
    config = _make_config(root)
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_release_key("release-a")
    trust.activate_release_key("release-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")
    signing = SigningService(config=config, trust_service=trust)

    # Write and sign a baseline and active pointer
    bp = root / "baselines" / "baseline-1.json"
    bp.parent.mkdir(parents=True, exist_ok=True)
    bp.write_text(json.dumps({"baseline_id": "baseline-1", "status": "active"}, indent=2) + "\n")
    signing.sign_file(bp)
    config.active_pointer.parent.mkdir(parents=True, exist_ok=True)
    config.active_pointer.write_text(
        json.dumps({
            "baseline_id": "baseline-1",
            "activated_at": "2026-01-01T00:00:00Z",
            "previous_baseline_id": None,
        }, indent=2) + "\n"
    )
    signing.sign_file(config.active_pointer)
    return config, trust, signing


# ---------------------------------------------------------------------------
# Exit code 0 — healthy
# ---------------------------------------------------------------------------


def test_check_returns_0_for_healthy_state(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 0
    assert result.reason == "ok"


# ---------------------------------------------------------------------------
# Exit code 51 — audit chain integrity (S-2)
# ---------------------------------------------------------------------------


def test_check_returns_51_for_tampered_audit_chain(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    logger = AuditLogger(config=config)
    logger.emit("baseline.create", "alice", "success")

    lines = config.audit_log.read_text().splitlines()
    record = json.loads(lines[0])
    record["outcome"] = "tampered"
    lines[0] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 51


def test_check_exit_51_is_distinct_from_50(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    """S-2: exit 51 (chain integrity) must not equal exit 50 (review overdue)."""
    config, _, _ = healthy_env
    logger = AuditLogger(config=config)
    logger.emit("baseline.create", "alice", "success")

    lines = config.audit_log.read_text().splitlines()
    record = json.loads(lines[0])
    record["outcome"] = "tampered"
    lines[0] = json.dumps(record)
    config.audit_log.write_text("\n".join(lines) + "\n")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 51
    assert result.exit_code != 50


def test_check_skips_audit_integrity_when_log_absent(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    """Fresh install with no audit log must not fire exit 51."""
    config, _, _ = healthy_env
    assert not config.audit_log.exists()
    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Exit code 33 — B4 event
# ---------------------------------------------------------------------------


def test_check_returns_33_for_unresolved_b4_event(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    event_path = config.root_dir / "state" / ".last_b4_event.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(
        json.dumps({"class": "ReadOnlyDuringRecoveryError"}) + "\n"
    )
    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 33


def test_check_ignores_resolved_b4_event(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    import os
    config, _, _ = healthy_env
    event_path = config.root_dir / "state" / ".last_b4_event.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    event_path.write_text(
        json.dumps({
            "class": "DiskFullError",
            "resolved_at": "2026-01-01T01:00:00Z",
        }) + "\n"
    )
    os.chmod(event_path, 0o600)  # I-B4-1 requires 0o600 mode
    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Exit code 50 — audit review overdue
# ---------------------------------------------------------------------------


def test_check_returns_50_when_review_overdue_no_checkpoint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "wpg"
    config = _make_config(root, review_max_age_days=7)
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")

    logger = AuditLogger(config=config)
    logger.emit("baseline.create", "alice", "success")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 50


def test_check_returns_0_when_review_current(
    tmp_path: Path,
) -> None:
    root = tmp_path / "wpg"
    config = _make_config(root, review_max_age_days=7)
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")

    logger = AuditLogger(config=config)
    # Emit a checkpoint record and its required signature companion
    # so I-AUD-1 doesn't fire when governance-check runs invariants.
    import uuid
    from wpgovern.core.signing import SigningService as SS
    signing = SS(config=config)
    checkpoint_id = f"cp-{uuid.uuid4().hex[:8]}"
    checkpoint_record = logger.emit(
        "audit.review.checkpoint", "operator", "success",
        {"reason": "periodic review", "checkpoint_id": checkpoint_id,
         "records_reviewed": 0, "review_status": "clean",
         "review_period_start": "2026-01-01T00:00:00Z",
         "review_period_end": "2026-01-01T00:01:00Z"},
    )
    sig = signing.sign_bytes(checkpoint_record.self_hash.encode(), domain="runtime")
    logger.emit(
        "audit.checkpoint.signature", "operator", "success",
        {"checkpoint_id": checkpoint_id,
         "checkpoint_seq": checkpoint_record.seq,
         "checkpoint_hash": checkpoint_record.self_hash,
         "checkpoint_signature": sig},
    )

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 0


def test_check_no_exit_50_when_review_max_age_not_configured(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    # No review_max_age_days → audit review check is skipped entirely
    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Exit code 20 — trust / active pointer
# ---------------------------------------------------------------------------


def test_check_returns_20_for_corrupt_trust_store(tmp_path: Path) -> None:
    root = tmp_path / "wpg"
    config = _make_config(root)
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")

    store_path = config.runtime_trust_store
    store_path.write_text("not-valid-json\n")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 20


def test_check_returns_20_for_corrupt_active_pointer(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    # Tamper the active pointer signature
    sig_path = config.active_pointer.with_name(
        config.active_pointer.name + ".sig.json"
    )
    sig = json.loads(sig_path.read_text())
    sig["value_b64"] = "dGFtcGVyZWQ="
    sig_path.write_text(json.dumps(sig, indent=2) + "\n")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 20


# ---------------------------------------------------------------------------
# Exit code 13 — journal trust
# ---------------------------------------------------------------------------


def test_check_returns_13_when_journal_key_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "wpg"
    config = _make_config(root)
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    # Deliberately do NOT create any journal key

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 13


# ---------------------------------------------------------------------------
# Exit code 10 — reconciliation required
# ---------------------------------------------------------------------------


def test_check_returns_10_when_reconciliation_required(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    gate = config.root_dir / "state" / "reconciliation" / "required"
    gate.parent.mkdir(parents=True, exist_ok=True)
    gate.write_text("recon-123\n")

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 10


# ---------------------------------------------------------------------------
# Exit code 11 — break-glass debt
# ---------------------------------------------------------------------------


def test_check_returns_11_for_pending_emergency_review(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, signing = healthy_env
    # Create a signed active pointer first
    bg = BreakglassService(config=config)
    monkeypatch.setattr(breakglass_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    monkeypatch.setattr(approval_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")
    approval_id = bg.approve("INC-1", "urgent patch", 30)
    bg.activate(approval_id)

    # Verify gate is set; now remove it so only the unreviewed emergency matters
    gate = config.root_dir / "state" / "reconciliation" / "required"
    if gate.exists():
        gate.unlink()

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 11
    assert "review_pending" in result.reason


# ---------------------------------------------------------------------------
# Exit code 12 — journal staleness enforcement
# ---------------------------------------------------------------------------


def test_check_returns_12_when_journal_staleness_exceeds_enforce_threshold(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
    tmp_path: Path,
) -> None:
    root = tmp_path / "wpg2"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
        journal_staleness_warn_seconds=1,
        journal_staleness_enforce_seconds=2,
    )
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")

    journal_dir = root / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    intent = journal_dir / "txn-old.intent"
    intent.write_text('{"txn_id":"txn-old"}\n')
    # Make it appear old
    old_time = time.time() - 100
    os.utime(intent, (old_time, old_time))

    result = GovernanceChecker(config=config).check()
    assert result.exit_code == 12


def test_reconciliation_takes_priority_over_journal_staleness(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
    tmp_path: Path,
) -> None:
    root = tmp_path / "wpg3"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
        journal_staleness_enforce_seconds=1,
    )
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")

    journal_dir = root / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    intent = journal_dir / "txn-stale.intent"
    intent.write_text('{"txn_id":"txn-stale"}\n')
    old_time = time.time() - 100
    os.utime(intent, (old_time, old_time))

    gate = root / "state" / "reconciliation" / "required"
    gate.parent.mkdir(parents=True, exist_ok=True)
    gate.write_text("recon-xyz\n")

    result = GovernanceChecker(config=config).check()
    # Reconciliation (10) beats journal staleness (12) in the check order
    assert result.exit_code == 10


# ---------------------------------------------------------------------------
# GovernanceReporter
# ---------------------------------------------------------------------------


def test_reporter_returns_dict_with_all_required_sections(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    report = GovernanceReporter(config=config).report()

    assert set(report.keys()) == {
        "summary", "trust", "active_state", "reconciliation", "emergency", "audit"
    }


def test_reporter_summary_section_reflects_exit_code(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    report = GovernanceReporter(config=config).report()

    assert report["summary"]["exit_code"] == 0
    assert report["summary"]["ok"] is True
    assert report["summary"]["reason"] == "ok"


def test_reporter_trust_section_shows_active_key(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    report = GovernanceReporter(config=config).report()

    runtime = report["trust"]["runtime"]
    assert runtime["store_present"] is True
    assert runtime["active_key_id"] == "runtime-a"
    assert runtime["status"] == "ok"


def test_reporter_reconciliation_section_reflects_gate_file(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    gate = config.root_dir / "state" / "reconciliation" / "required"
    gate.parent.mkdir(parents=True, exist_ok=True)
    gate.write_text("recon-abc\n")

    report = GovernanceReporter(config=config).report()
    assert report["reconciliation"]["required"] is True
    assert report["reconciliation"]["required_id"] == "recon-abc"


def test_reporter_audit_section_shows_no_log_when_absent(
    healthy_env: tuple[WPGovernConfig, TrustService, SigningService],
) -> None:
    config, _, _ = healthy_env
    report = GovernanceReporter(config=config).report()
    # No audit log written in healthy_env fixture
    assert report["audit"]["present"] is False
