"""
Regression tests for findings confirmed by external review and external review.

Finding 1 — Baseline tamper-laundering blocked
Finding 2 — Timestamp-only ID collision resistance
Finding 3 — Reconciliation completion atomicity
Finding 4 — sign_release refuses missing/empty manifest
Finding 5 — Key-compromise event taxonomy normalized
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.baseline import BaselineService, BaselineError
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import ValidationError
from wpgovern.policy.reconciliation import ReconciliationService


@pytest.fixture()
def config(tmp_path: Path, monkeypatch) -> WPGovernConfig:
    import wpgovern.core.baseline as baseline_module
    monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, args: [])
    monkeypatch.setattr(BaselineService, "_wp_text", lambda self, args: "6.8.1")
    monkeypatch.setattr(baseline_module, "utc_now_iso", lambda: "2026-01-01T00:00:00Z")

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
    return cfg


# ---------------------------------------------------------------------------
# Finding 1: Baseline tamper-laundering blocked
# ---------------------------------------------------------------------------

def test_finding1_tampered_draft_blocked_at_submit(config: WPGovernConfig) -> None:
    """submit() must refuse a baseline whose content was tampered after create."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()

    bpath = config.root_dir / "baselines" / f"{b_id}.json"
    data = json.loads(bpath.read_text())
    data["plugins"] = ["evil-backdoor"]
    bpath.write_text(json.dumps(data))

    with pytest.raises((BaselineError, Exception), match="signature"):
        svc.submit(b_id)


def test_finding1_tampered_submitted_blocked_at_approve(config: WPGovernConfig) -> None:
    """approve() must refuse a baseline tampered after submit."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()
    svc.submit(b_id)

    bpath = config.root_dir / "baselines" / f"{b_id}.json"
    data = json.loads(bpath.read_text())
    data["plugins"] = ["evil-backdoor"]
    bpath.write_text(json.dumps(data))

    with pytest.raises((BaselineError, Exception)):
        svc.approve(b_id)


def test_finding1_clean_lifecycle_still_works(config: WPGovernConfig) -> None:
    """The happy path: create → submit → approve succeeds without tampering."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()
    svc.submit(b_id)
    svc.approve(b_id)

    bpath = config.root_dir / "baselines" / f"{b_id}.json"
    payload = json.loads(bpath.read_text())
    assert payload["status"] == "approved"


def test_finding1_load_unverified_for_diagnostics_available(
    config: WPGovernConfig,
) -> None:
    """load_unverified_for_diagnostics_only() exists and is explicitly named."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()
    # Even after tampering, the unsafe path can read it.
    bpath = config.root_dir / "baselines" / f"{b_id}.json"
    data = json.loads(bpath.read_text())
    data["plugins"] = ["anything"]
    bpath.write_text(json.dumps(data))
    record = svc.load_unverified_for_diagnostics_only(b_id)
    assert record.plugins == ["anything"]


# ---------------------------------------------------------------------------
# Finding 2: Timestamp-only ID collision resistance
# ---------------------------------------------------------------------------

def test_finding2_hundred_same_second_baseline_ids_are_unique(
    config: WPGovernConfig,
) -> None:
    """100 baseline IDs generated at the same (mocked) second are all unique."""
    from unittest import mock
    from wpgovern.utils import time as time_mod
    import wpgovern.core.baseline as baseline_mod

    ids = set()
    with mock.patch.object(
        baseline_mod, "utc_now_iso", return_value="2026-01-01T00:00:00Z"
    ):
        for _ in range(100):
            from wpgovern.core.baseline import _timestamped_id
            ids.add(_timestamped_id("baseline"))
    assert len(ids) == 100, f"Collision detected: only {len(ids)} unique IDs from 100"


def test_finding2_id_format_has_uuid_suffix(config: WPGovernConfig) -> None:
    """IDs now include a UUID4 hex suffix, not just a timestamp."""
    from wpgovern.core.baseline import _timestamped_id
    id1 = _timestamped_id("baseline")
    parts = id1.split("-")
    # Format: prefix-YYYYMMDDHHMMSS-hexsuffix
    assert len(parts) == 3
    assert len(parts[2]) == 8  # 8-char hex suffix
    # hex suffix is valid hex
    int(parts[2], 16)


# ---------------------------------------------------------------------------
# Finding 3: Reconciliation completion atomicity
# ---------------------------------------------------------------------------

def test_finding3_gate_mismatch_does_not_write_completed_record(
    tmp_path: Path,
) -> None:
    """complete() must NOT write a completed record when the gate points
    to a different reconciliation ID. Pre-fix, the record was written and
    signed BEFORE the gate was checked."""
    from wpgovern.policy.reconciliation import ReconciliationService, ReconciliationError
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

    svc = ReconciliationService(config=cfg)

    # Write a minimal reconciliation record.
    from wpgovern.paths import build_paths
    paths = build_paths(cfg)
    paths.state_reconciliation.mkdir(parents=True, exist_ok=True)
    rec_path = paths.state_reconciliation / "reconciliation-X.json"
    payload = {
        "reconciliation_id": "reconciliation-X",
        "status": "pending",
        "created_at": "2026-01-01T00:00:00Z",
        "emergency_id": "emergency-1",
        "review_id": "review-1",
        "completed_at": None,
    }
    rec_path.write_text(json.dumps(payload))
    signing = SigningService(config=cfg)
    signing.sign_runtime_artifact(rec_path)

    # Set the gate to a DIFFERENT ID.
    paths.reconciliation_required.parent.mkdir(parents=True, exist_ok=True)
    paths.reconciliation_required.write_text("reconciliation-Y")

    with pytest.raises(ReconciliationError, match="gate"):
        svc.complete("reconciliation-X")

    # The record must still be "pending" — not "completed".
    final = json.loads(rec_path.read_text())
    assert final["status"] == "pending", (
        "complete() wrote a completed record despite gate mismatch — "
        "regression for Finding 3"
    )


# ---------------------------------------------------------------------------
# Finding 4: sign_release refuses missing/empty manifest
# ---------------------------------------------------------------------------

def test_finding4_sign_release_refuses_missing_manifest(config: WPGovernConfig) -> None:
    """sign_release() must refuse when no manifest file exists."""
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValidationError, match="missing"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding4_sign_release_refuses_empty_manifest(config: WPGovernConfig) -> None:
    """sign_release() must refuse a manifest containing only {}."""
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "manifest.json").write_text("{}\n")
    with pytest.raises(ValidationError, match="empty"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding4_sign_release_refuses_manifest_without_artifacts(
    config: WPGovernConfig,
) -> None:
    """sign_release() must refuse a manifest with no artifacts list."""
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "manifest.json").write_text(
        json.dumps({"version": "1.0.0", "artifacts": []})
    )
    with pytest.raises(ValidationError, match="artifacts"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding4_sign_release_accepts_valid_manifest(config: WPGovernConfig) -> None:
    """sign_release() accepts a manifest with at least one artifact entry."""
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    artifact = dist_dir / "app.tar.gz"
    artifact.write_bytes(b"content")
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [
            {"path": "app.tar.gz",
             "sha256": hashlib.sha256(b"content").hexdigest()},
        ],
    }))
    sig_path = signing.sign_release(dist_dir=dist_dir)
    assert sig_path.exists()


# ---------------------------------------------------------------------------
# Finding 5: Key-compromise event taxonomy normalized
# ---------------------------------------------------------------------------

def test_finding5_key_compromise_intermediate_events_use_period_form() -> None:
    """The intermediate audit events during a key compromise must use the
    canonical period-form taxonomy (trust.key.generated, not trust.key_generate).
    Pre-fix, the underscore-form was used, breaking SIEM correlation rules
    that operate on trust.key.* patterns."""
    from wpgovern.audit.alerter import BUILTIN_ALERT_TRIGGERS
    # No underscore-form should be in the trigger set
    assert "trust.key_generate" not in BUILTIN_ALERT_TRIGGERS
    assert "trust.key_activate" not in BUILTIN_ALERT_TRIGGERS
    assert "trust.key_revoke" not in BUILTIN_ALERT_TRIGGERS


def test_finding5_known_emitted_table_has_no_underscore_forms() -> None:
    """KNOWN_EMITTED_EVENT_TYPES must not contain the legacy underscore forms."""
    from tests.test_alert_highlight_coverage import KNOWN_EMITTED_EVENT_TYPES
    assert "trust.key_generate" not in KNOWN_EMITTED_EVENT_TYPES
    assert "trust.key_activate" not in KNOWN_EMITTED_EVENT_TYPES
    assert "trust.key_revoke" not in KNOWN_EMITTED_EVENT_TYPES


# ---------------------------------------------------------------------------
# Structural test: no new timestamp-only IDs (external review recommendation)
# ---------------------------------------------------------------------------

def test_structural_no_new_timestamp_only_ids() -> None:
    """Scan wpgovern/ source for f-string ID constructions that use only
    a compact timestamp (no UUID suffix). A new timestamp-only ID is a
    collision risk and will fail this test.

    Pattern detected: f"<prefix>-{_utcnow_compact()}" or
                      f"<prefix>-{stamp}" where stamp is [:14] of ISO time.

    Known-safe forms (UUID-suffixed) are in _timestamped_id() and are
    not flagged because they include a uuid.uuid4() suffix.
    """
    import re
    from pathlib import Path

    # Patterns that indicate a timestamp-only ID
    TIMESTAMP_ONLY_PATTERNS = [
        re.compile(r'f"[a-z][a-z-]+-\{_utcnow_compact\(\)\}"'),
        re.compile(r'f"[a-z][a-z-]+-\{[a-z_]+_stamp\}"'),
        re.compile(r'f"[a-z][a-z-]+-\{stamp\}"'),
    ]

    wpgovern_root = Path(__file__).parent.parent / "wpgovern"
    violations: list[str] = []

    for py_file in sorted(wpgovern_root.rglob("*.py")):
        # Skip the _timestamped_id definition itself
        rel = str(py_file.relative_to(wpgovern_root.parent))
        source = py_file.read_text(encoding="utf-8")
        for line_no, line in enumerate(source.splitlines(), start=1):
            for pat in TIMESTAMP_ONLY_PATTERNS:
                if pat.search(line):
                    violations.append(f"{rel}:{line_no}: {line.strip()}")

    assert not violations, (
        "Source contains timestamp-only ID constructions (no UUID suffix):\n"
        + "\n".join(f"  {v}" for v in violations)
        + "\nUse _timestamped_id(prefix) which includes a uuid4 suffix."
    )


# ---------------------------------------------------------------------------
# Broader Finding 1 regression: sidecar deletion bypass blocked
# ---------------------------------------------------------------------------

def test_finding1_delete_sidecar_blocks_submit(config: WPGovernConfig) -> None:
    """Deleting the sidecar after create_draft must block submit.
    Pre-fix: if sig_path.exists() allowed bypass when sidecar deleted."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()
    sig_path = config.root_dir / "baselines" / f"{b_id}.json.sig.json"
    assert sig_path.exists(), "Sidecar must exist after create_draft"
    sig_path.unlink()
    with pytest.raises(BaselineError, match="signature"):
        svc.submit(b_id)


def test_finding1_delete_submitted_sidecar_blocks_approve(
    config: WPGovernConfig,
) -> None:
    """Deleting the submitted sidecar blocks approve."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()
    svc.submit(b_id)
    sig_path = config.root_dir / "baselines" / f"{b_id}.json.sig.json"
    sig_path.unlink()
    with pytest.raises(BaselineError, match="signature"):
        svc.approve(b_id)


# ---------------------------------------------------------------------------
# Finding 2 broader: approval and supersession IDs are collision-resistant
# ---------------------------------------------------------------------------

def test_finding2_approval_ids_are_unique_same_second(
    config: WPGovernConfig,
) -> None:
    """Two approvals generated at the same mocked second must have distinct IDs."""
    import wpgovern.core.baseline as baseline_mod
    from unittest import mock

    svc = BaselineService(config=config)
    b1 = svc.create_draft()
    svc.submit(b1)
    b2 = svc.create_draft()
    svc.submit(b2)

    with mock.patch.object(
        baseline_mod, "utc_now_iso", return_value="2026-01-01T00:00:00Z"
    ):
        a1 = svc.approve(b1)
        a2 = svc.approve(b2)

    assert a1 != a2, "Approval IDs must be distinct even within the same second"


def test_finding2_approval_ids_have_uuid_suffix(config: WPGovernConfig) -> None:
    """Approval IDs must include a UUID4 hex suffix."""
    svc = BaselineService(config=config)
    b_id = svc.create_draft()
    svc.submit(b_id)
    a_id = svc.approve(b_id)
    parts = a_id.split("-")
    # Format: approval-YYYYMMDDHHMMSS-hexsuffix
    assert len(parts) == 3, f"Expected 3 parts in approval ID, got: {a_id!r}"
    assert len(parts[2]) == 8
    int(parts[2], 16)


# ---------------------------------------------------------------------------
# Finding 6 broader: release signing verifies artifact hashes
# ---------------------------------------------------------------------------

def test_finding6_missing_artifact_file_refused(config: WPGovernConfig) -> None:
    """sign_release refuses a manifest referencing a non-existent artifact."""
    import hashlib
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [
            {"path": "missing.tar.gz",
             "sha256": "a" * 64},
        ],
    }))
    with pytest.raises(ValidationError, match="not found"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding6_path_traversal_refused(config: WPGovernConfig) -> None:
    """sign_release refuses manifest with path traversal in artifact path."""
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [
            {"path": "../../etc/passwd", "sha256": "a" * 64},
        ],
    }))
    with pytest.raises(ValidationError, match="traversal"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding6_bad_sha256_format_refused(config: WPGovernConfig) -> None:
    """sign_release refuses a manifest with a non-hex sha256 value."""
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    artifact = dist_dir / "app.tar.gz"
    artifact.write_bytes(b"content")
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [{"path": "app.tar.gz", "sha256": "not-a-real-hash"}],
    }))
    with pytest.raises(ValidationError, match="sha256"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding6_hash_mismatch_refused(config: WPGovernConfig) -> None:
    """sign_release refuses when the artifact sha256 does not match the file."""
    import hashlib
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    artifact = dist_dir / "app.tar.gz"
    artifact.write_bytes(b"real content")
    wrong_hash = hashlib.sha256(b"different content").hexdigest()
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [{"path": "app.tar.gz", "sha256": wrong_hash}],
    }))
    with pytest.raises(ValidationError, match="mismatch"):
        signing.sign_release(dist_dir=dist_dir)


def test_finding6_verify_release_catches_tampered_artifact(
    config: WPGovernConfig,
) -> None:
    """verify_release must catch artifact tampering after signing."""
    import hashlib
    from wpgovern.errors import IntegrityError, ValidationError
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    artifact = dist_dir / "app.tar.gz"
    artifact.write_bytes(b"original content")
    (dist_dir / "manifest.json").write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [
            {"path": "app.tar.gz",
             "sha256": hashlib.sha256(b"original content").hexdigest()},
        ],
    }))
    signing.sign_release(dist_dir=dist_dir)
    # Tamper the artifact after signing
    artifact.write_bytes(b"tampered content")
    # Shared validator runs after signature check; raises ValidationError on mismatch
    with pytest.raises((IntegrityError, ValidationError), match="mismatch"):
        signing.verify_release(dist_dir=dist_dir)


# ---------------------------------------------------------------------------
# Finding 3 extended: stage_delete is fail-closed and journaled
# ---------------------------------------------------------------------------

def test_finding3_complete_fails_if_gate_cannot_be_deleted(tmp_path: Path) -> None:
    """complete() must NOT return success when the gate file cannot be deleted.
    Pre-fix: except OSError: pass swallowed unlink failures silently."""
    import unittest.mock as mock
    from wpgovern.policy.reconciliation import ReconciliationService, ReconciliationError
    from wpgovern.paths import build_paths

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
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")

    svc = ReconciliationService(config=cfg)
    paths = build_paths(cfg)
    paths.state_reconciliation.mkdir(parents=True, exist_ok=True)

    rec_path = paths.state_reconciliation / "reconciliation-X.json"
    payload = {
        "reconciliation_id": "reconciliation-X",
        "status": "pending",
        "created_at": "2026-01-01T00:00:00Z",
        "emergency_id": None,
        "review_id": None,
        "completed_at": None,
        "source": "manual",
    }
    rec_path.write_text(json.dumps(payload))
    signing = SigningService(config=cfg)
    signing.sign_runtime_artifact(rec_path)

    # Set gate to matching ID
    paths.reconciliation_required.parent.mkdir(parents=True, exist_ok=True)
    paths.reconciliation_required.write_text("reconciliation-X")

    # Simulate gate unlink failure
    original_unlink = paths.reconciliation_required.unlink

    def fail_unlink(*args, **kwargs):
        raise OSError("Simulated unlink failure: permission denied")

    with mock.patch.object(
        type(paths.reconciliation_required),
        "unlink",
        fail_unlink,
    ):
        with pytest.raises((Exception,)):
            svc.complete("reconciliation-X")

    # Gate must still exist — complete() must not have claimed success
    assert paths.reconciliation_required.exists(), (
        "Gate was removed despite simulated unlink failure — "
        "or complete() succeeded while gate still existed"
    )


def test_finding3_postcondition_catches_gate_still_present(
    tmp_path: Path,
) -> None:
    """complete() postcondition check raises if gate exists after transaction."""
    from wpgovern.policy.reconciliation import ReconciliationService, ReconciliationError
    from wpgovern.paths import build_paths

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
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")

    paths = build_paths(cfg)
    svc = ReconciliationService(config=cfg)
    paths.state_reconciliation.mkdir(parents=True, exist_ok=True)

    rec_path = paths.state_reconciliation / "reconciliation-Y.json"
    payload = {
        "reconciliation_id": "reconciliation-Y",
        "status": "pending",
        "created_at": "2026-01-01T00:00:00Z",
        "emergency_id": None,
        "review_id": None,
        "completed_at": None,
        "source": "manual",
    }
    rec_path.write_text(json.dumps(payload))
    signing = SigningService(config=cfg)
    signing.sign_runtime_artifact(rec_path)

    # Set matching gate
    paths.reconciliation_required.parent.mkdir(parents=True, exist_ok=True)
    paths.reconciliation_required.write_text("reconciliation-Y")

    # Monkey-patch stage_delete to do nothing (gate not deleted)
    from wpgovern.utils import transaction as txn_mod
    original_stage_delete = txn_mod.AtomicTransaction.stage_delete

    def noop_stage_delete(self, target):
        pass  # Don't actually queue the delete

    txn_mod.AtomicTransaction.stage_delete = noop_stage_delete
    try:
        with pytest.raises((ReconciliationError, Exception), match="gate"):
            svc.complete("reconciliation-Y")
    finally:
        txn_mod.AtomicTransaction.stage_delete = original_stage_delete


# ---------------------------------------------------------------------------
# Finding 4 extended: verify_release is as strict as sign_release
# ---------------------------------------------------------------------------

def test_finding4_verify_release_rejects_empty_artifacts_even_if_signed(
    config: WPGovernConfig,
) -> None:
    """verify_release must reject a manifest with an empty artifacts list
    even if the manifest signature is valid. Pre-fix, verify_release used
    'continue' to skip malformed entries — a signed {} passed."""
    import hashlib
    from wpgovern.errors import ValidationError
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    # Manually write and sign a manifest with valid structure but empty artifacts
    # (bypassing sign_release's strict validator to simulate an old signed manifest)
    manifest = dist_dir / "manifest.json"
    manifest.write_text(json.dumps({"version": "1.0.0", "artifacts": []}))
    signing.sign_file(manifest, domain="release")
    with pytest.raises((ValidationError, Exception)):
        signing.verify_release(dist_dir=dist_dir)


def test_finding4_verify_release_rejects_path_traversal_even_if_signed(
    config: WPGovernConfig,
) -> None:
    """verify_release must reject path traversal in artifact paths."""
    from wpgovern.errors import ValidationError
    signing = SigningService(config=config)
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    manifest = dist_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [{"path": "../../etc/passwd", "sha256": "a" * 64}],
    }))
    signing.sign_file(manifest, domain="release")
    with pytest.raises((ValidationError, Exception)):
        signing.verify_release(dist_dir=dist_dir)


# ---------------------------------------------------------------------------
# audit-review --json flag is implemented, not a no-op
# ---------------------------------------------------------------------------

def test_audit_review_json_flag_produces_parseable_stdout(config: WPGovernConfig) -> None:
    """audit-review --json must produce JSON-only output (no human banner)."""
    from wpgovern.audit.logger import AuditLogger
    from typer.testing import CliRunner
    from wpgovern.cli import app
    import wpgovern.cli._common as _common
    import wpgovern.cli.commands.audit as _audit_cmd
    _common._config = lambda: config
    _audit_cmd._config = lambda: config

    logger = AuditLogger(config)
    logger.emit("baseline.create", "alice", "success")

    runner = CliRunner()
    result = runner.invoke(app, [
        "audit-review", "--json", "--auto-confirm",
        "--actor-id", "auditor", "--reason", "json-mode test",
    ])
    assert result.exit_code == 0, result.output
    # With --json, the output must be valid JSON (no human banner mixed in)
    out = json.loads(result.output)
    assert out["checkpoint_written"] is True
    assert "signed" in out
    # No "WPGovern Audit Review" banner in the output
    assert "WPGovern Audit Review" not in result.output
