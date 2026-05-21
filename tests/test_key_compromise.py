"""
Tests for wpgovern.core.key_compromise — KeyCompromiseService.

Coverage:
- Runtime key compromise revokes old key and activates replacement
- Trust store updated: compromised key revoked, replacement active
- Compromise re-signs active pointer and governance artifacts
- Compromise writes and signs forensic report
- Compromised key cannot equal replacement key
- Missing compromised key is rejected
- Already-revoked key is rejected
- Failed re-sign is recorded in report but does not abort recovery
- Release key compromise (no artifact re-sign)
- Audit record emitted when logger provided
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.audit.logger import AuditLogger
from wpgovern.config import WPGovernConfig
from wpgovern.core.key_compromise import KeyCompromiseError, KeyCompromiseService
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def env(tmp_path: Path) -> tuple[KeyCompromiseService, SigningService, WPGovernConfig]:
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
    kc = KeyCompromiseService(config=config)
    return kc, signing, config


def _write_and_sign(signing: SigningService, path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    signing.sign_file(path)


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Happy path: runtime key
# ---------------------------------------------------------------------------


def test_runtime_compromise_revokes_compromised_and_activates_replacement(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, signing, config = env
    result = kc.recover_runtime_key("runtime-a", "runtime-b", "test compromise")

    assert result.compromised_key_id == "runtime-a"
    assert result.replacement_key_id == "runtime-b"
    assert result.domain == "runtime"

    trust = TrustService(config=config)
    store = trust.get_runtime_store()
    keys = {e["key_id"]: e for e in store["keys"]}
    assert keys["runtime-a"]["status"] == "revoked"
    assert keys["runtime-b"]["status"] == "active"
    assert store["active_key_id"] == "runtime-b"


def test_runtime_compromise_resigns_active_pointer(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, signing, config = env
    _write_and_sign(
        signing,
        config.root_dir / "baselines" / "baseline-1.json",
        {"baseline_id": "baseline-1", "status": "active"},
    )
    _write_and_sign(
        signing,
        config.active_pointer,
        {
            "baseline_id": "baseline-1",
            "activated_at": "2026-01-01T00:00:00Z",
            "previous_baseline_id": None,
        },
    )

    kc.recover_runtime_key("runtime-a", "runtime-b", "test compromise")

    # Verify the active pointer with the NEW key
    new_signing = SigningService(config=config)
    new_signing.verify_active_pointer()


def test_runtime_compromise_writes_signed_forensic_report(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, signing, config = env
    result = kc.recover_runtime_key("runtime-a", "runtime-b", "test compromise")

    assert result.report_path.exists()
    payload = _read_json(result.report_path)
    assert payload["domain"] == "runtime"
    assert payload["compromised_key_id"] == "runtime-a"
    assert payload["replacement_key_id"] == "runtime-b"
    assert payload["status"] in ("completed", "completed_with_failures")

    # Report must be signed with the NEW key
    new_signing = SigningService(config=config)
    new_signing.verify_file(result.report_path)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_compromise_rejects_identical_key_ids(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, _, _ = env
    with pytest.raises(KeyCompromiseError, match="must differ"):
        kc.recover_runtime_key("runtime-a", "runtime-a", "test")


def test_compromise_rejects_missing_compromised_key(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, _, _ = env
    with pytest.raises(KeyCompromiseError, match="not found"):
        kc.recover_runtime_key("does-not-exist", "runtime-b", "test")


def test_compromise_rejects_already_revoked_key(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, _, config = env
    trust = TrustService(config=config)
    trust.generate_runtime_key("runtime-b")
    trust.activate_runtime_key("runtime-b")
    trust.revoke_runtime_key("runtime-a", "pre-revoked")

    with pytest.raises(KeyCompromiseError, match="already revoked"):
        kc.recover_runtime_key("runtime-a", "runtime-c", "test")


def test_compromise_rejects_empty_reason(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, _, _ = env
    with pytest.raises(KeyCompromiseError, match="cannot be empty"):
        kc.recover_runtime_key("runtime-a", "runtime-b", "   ")


# ---------------------------------------------------------------------------
# Partial failure
# ---------------------------------------------------------------------------


def test_failed_resign_recorded_in_report_but_recovery_completes(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kc, signing, config = env

    original_sign = signing.sign_runtime_artifact.__func__

    def failing_sign(self: SigningService, path: Path) -> Path:
        if "baseline" in path.name:
            raise RuntimeError("simulated sign failure")
        return original_sign(self, path)

    _write_and_sign(
        signing,
        config.root_dir / "baselines" / "baseline-1.json",
        {"baseline_id": "baseline-1", "status": "active"},
    )

    monkeypatch.setattr(SigningService, "sign_runtime_artifact", failing_sign)
    result = kc.recover_runtime_key("runtime-a", "runtime-b", "test")

    assert len(result.failed_artifacts) > 0
    payload = _read_json(result.report_path)
    assert payload["status"] == "completed_with_failures"
    assert len(payload["failed_artifacts"]) > 0


# ---------------------------------------------------------------------------
# Release domain
# ---------------------------------------------------------------------------


def test_release_key_compromise_revokes_and_activates_no_resign(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, _, config = env
    trust = TrustService(config=config)
    trust.generate_release_key("release-a")
    trust.activate_release_key("release-a")

    result = kc.recover_release_key("release-a", "release-b", "stolen key")

    assert result.domain == "release"
    # Release domain does not re-sign governance artifacts
    assert result.re_signed_artifacts == []
    store = trust.get_release_store()
    keys = {e["key_id"]: e for e in store["keys"]}
    assert keys["release-a"]["status"] == "revoked"
    assert keys["release-b"]["status"] == "active"


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_compromise_emits_audit_record_when_logger_provided(
    env: tuple[KeyCompromiseService, SigningService, WPGovernConfig],
) -> None:
    kc, _, config = env
    audit_logger = AuditLogger(config=config)
    actor = {"actor_id": "alice", "reason": "security incident", "change_ticket": None}

    kc.recover_runtime_key(
        "runtime-a", "runtime-b", "test",
        audit_logger=audit_logger, actor_context=actor,
    )

    lines = [l for l in config.audit_log.read_text().splitlines() if l.strip()]
    last = json.loads(lines[-1])
    assert last["event_type"] == "key-compromise-runtime"
    assert last["details"]["key_id"] == "runtime-a"


# ---------------------------------------------------------------------------
# external review integration + regression tests — event-name alignment
# ---------------------------------------------------------------------------


def test_key_compromise_alerts_fire_with_correct_event_name(
    env: tuple,
) -> None:
    """Integration test: key-compromise-runtime produces exactly one alert
    with the correct event_type through a memory sink. Pre-fix, the emitted
    name was 'key_compromise.runtime' (underscore-period), which does not
    match 'key-compromise-runtime' in BUILTIN_ALERT_TRIGGERS or the
    'key-compromise' prefix in BUILTIN_ALERT_PREFIXES. Zero alerts fired.
    This test locks the correct behaviour."""
    import json as _json
    from wpgovern.audit.alerter import AuditAlerter
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.config import WPGovernConfig

    kc, _, config = env
    alerts_captured: list[dict] = []

    class _CaptureSink:
        """In-memory alert sink for integration testing."""
        def deliver(self, payload: dict) -> None:
            alerts_captured.append(payload)

    class _CapturingAlerter(AuditAlerter):
        def maybe_alert(self, event_type, actor, outcome, details,
                        self_hash, timestamp) -> None:
            from wpgovern.audit.alerter import _should_alert, _build_alert_payload
            if _should_alert(event_type, self.extra_triggers):
                alerts_captured.append(_build_alert_payload(
                    event_type, actor, outcome, details, self_hash, timestamp
                ))

    # Patch alerter_from_config at the alerter module level.
    import wpgovern.audit.alerter as _alerter_mod
    orig = _alerter_mod.alerter_from_config

    def _patched(cfg):
        return _CapturingAlerter(
            sinks=[{"type": "none"}], extra_triggers=[]
        )

    _alerter_mod.alerter_from_config = _patched
    try:
        alert_cfg = WPGovernConfig(
            root_dir=config.root_dir,
            install_dir=config.install_dir,
            runtime_trust_store=config.runtime_trust_store,
            release_trust_store=config.release_trust_store,
            active_pointer=config.active_pointer,
            audit_log=config.audit_log,
            alert_sinks=({"type": "none"},),
        )
        audit_logger = AuditLogger(config=alert_cfg)
        actor = {"actor_id": "alice", "reason": "test", "change_ticket": None}

        kc.recover_runtime_key(
            "runtime-a", "runtime-b", "integration-test",
            audit_logger=audit_logger, actor_context=actor,
        )
    finally:
        _alerter_mod.alerter_from_config = orig

    # Exactly one key-compromise alert must have fired.
    compromise_alerts = [
        a for a in alerts_captured
        if a.get("event_type") == "key-compromise-runtime"
    ]
    assert len(compromise_alerts) == 1, (
        f"Expected 1 key-compromise-runtime alert, got {len(compromise_alerts)}. "
        f"All alerts captured: {[a.get('event_type') for a in alerts_captured]}"
    )


def test_key_compromise_event_appears_in_review_window_highlighted(
    env: tuple,
) -> None:
    """Integration test: after a runtime key compromise, the compromise
    event appears in review_window().highlighted. Pre-fix, the event name
    mismatch meant it never appeared — an auditor scanning highlights
    would not see the compromise."""
    from wpgovern.audit.logger import AuditLogger
    from wpgovern.audit.verifier import AuditVerifier

    kc, _, config = env
    audit_logger = AuditLogger(config=config)
    actor = {"actor_id": "alice", "reason": "test", "change_ticket": None}

    kc.recover_runtime_key(
        "runtime-a", "runtime-b", "highlight-test",
        audit_logger=audit_logger, actor_context=actor,
    )

    window = AuditVerifier(config=config).review_window()
    highlighted_types = {h["event_type"] for h in window.highlighted}
    assert "key-compromise-runtime" in highlighted_types, (
        f"key-compromise-runtime not in highlighted. "
        f"Highlighted types: {highlighted_types}"
    )


def test_r1_compromise_secures_trust_state_even_on_corrupt_audit_chain(
    env: tuple,
) -> None:
    """Regression for external review finding R1.

    Before the fix: intermediate audit_logger.emit() calls between trust
    mutations meant that a corrupt audit chain caused recovery to fail AFTER
    generate_key() but BEFORE activate_key() and revoke_key(). This left the
    compromised key still ACTIVE and the replacement key PREACTIVE.

    After the fix: all three trust mutations run first (uninterrupted), then
    emits are attempted best-effort. A corrupt audit chain produces no audit
    records but the trust state is correctly secured.

    This test MUST fail on v3-pre-fix code (where emits interleave with trust
    ops) and MUST pass on v4 code (where trust ops are batched first).
    """
    kc, _, config = env
    logger = AuditLogger(config=config)
    logger.emit("baseline.create", "alice", "success")

    # Corrupt the audit chain so all emit() calls will fail.
    config.audit_log.write_text("THIS IS NOT VALID JSON\n")

    actor = {"actor_id": "alice", "reason": "r1-regression", "change_ticket": None}

    # Compromise must succeed — trust state must be secured despite audit failure.
    result = kc.recover_runtime_key(
        "runtime-a", "runtime-b", "r1-regression-test",
        audit_logger=logger, actor_context=actor,
    )
    assert result is not None

    # THE CORE ASSERTION: trust state is correct regardless of audit health.
    from wpgovern.core.trust import TrustService
    trust = TrustService(paths=kc.paths)
    store = trust.load_store("runtime")
    statuses = {k.key_id: k.status for k in store.keys}

    assert statuses.get("runtime-a") == "revoked", (
        f"Compromised key runtime-a should be revoked, got: {statuses.get('runtime-a')}. "
        f"R1 regression: if audit emit fires between trust ops and the chain is corrupt, "
        f"the compromised key remains active."
    )
    assert statuses.get("runtime-b") == "active", (
        f"Replacement key runtime-b should be active, got: {statuses.get('runtime-b')}. "
        f"Full trust state: {statuses}"
    )
