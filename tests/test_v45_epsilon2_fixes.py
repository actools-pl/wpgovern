"""
Regression tests for Phase ε.2 fixes.

ε.2-1 — I-T-6 duplicate definition removed (verified by CI guard in ε.2-2)
ε.2-2 — CI guard: no duplicate invariant IDs (in test_ci_guards.py)
ε.2-3 — TrustService.revoke_key journaled through AtomicTransaction
"""

from __future__ import annotations

import json
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


# ---------------------------------------------------------------------------
# ε.2-1 — Structural: I-T-6 registered exactly once
# ---------------------------------------------------------------------------

def test_epsilon21_it6_registered_exactly_once() -> None:
    """I-T-6 must appear exactly once in the invariant registry.
    Pre-fix: the function was defined twice, both @invariant-decorated,
    so a single orphan produced 4 violation entries instead of 1.
    """
    from wpgovern.utils.invariants import _INVARIANT_REGISTRY
    it6_entries = [e for e in _INVARIANT_REGISTRY if e[0] == "I-T-6"]
    assert len(it6_entries) == 1, (
        f"I-T-6 must be registered exactly once. Found {len(it6_entries)} registrations."
    )


def test_epsilon21_orphan_produces_exactly_two_violations(env) -> None:
    """One orphan keypair produces exactly two violations: one for the .pem and
    one for the .pub — not four (which would indicate the duplicate was still present).
    """
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    import os
    orphan_pem = cfg.root_dir / "trust" / "runtime" / "private" / "orphan.pem"
    orphan_pub = cfg.root_dir / "trust" / "runtime" / "public" / "orphan.pub"
    orphan_pem.write_text("fake pem\n")
    os.chmod(orphan_pem, 0o600)
    orphan_pub.write_text("fake pub\n")

    violations = check_all_invariants(cfg)
    it6 = [v for v in violations if v.invariant_id == "I-T-6"]
    assert len(it6) == 2, (
        f"One orphan keypair must produce exactly 2 I-T-6 violations (one .pem, "
        f"one .pub). Got {len(it6)} — if 4, the duplicate definition was not removed."
    )


# ---------------------------------------------------------------------------
# ε.2-3 — revoke_key journaled atomicity
# ---------------------------------------------------------------------------

def test_epsilon23_revoke_key_writes_journal_record(env) -> None:
    """ε.2-3: revoke_key must journal through AtomicTransaction.

    Journaling is verified by patching _write_journal_intent and confirming
    it's called with the correct service_label. The .complete files are cleaned
    up immediately by cleanup_completed(), so we verify via the call trace.

    Pre-fix: revoke_key used _atomic_write_json directly (no journaling at all).
    Post-fix: AtomicTransaction with service_label="TrustService.revoke_..._key".
    """
    from wpgovern.utils.transaction import AtomicTransaction
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    intent_calls: list[str] = []
    orig_wji = AtomicTransaction._write_journal_intent

    def tracking_wji(self):
        intent_calls.append(self.service_label or "None")
        return orig_wji(self)

    with mock.patch.object(AtomicTransaction, "_write_journal_intent", tracking_wji):
        trust.revoke_key("runtime", "runtime-2", reason="test revocation")

    revoke_calls = [c for c in intent_calls if "revoke" in c]
    assert revoke_calls, (
        f"revoke_key must call _write_journal_intent with 'revoke' in service_label. "
        f"All intent calls: {intent_calls}"
    )


def test_epsilon23_revoke_active_key_still_refused(env) -> None:
    """ε.2-3: revoking the active key must remain forbidden."""
    cfg, trust = env
    with pytest.raises(PolicyError):
        trust.revoke_key("runtime", "runtime-1", reason="should be refused")

    store = trust.load_store("runtime")
    target = next(r for r in store.keys if r.key_id == "runtime-1")
    assert target.status != "revoked", "Active key must not be revoked"


def test_epsilon23_revoke_idempotent(env) -> None:
    """ε.2-3: revoking an already-revoked key is a no-op — preserves original reason."""
    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    trust.revoke_key("runtime", "runtime-2", reason="first revocation")
    target = trust.revoke_key("runtime", "runtime-2", reason="duplicate call")

    assert target.status == "revoked"
    assert target.revoke_reason == "first revocation", (
        "Idempotent revoke must return the original reason, not overwrite it"
    )


def test_epsilon23_kill_point_recovery(env) -> None:
    """ε.2-3: a kill between intent-write and complete-write must leave the
    system in a consistent state — either rolled back or completed, never hybrid.
    """
    from wpgovern.utils.transaction import AtomicTransaction
    from wpgovern.utils.recovery import RecoveryService

    cfg, trust = env
    trust.generate_runtime_key("runtime-2")

    real_commit = AtomicTransaction.commit

    def killing_commit(self, *args, **kwargs):
        raise RuntimeError("simulated kill mid-revoke")

    with mock.patch.object(AtomicTransaction, "commit", killing_commit):
        with pytest.raises(Exception):
            trust.revoke_key("runtime", "runtime-2", reason="will be killed")

    rs = RecoveryService(config=cfg)
    rs.recover_with_diagnostics()

    store = trust.load_store("runtime")
    r2 = next(r for r in store.keys if r.key_id == "runtime-2")
    assert r2.status in ("preactive", "revoked"), (
        f"After kill+recovery, r2 must be in a consistent state. "
        f"Got: {r2.status}"
    )
