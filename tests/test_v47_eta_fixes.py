"""
Regression tests for Phase η — final hardening sweep.

η-1 — I-T-7: .keygen-* staging residue detected as violation
η-2 — I-T-6 strengthened: unregistered symlinks flagged
η-3 — KeyCompromiseService._atomic_write_and_sign: ALL reports signed (no domain conditional)
η-4 — sign_bytes/verify_bytes: TemporaryDirectory pattern (no predictable temp paths)
η-5 — Algorithm field enforcement: non-ed25519 rejected in verify_file and verify_bytes
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.errors import IntegrityError


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
# η-1 — I-T-7: .keygen-* residue detection
# ---------------------------------------------------------------------------

def test_eta1_it7_catches_staging_residue(env) -> None:
    """I-T-7 must fire when a .keygen-* staging dir exists in a trust domain."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    # Plant residue in runtime domain
    residue = cfg.root_dir / "trust" / "runtime" / ".keygen-runtime-eta3-deadbeef"
    residue.mkdir()
    (residue / "runtime-2.pem").write_text("fake private key")
    os.chmod(residue / "runtime-2.pem", 0o600)

    violations = check_all_invariants(cfg)
    it7 = [v for v in violations if v.invariant_id == "I-T-7"]
    assert it7, "I-T-7 must fire on .keygen-* staging residue"
    assert any("keygen" in str(v.details).lower() or "runtime" in str(v.details).lower()
               for v in it7), (
        "I-T-7 violation must identify the staging directory"
    )


def test_eta1_it7_clean_state_passes(env) -> None:
    """I-T-7 must not fire when no staging residue exists."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    violations = check_all_invariants(cfg)
    it7 = [v for v in violations if v.invariant_id == "I-T-7"]
    assert not it7, f"I-T-7 false positive on clean state: {it7}"


def test_eta1_governance_check_surfaces_residue(env) -> None:
    """governance-check must report exit 21 when staging residue is present."""
    import json
    from wpgovern.core.signing import SigningService
    from wpgovern.status.checker import GovernanceChecker
    cfg, _ = env

    # Create an active pointer so the invariant step in checker runs
    # (checker skips invariants unless trust_dir + active_ptr both exist)
    signing = SigningService(config=cfg)
    baselines_dir = cfg.root_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    fake_baseline = baselines_dir / "baseline-residue-test.json"
    fake_baseline.write_text(json.dumps({
        "baseline_id": "baseline-residue-test", "status": "active",
        "wp_version": "6.5", "plugins": [], "themes": [],
    }))
    signing.sign_runtime_artifact(fake_baseline)
    active_ptr = cfg.root_dir / "state" / "active.json"
    active_ptr.parent.mkdir(parents=True, exist_ok=True)
    active_ptr.write_text(json.dumps({"baseline_id": "baseline-residue-test"}))
    signing.sign_runtime_artifact(active_ptr)

    residue = cfg.root_dir / "trust" / "journal" / ".keygen-journal-2-cafebabe"
    residue.mkdir()
    (residue / "journal-2.pem").write_text("fake key")
    os.chmod(residue / "journal-2.pem", 0o600)

    checker = GovernanceChecker(cfg)
    result = checker.check()
    assert result.exit_code == 21, (
        f"governance-check must surface staging residue as exit 21. "
        f"Got {result.exit_code}: {result.reason}"
    )


# ---------------------------------------------------------------------------
# η-2 — I-T-6 strengthened: unregistered symlinks flagged
# ---------------------------------------------------------------------------

def test_eta2_it6_catches_unregistered_symlink_in_private(env) -> None:
    """I-T-6 must flag an unregistered symlink in trust/<domain>/private/.
    Pre-fix: all symlinks in private/ were silently skipped.
    """
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    # Create a rogue symlink (not the managed active pointer)
    target = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem"
    rogue_link = cfg.root_dir / "trust" / "runtime" / "private" / "rogue.pem"
    rogue_link.symlink_to(target)

    violations = check_all_invariants(cfg)
    it6 = [v for v in violations if v.invariant_id == "I-T-6"]
    assert any("rogue" in str(v.details) for v in it6), (
        f"I-T-6 must flag unregistered symlink 'rogue.pem' in private/. Got: {it6}"
    )


def test_eta2_it6_catches_symlink_in_public(env) -> None:
    """I-T-6 must flag any symlink in trust/<domain>/public/ (none are managed)."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    existing_pub = cfg.root_dir / "trust" / "runtime" / "public" / "runtime-1.pub"
    rogue_link = cfg.root_dir / "trust" / "runtime" / "public" / "alias.pub"
    rogue_link.symlink_to(existing_pub)

    violations = check_all_invariants(cfg)
    it6 = [v for v in violations if v.invariant_id == "I-T-6"]
    assert any("alias" in str(v.details) or "public" in str(v.details) for v in it6), (
        f"I-T-6 must flag symlinks in public/. Got: {it6}"
    )


def test_eta2_it6_active_symlink_not_flagged(env) -> None:
    """I-T-6 must not flag the managed <domain>-active.pem symlink."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    active_link = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-active.pem"
    assert active_link.is_symlink(), "Test setup: active symlink should exist"

    violations = check_all_invariants(cfg)
    it6_on_active = [
        v for v in violations
        if v.invariant_id == "I-T-6" and "active" in str(v.details)
    ]
    assert not it6_on_active, (
        f"I-T-6 must not flag the managed active symlink: {it6_on_active}"
    )


# ---------------------------------------------------------------------------
# η-3 — All compromise reports signed regardless of domain
# ---------------------------------------------------------------------------

def test_eta3_release_compromise_report_is_signed(env) -> None:
    """Release-domain compromise reports must now be signed with the runtime key.

    Pre-fix: if domain == "runtime" conditional left release reports unsigned,
    making forensic evidence of release key compromise tamper-able.
    """
    from wpgovern.core.signing import SigningService
    from wpgovern.core.key_compromise import KeyCompromiseService

    cfg, trust = env
    signing = SigningService(config=cfg)
    kcs = KeyCompromiseService(config=cfg, signing=signing)

    result = kcs.recover_release_key(
        compromised_key_id="release-1",
        replacement_key_id="release-new-1",
        reason="η-3 test: release compromise must produce signed report",
    )

    report_path = Path(result.report_path)
    sig_path = Path(str(report_path) + ".sig.json")

    assert report_path.exists(), "Release compromise report JSON must exist"
    assert sig_path.exists(), (
        "Release compromise report must have a signature sidecar. "
        "Pre-fix: release reports were written unsigned."
    )

    # Signature must verify against the runtime key
    signing.verify_runtime_artifact(report_path)  # must not raise


def test_eta3_runtime_compromise_report_still_signed(env) -> None:
    """Runtime compromise reports must still be signed (regression guard)."""
    from wpgovern.core.signing import SigningService
    from wpgovern.core.key_compromise import KeyCompromiseService

    cfg, trust = env
    signing = SigningService(config=cfg)
    kcs = KeyCompromiseService(config=cfg, signing=signing)

    result = kcs.recover_runtime_key(
        compromised_key_id="runtime-1",
        replacement_key_id="runtime-new-1",
        reason="η-3 test: runtime compromise regression guard",
    )

    report_path = Path(result.report_path)
    sig_path = Path(str(report_path) + ".sig.json")
    assert sig_path.exists(), "Runtime compromise report must be signed"
    signing.verify_runtime_artifact(report_path)


# ---------------------------------------------------------------------------
# η-4 — No predictable temp paths in sign_bytes / verify_bytes
# ---------------------------------------------------------------------------

def test_eta4_sign_bytes_no_temp_files_in_os_tmpdir(env) -> None:
    """sign_bytes must not leave temp files in the OS temp directory.
    Pre-fix: NamedTemporaryFile + with_suffix created data.data and data.sig.raw
    at adjacent, predictable paths in /tmp.
    """
    import tempfile
    from wpgovern.core.signing import SigningService
    cfg, _ = env
    signing = SigningService(config=cfg)

    data = b"test sign_bytes temp path"

    # Capture what temp files exist before
    tmp_root = Path(tempfile.gettempdir())
    before = set(tmp_root.glob("*.sig.raw")) | set(tmp_root.glob("*.data"))

    sig = signing.sign_bytes(data, domain="runtime")
    signing.verify_bytes(data, sig, domain="runtime")

    after = set(tmp_root.glob("*.sig.raw")) | set(tmp_root.glob("*.data"))
    new_files = after - before
    assert not new_files, (
        f"sign_bytes/verify_bytes must not leave temp files in OS temp dir. "
        f"Found: {new_files}"
    )


# ---------------------------------------------------------------------------
# η-5 — Algorithm field enforcement
# ---------------------------------------------------------------------------

def test_eta5_verify_file_rejects_missing_algorithm(env) -> None:
    """verify_file must reject a signature with no algorithm field."""
    import json
    from wpgovern.core.signing import SigningService
    cfg, _ = env
    signing = SigningService(config=cfg)

    artifact = cfg.root_dir / "test-artifact.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('{"test": true}')
    signing.sign_file(artifact)

    # Remove algorithm field from sig
    sig_path = Path(str(artifact) + ".sig.json")
    payload = json.loads(sig_path.read_text())
    del payload["algorithm"]
    sig_path.write_text(json.dumps(payload))

    with pytest.raises(IntegrityError, match="algorithm"):
        signing.verify_file(artifact)


def test_eta5_verify_file_rejects_wrong_algorithm(env) -> None:
    """verify_file must reject a signature with algorithm != 'ed25519'."""
    import json
    from wpgovern.core.signing import SigningService
    cfg, _ = env
    signing = SigningService(config=cfg)

    artifact = cfg.root_dir / "test-artifact2.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('{"test": true}')
    signing.sign_file(artifact)

    sig_path = Path(str(artifact) + ".sig.json")
    payload = json.loads(sig_path.read_text())
    payload["algorithm"] = "rsa-sha256"
    sig_path.write_text(json.dumps(payload))

    with pytest.raises(IntegrityError, match="algorithm.*not supported|not supported.*algorithm"):
        signing.verify_file(artifact)


def test_eta5_verify_bytes_rejects_missing_algorithm(env) -> None:
    """verify_bytes must reject a signature dict with no algorithm field."""
    from wpgovern.core.signing import SigningService
    cfg, _ = env
    signing = SigningService(config=cfg)

    data = b"test algorithm enforcement"
    sig = signing.sign_bytes(data, domain="runtime")
    del sig["algorithm"]

    with pytest.raises(IntegrityError, match="algorithm"):
        signing.verify_bytes(data, sig, domain="runtime")


def test_eta5_verify_bytes_rejects_wrong_algorithm(env) -> None:
    """verify_bytes must reject algorithm != 'ed25519'."""
    from wpgovern.core.signing import SigningService
    cfg, _ = env
    signing = SigningService(config=cfg)

    data = b"test algorithm enforcement 2"
    sig = signing.sign_bytes(data, domain="runtime")
    sig["algorithm"] = "hmac-sha256"

    with pytest.raises(IntegrityError, match="algorithm"):
        signing.verify_bytes(data, sig, domain="runtime")


def test_eta5_correct_algorithm_passes(env) -> None:
    """verify_file and verify_bytes must accept 'ed25519' normally."""
    from wpgovern.core.signing import SigningService
    cfg, _ = env
    signing = SigningService(config=cfg)

    # verify_file
    artifact = cfg.root_dir / "test-algo-ok.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('{"test": true}')
    signing.sign_file(artifact)
    signing.verify_file(artifact)  # must not raise

    # verify_bytes
    data = b"test correct algorithm"
    sig = signing.sign_bytes(data, domain="runtime")
    signing.verify_bytes(data, sig, domain="runtime")  # must not raise
