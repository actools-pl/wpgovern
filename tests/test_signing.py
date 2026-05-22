"""
Tests for wpgovern.core.signing — SigningService, VALID_VERIFY_STATUSES.

Coverage:
- sign_file creates .sig.json sidecar with correct fields
- verify_file passes on valid signature
- verify_file raises IntegrityError when file modified after signing
- verify_file raises IntegrityError when key is revoked (fail-closed)
- verify_file raises IntegrityError when key is preactive (fail-closed)
- verify_file passes when key is retired_verify_only
- verify_file raises NotFoundError when artifact missing
- verify_file raises NotFoundError when sig file missing
- verify_file raises IntegrityError on unknown key_id
- VALID_VERIFY_STATUSES is exactly {"active", "retired_verify_only"}
- verify_active_pointer validates pointer and referenced baseline
- sign_release / verify_release use release domain
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.signing import VALID_VERIFY_STATUSES, SigningService
from wpgovern.core.trust import TrustService
from wpgovern.errors import IntegrityError, NotFoundError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def services(tmp_path: Path) -> tuple[TrustService, SigningService, WPGovernConfig]:
    root = tmp_path / "wpg"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
    )
    trust = TrustService(config=config)
    signing = SigningService(config=config, trust_service=trust)
    return trust, signing, config


def _setup_runtime(trust: TrustService) -> None:
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")
    trust.generate_journal_key("journal-a")
    trust.activate_journal_key("journal-a")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# VALID_VERIFY_STATUSES
# ---------------------------------------------------------------------------


def test_valid_verify_statuses_is_exactly_active_and_retired() -> None:
    assert VALID_VERIFY_STATUSES == frozenset({"active", "retired_verify_only"})


def test_valid_verify_statuses_does_not_include_preactive() -> None:
    assert "preactive" not in VALID_VERIFY_STATUSES


def test_valid_verify_statuses_does_not_include_revoked() -> None:
    assert "revoked" not in VALID_VERIFY_STATUSES


# ---------------------------------------------------------------------------
# sign_file / verify_file happy path
# ---------------------------------------------------------------------------


def test_sign_file_creates_sig_sidecar_with_correct_fields(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})

    sig_path = signing.sign_file(target)

    assert sig_path.exists()
    payload = json.loads(sig_path.read_text())
    assert payload["algorithm"] == "ed25519"
    assert payload["key_id"] == "runtime-a"
    assert isinstance(payload["value_b64"], str) and payload["value_b64"]


def test_verify_file_succeeds_on_valid_signature(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})
    signing.sign_file(target)
    signing.verify_file(target)  # must not raise


# ---------------------------------------------------------------------------
# verify_file failure cases
# ---------------------------------------------------------------------------


def test_verify_file_raises_on_modified_file(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"version": 1})
    signing.sign_file(target)
    _write_json(target, {"version": 2})  # tamper
    with pytest.raises(IntegrityError, match="verification failed"):
        signing.verify_file(target)


def test_verify_file_raises_when_key_is_revoked(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})
    signing.sign_file(target)

    trust.generate_runtime_key("runtime-b")
    trust.activate_runtime_key("runtime-b")
    trust.revoke_runtime_key("runtime-a", "compromised")

    with pytest.raises(IntegrityError, match="revoked"):
        signing.verify_file(target)


def test_verify_file_raises_when_key_is_preactive(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    """Fail-closed: preactive key status is not in VALID_VERIFY_STATUSES."""
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})
    signing.sign_file(target)

    # Downgrade the key status to preactive in the store
    store_path = config.runtime_trust_store
    payload = json.loads(store_path.read_text())
    for key in payload["keys"]:
        if key["key_id"] == "runtime-a":
            key["status"] = "preactive"
            key["usage"] = ["sign", "verify"]
    store_path.write_text(json.dumps(payload, indent=2) + "\n")

    with pytest.raises(IntegrityError, match="preactive"):
        signing.verify_file(target)


def test_verify_file_succeeds_for_retired_verify_only_key(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})
    signing.sign_file(target)

    # Activate a new key — runtime-a becomes retired_verify_only
    trust.generate_runtime_key("runtime-b")
    trust.activate_runtime_key("runtime-b")

    store = trust.get_runtime_store()
    key_a = next(e for e in store["keys"] if e["key_id"] == "runtime-a")
    assert key_a["status"] == "retired_verify_only"

    signing.verify_file(target)  # must still pass with retired key


def test_verify_file_raises_when_artifact_missing(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    _, signing, config = services
    target = config.root_dir / "baselines" / "missing.json"
    with pytest.raises(NotFoundError):
        signing.verify_file(target)


def test_verify_file_raises_when_signature_missing(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})
    with pytest.raises(NotFoundError, match="Signature file missing"):
        signing.verify_file(target)


def test_verify_file_raises_on_unknown_key_id(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    target = config.root_dir / "baselines" / "sample.json"
    _write_json(target, {"hello": "world"})
    sig_path = signing.sign_file(target)
    payload = json.loads(sig_path.read_text())
    payload["key_id"] = "no-such-key"
    sig_path.write_text(json.dumps(payload, indent=2) + "\n")
    with pytest.raises(IntegrityError, match="not registered"):
        signing.verify_file(target)


# ---------------------------------------------------------------------------
# verify_active_pointer
# ---------------------------------------------------------------------------


def test_verify_active_pointer_validates_signature_and_baseline(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    trust, signing, config = services
    _setup_runtime(trust)
    baseline = config.root_dir / "baselines" / "baseline-1.json"
    _write_json(baseline, {"baseline_id": "baseline-1", "status": "active"})
    _write_json(config.active_pointer, {"baseline_id": "baseline-1",
                                         "activated_at": "2026-01-01T00:00:00Z"})
    signing.sign_file(config.active_pointer)
    signing.verify_active_pointer()  # must not raise


# ---------------------------------------------------------------------------
# Release domain
# ---------------------------------------------------------------------------


def test_sign_and_verify_release_manifest(
    services: tuple[TrustService, SigningService, WPGovernConfig],
) -> None:
    import json, hashlib
    trust, signing, config = services
    trust.generate_release_key("release-a")
    trust.activate_release_key("release-a")
    dist_dir = config.root_dir / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    # Fix 4: sign_release now refuses a missing/empty manifest.
    # Provide a valid manifest with at least one artifact.
    artifact = dist_dir / "app.tar.gz"
    artifact.write_bytes(b"release content")
    manifest = dist_dir / "manifest.json"
    manifest.write_text(json.dumps({
        "version": "1.0.0",
        "artifacts": [
            {"path": "app.tar.gz",
             "sha256": hashlib.sha256(b"release content").hexdigest()},
        ],
    }))
    signing.sign_release(dist_dir=dist_dir)
    signing.verify_release(dist_dir=dist_dir)  # must not raise
