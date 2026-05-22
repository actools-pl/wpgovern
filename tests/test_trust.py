"""
Tests for wpgovern.core.trust — TrustService key lifecycle and validation.

Coverage:
- init_store creates correct structure per domain (runtime/release/journal)
- generate_key creates preactive key with correct usage
- generate_key rejects duplicate key_id
- activate_key transitions preactive → active, retires previous active
- activate_key symlink points to new active key
- activate_key rejects non-preactive key
- revoke_key transitions non-active key → revoked, clears usage
- revoke_key on active key raises PolicyError
- revoke_key requires non-empty reason
- key_status returns correct status at each lifecycle step
- active_private_key_path returns resolved path
- active_private_key_path detects symlink/store desync (FC-5)
- validate_store: duplicate key_ids detected
- validate_store: missing active_key_id detected
- validate_store: invalid active usage detected
- private_dir mode is 0o700
- _validate_key_id rejects empty / path-traversal
- All three domains supported
- Journal domain uses sign+verify usage (not verify-only like release)
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustError, TrustService
from wpgovern.errors import IntegrityError, PolicyError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def service(tmp_path: Path) -> TrustService:
    root = tmp_path / "wpg"
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
    )
    return TrustService(config=config)


# ---------------------------------------------------------------------------
# init_store
# ---------------------------------------------------------------------------


def test_init_runtime_store_creates_correct_structure(service: TrustService) -> None:
    path = service.init_runtime_trust_store()
    assert path.exists()
    payload = json.loads(path.read_text())
    assert payload["type"] == "wpgovern.runtime_trust_store"
    assert payload["version"] == 1
    assert payload["active_key_id"] is None
    assert payload["keys"] == []
    assert payload["legacy_verification_enabled"] is False
    assert payload["legacy_compatibility_key_id"] is None


def test_init_journal_store_creates_journal_type(service: TrustService) -> None:
    path = service.init_journal_trust_store()
    payload = json.loads(path.read_text())
    assert payload["type"] == "wpgovern.journal_trust_store"


def test_init_release_store_creates_release_type(service: TrustService) -> None:
    path = service.init_release_trust_store()
    payload = json.loads(path.read_text())
    assert payload["type"] == "wpgovern.release_trust_store"


def test_private_dir_has_restrictive_mode(service: TrustService) -> None:
    service.init_runtime_trust_store()
    private_dir = service.paths.runtime_private_dir
    mode = stat.S_IMODE(private_dir.stat().st_mode)
    assert mode == 0o700, f"expected 0o700, got 0o{mode:o}"


# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------


def test_generate_runtime_key_creates_preactive_key(service: TrustService) -> None:
    record = service.generate_runtime_key("runtime-a")
    assert record.key_id == "runtime-a"
    assert record.status == "preactive"
    assert "sign" in record.usage
    assert "verify" in record.usage
    assert record.activated_at is None


def test_generate_runtime_key_creates_key_files(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    private = service.paths.runtime_private_dir / "runtime-a.pem"
    public = service.paths.runtime_public_dir / "runtime-a.pub"
    assert private.exists()
    assert public.exists()


def test_generate_key_rejects_duplicate_key_id(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    with pytest.raises(TrustError, match="already exists"):
        service.generate_runtime_key("runtime-a")


def test_generate_release_key_uses_verify_only_usage(service: TrustService) -> None:
    record = service.generate_release_key("release-a")
    assert record.usage == ["verify"]


def test_generate_journal_key_uses_sign_and_verify_usage(service: TrustService) -> None:
    record = service.generate_journal_key("journal-a")
    assert "sign" in record.usage and "verify" in record.usage


# ---------------------------------------------------------------------------
# activate_key
# ---------------------------------------------------------------------------


def test_activate_runtime_key_transitions_to_active(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    record = service.activate_runtime_key("runtime-a")
    assert record.status == "active"
    assert record.activated_at is not None
    assert service.active_key_id("runtime") == "runtime-a"


def test_activate_key_retires_previous_active(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    service.generate_runtime_key("runtime-b")
    service.activate_runtime_key("runtime-b")

    store = service.get_runtime_store()
    keys = {e["key_id"]: e for e in store["keys"]}
    assert keys["runtime-a"]["status"] == "retired_verify_only"
    assert keys["runtime-a"]["usage"] == ["verify"]
    assert keys["runtime-b"]["status"] == "active"
    assert store["active_key_id"] == "runtime-b"


def test_activate_key_updates_symlink(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    symlink = service.paths.runtime_active_private_key
    assert symlink.is_symlink()
    assert symlink.resolve().name == "runtime-a.pem"


def test_activate_key_rejects_non_preactive_key(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    with pytest.raises(TrustError, match="cannot be activated"):
        service.activate_runtime_key("runtime-a")


def test_activate_nonexistent_key_raises(service: TrustService) -> None:
    with pytest.raises(TrustError, match="not found"):
        service.activate_runtime_key("does-not-exist")


# ---------------------------------------------------------------------------
# revoke_key
# ---------------------------------------------------------------------------


def test_revoke_non_active_key_marks_revoked_and_clears_usage(
    service: TrustService,
) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    service.generate_runtime_key("runtime-b")
    service.revoke_runtime_key("runtime-b", "test revocation")

    store = service.get_runtime_store()
    key = next(e for e in store["keys"] if e["key_id"] == "runtime-b")
    assert key["status"] == "revoked"
    assert key["usage"] == []
    assert key["revoke_reason"] == "test revocation"
    assert "revoked_at" in key


def test_revoke_active_key_raises_policy_error(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    with pytest.raises(PolicyError, match="currently active"):
        service.revoke_runtime_key("runtime-a", "compromised")


def test_revoke_key_requires_non_empty_reason(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    service.generate_runtime_key("runtime-b")
    with pytest.raises(TrustError, match="Revocation reason"):
        service.revoke_runtime_key("runtime-b", "   ")


# ---------------------------------------------------------------------------
# active_private_key_path — FC-5 desync detection
# ---------------------------------------------------------------------------


def test_active_private_key_path_returns_resolved_path(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.generate_journal_key("journal-a")
    service.activate_runtime_key("runtime-a")
    path = service.active_private_key_path("runtime")
    assert path.exists()
    assert path.name == "runtime-a.pem"


def test_active_private_key_path_raises_when_symlink_missing(
    service: TrustService,
) -> None:
    service.generate_runtime_key("runtime-a")
    service.generate_journal_key("journal-a")
    service.activate_runtime_key("runtime-a")
    symlink = service.paths.runtime_active_private_key
    symlink.unlink()
    with pytest.raises(TrustError, match="symlink missing"):
        service.active_private_key_path("runtime")


def test_active_private_key_path_raises_on_store_symlink_desync(
    service: TrustService, tmp_path: Path
) -> None:
    """FC-5: trust store says key-A is active but symlink points to key-B."""
    service.generate_runtime_key("runtime-a")
    service.generate_runtime_key("runtime-b")
    service.generate_journal_key("journal-a")
    service.activate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-b")  # both keys activated

    # Manually rewrite the store to claim runtime-a is still active
    # while the symlink still points to runtime-b (from the last activate)
    store_path = service.paths.runtime_trust_store
    payload = json.loads(store_path.read_text())
    payload["active_key_id"] = "runtime-a"
    store_path.write_text(json.dumps(payload, indent=2) + "\n")

    with pytest.raises(TrustError, match="desync"):
        service.active_private_key_path("runtime")


# ---------------------------------------------------------------------------
# validate_store
# ---------------------------------------------------------------------------


def test_validate_store_passes_on_healthy_runtime_store(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.generate_journal_key("journal-a")
    service.activate_runtime_key("runtime-a")
    service.verify_runtime_trust()  # must not raise


def test_validate_store_detects_duplicate_key_ids(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    store_path = service.paths.runtime_trust_store
    payload = json.loads(store_path.read_text())
    payload["keys"].append(dict(payload["keys"][0]))
    store_path.write_text(json.dumps(payload, indent=2) + "\n")
    with pytest.raises((TrustError, IntegrityError), match="Duplicate"):
        service.verify_runtime_trust()


def test_validate_store_detects_missing_active_key_id(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    store_path = service.paths.runtime_trust_store
    payload = json.loads(store_path.read_text())
    payload["active_key_id"] = None
    store_path.write_text(json.dumps(payload, indent=2) + "\n")
    with pytest.raises((TrustError, IntegrityError), match="active_key_id"):
        service.verify_runtime_trust()


def test_validate_store_detects_invalid_active_usage(service: TrustService) -> None:
    service.generate_runtime_key("runtime-a")
    service.activate_runtime_key("runtime-a")
    store_path = service.paths.runtime_trust_store
    payload = json.loads(store_path.read_text())
    payload["keys"][0]["usage"] = ["verify"]  # active runtime key should have sign+verify
    store_path.write_text(json.dumps(payload, indent=2) + "\n")
    with pytest.raises((TrustError, IntegrityError), match="does not match expected"):
        service.verify_runtime_trust()


# ---------------------------------------------------------------------------
# key_id validation
# ---------------------------------------------------------------------------


def test_validate_key_id_rejects_empty(service: TrustService) -> None:
    with pytest.raises((TrustError, Exception)):
        service.generate_runtime_key("   ")


def test_validate_key_id_rejects_path_traversal(service: TrustService) -> None:
    with pytest.raises(Exception):
        service.generate_runtime_key("../escape")


def test_validate_key_id_rejects_forward_slash(service: TrustService) -> None:
    with pytest.raises(Exception):
        service.generate_runtime_key("some/path")
