"""
H.0 test suite — config-file hashing and cli profile alignment.

H.0-A: BaselineService.create_draft() captures SHA-256 hashes of four config
       files; governance-check verifies hashes against active baseline.
H.0-B: BaselineService._docker_wp changed from 'docker compose exec -T php wp'
       to 'docker compose run --rm -T cli wp' (cli profile-gated service).

Three input shapes per discipline as required by CODING_AGENT_REFERENCE.md.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.baseline import (
    BaselineError,
    BaselineRecord,
    BaselineService,
    CONFIG_FILE_PATHS,
    _compute_config_file_hashes,
    _sha256_hex,
    _validate_config_file_hashes,
    _validate_relative_path,
)
from wpgovern.status.checker import GovernanceChecker
from wpgovern.utils.invariants import check_all_invariants


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_config_files(install_dir: Path, content: dict[str, bytes] | None = None) -> dict[str, str]:
    """Create the four config files and return their expected sha256 digests."""
    install_dir.mkdir(parents=True, exist_ok=True)
    default_content: dict[str, bytes] = {
        "docker-compose.yml": b"version: '3.8'\nservices: {}\n",
        "Caddyfile":          b"example.com { respond 200 }\n",
        "my.cnf":             b"[mysqld]\ninnodb_buffer_pool_size = 512M\n",
        "wp-config.php":      b"<?php define('DB_NAME', 'wordpress');\n",
    }
    if content:
        default_content.update(content)
    hashes: dict[str, str] = {}
    for rel_path in CONFIG_FILE_PATHS:
        data = default_content.get(rel_path, b"default content for " + rel_path.encode())
        (install_dir / rel_path).write_bytes(data)
        hashes[rel_path] = _sha256_hex(data)
    return hashes


def _build_config(tmp_path: Path) -> WPGovernConfig:
    """Build a WPGovernConfig with install_dir under tmp_path."""
    root = tmp_path / "root"
    install = tmp_path / "install"
    return WPGovernConfig(
        root_dir=root,
        install_dir=install,
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )


def _bootstrap_trust(cfg: WPGovernConfig):
    """Set up trust + signing service for tests that call create_draft."""
    from wpgovern.core.trust import TrustService
    from wpgovern.core.signing import SigningService
    trust = TrustService(config=cfg)
    trust.generate_runtime_key("r1")
    trust.activate_runtime_key("r1")
    trust.generate_journal_key("j1")
    trust.activate_journal_key("j1")
    return SigningService(config=cfg)


def _make_active_baseline_on_disk(
    cfg: WPGovernConfig,
    fake_hashes: dict[str, str] | None = None,
    include_hashes: bool = True,
) -> dict[str, str]:
    """Write a minimal active baseline + active pointer to disk.

    Returns the hash dict that was written (or {} if not included).
    """
    if fake_hashes is None and include_hashes:
        fake_hashes = {
            rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS
        }

    baselines_dir = cfg.root_dir / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    bid = "baseline-h0-test"
    payload: dict[str, Any] = {
        "baseline_id": bid,
        "created_at": "2026-01-01T00:00:00Z",
        "status": "active",
        "wp_version": "6.5",
        "plugins": [],
        "themes": [],
    }
    if include_hashes and fake_hashes:
        payload["config_file_hashes"] = fake_hashes

    (baselines_dir / f"{bid}.json").write_text(json.dumps(payload), encoding="utf-8")

    (cfg.root_dir / "state").mkdir(parents=True, exist_ok=True)
    (cfg.root_dir / "state" / "active.json").write_text(
        json.dumps({"baseline_id": bid}), encoding="utf-8"
    )
    return fake_hashes or {}


# ===========================================================================
# H.0-A — create_draft() config-file hashing tests
# ===========================================================================

class TestCreateDraftHashesConfigFiles:
    """Named: four files present → hashes captured.
    Adjacent: one file missing → BaselineError.
    Adversarial: install_dir points at non-existent directory → clear error.
    """

    def test_create_draft_hashes_all_four_config_files(self, tmp_path, monkeypatch):
        """Named: all four files present; create_draft captures SHA-256 hashes."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        expected = _make_config_files(cfg.install_dir)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        record = svc.load(str(bid))

        assert record.config_file_hashes is not None
        assert set(record.config_file_hashes.keys()) == set(CONFIG_FILE_PATHS)
        for rel in CONFIG_FILE_PATHS:
            assert record.config_file_hashes[rel] == expected[rel], (
                f"Hash mismatch for {rel}"
            )

    def test_create_draft_fails_closed_when_config_file_missing(self, tmp_path, monkeypatch):
        """Adjacent: one config file missing → BaselineError (fail-closed)."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        # Create only 3 of the 4 files
        for rel in list(CONFIG_FILE_PATHS)[:-1]:
            (cfg.install_dir / rel).write_bytes(b"content")

        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        with pytest.raises(BaselineError, match="missing"):
            svc.create_draft()

    def test_create_draft_fails_when_install_dir_nonexistent(self, tmp_path, monkeypatch):
        """Adversarial: install_dir does not exist → clear error before transaction."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = WPGovernConfig(
            root_dir=tmp_path / "root",
            install_dir=tmp_path / "no-such-dir",
            runtime_trust_store=tmp_path / "root/trust/runtime/public/trusted-runtime-keys.json",
            release_trust_store=tmp_path / "root/trust/release/public/trusted-release-keys.json",
            active_pointer=tmp_path / "root/state/active.json",
            audit_log=tmp_path / "root/audit/audit.log",
            alert_sinks=({"type": "none"},),
        )
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        with pytest.raises(BaselineError, match="does not exist|missing"):
            svc.create_draft()


class TestCreateDraftHashChanges:
    """Named: file modified → different hash in second baseline.
    Adjacent: file unchanged → identical hash.
    Adversarial: file replaced by directory → BaselineError at create time.
    """

    def test_hash_changes_when_file_changes(self, tmp_path, monkeypatch):
        """Named: file modified between create_draft calls; hash differs."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid1 = svc.create_draft()
        (cfg.install_dir / "wp-config.php").write_bytes(b"<?php // modified\n")
        bid2 = svc.create_draft()

        r1 = svc.load(str(bid1))
        r2 = svc.load(str(bid2))
        assert r1.config_file_hashes["wp-config.php"] != r2.config_file_hashes["wp-config.php"]

    def test_hash_unchanged_when_file_unchanged(self, tmp_path, monkeypatch):
        """Adjacent: identical files → identical hashes across two baselines."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid1 = svc.create_draft()
        bid2 = svc.create_draft()
        r1 = svc.load(str(bid1))
        r2 = svc.load(str(bid2))
        assert r1.config_file_hashes == r2.config_file_hashes

    def test_directory_in_place_of_config_file_raises(self, tmp_path, monkeypatch):
        """Adversarial: config file path is a directory → BaselineError (not a file)."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)
        # Replace one file with a directory
        target = cfg.install_dir / "my.cnf"
        target.unlink()
        target.mkdir()

        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        with pytest.raises(BaselineError, match="not a regular file|missing"):
            svc.create_draft()


class TestCreateDraftInstallDir:
    """Named: custom install_dir honored.
    Adjacent: default install_dir used when not overridden.
    Adversarial: config_file_hashes included in signed payload.
    """

    def test_uses_install_dir_from_config(self, tmp_path, monkeypatch):
        """Named: custom install_dir is used to resolve config file paths."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        custom_install = tmp_path / "custom_install"
        cfg = WPGovernConfig(
            root_dir=tmp_path / "root",
            install_dir=custom_install,
            runtime_trust_store=tmp_path / "root/trust/runtime/public/trusted-runtime-keys.json",
            release_trust_store=tmp_path / "root/trust/release/public/trusted-release-keys.json",
            active_pointer=tmp_path / "root/state/active.json",
            audit_log=tmp_path / "root/audit/audit.log",
            alert_sinks=({"type": "none"},),
        )
        expected = _make_config_files(custom_install)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        record = svc.load(str(bid))
        assert record.config_file_hashes == expected

    def test_config_file_hashes_included_in_json_payload(self, tmp_path, monkeypatch):
        """Adjacent: the signed JSON on disk contains config_file_hashes."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        raw = json.loads(
            (cfg.root_dir / "baselines" / f"{bid}.json").read_text(encoding="utf-8")
        )
        assert "config_file_hashes" in raw
        assert isinstance(raw["config_file_hashes"], dict)
        assert len(raw["config_file_hashes"]) == 4

    def test_all_hash_values_have_sha256_prefix(self, tmp_path, monkeypatch):
        """Adversarial: all hash values must match sha256:<64 hex chars>."""
        import wpgovern.core.baseline as bmod
        import re
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        record = svc.load(str(bid))
        pat = re.compile(r'^sha256:[0-9a-f]{64}$')
        for k, v in record.config_file_hashes.items():
            assert pat.match(v), f"Hash for {k!r} does not match pattern: {v!r}"


# ===========================================================================
# H.0-A — governance-check hash verification (via _evaluate_config_file_hashes)
# Tested directly on the evaluation method to avoid requiring a full trust stack.
# End-to-end (exit 0 through real check()) is covered by TestGovernanceCheckE2E.
# ===========================================================================

class TestGovernanceCheckHashes:
    """Named: hashes match → returns None (no issue).
    Adjacent: legacy baseline (no hashes) → returns None.
    Adversarial: file replaced by directory → exit 53.
    """

    def test_passes_when_hashes_match(self, tmp_path):
        """Named: all four files on disk match baseline → None (clean)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel, digest in fake_hashes.items():
            (cfg.install_dir / rel).write_bytes(rel.encode())

        checker = GovernanceChecker(cfg)
        active_baseline = {"config_file_hashes": fake_hashes}
        result = checker._evaluate_config_file_hashes(active_baseline)
        assert result is None, f"Expected None (clean), got {result}"

    def test_passes_with_legacy_baseline_no_hashes(self, tmp_path):
        """Adjacent: baseline with no config_file_hashes → None (no check performed)."""
        cfg = _build_config(tmp_path)
        checker = GovernanceChecker(cfg)
        # Legacy baseline: no config_file_hashes key
        result = checker._evaluate_config_file_hashes(
            {"baseline_id": "old", "wp_version": "6.4"}
        )
        assert result is None

    def test_exit_53_when_file_replaced_by_directory(self, tmp_path):
        """Adversarial: config path is a directory → (53, reason with path)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        # Replace one with a directory
        target = "docker-compose.yml"
        (cfg.install_dir / target).unlink()
        (cfg.install_dir / target).mkdir()

        checker = GovernanceChecker(cfg)
        result = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert result is not None
        exit_code, reason = result
        assert exit_code == 53
        assert target in reason


class TestGovernanceCheckExit52:
    """Named: one file modified → (52, reason naming file).
    Adjacent: two files modified → (52, first in sorted order).
    Adversarial: file modified then reverted → None (clean).
    """

    def test_exit_52_on_hash_mismatch(self, tmp_path):
        """Named: one file content changed → (52, reason names the file)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        # Tamper wp-config.php
        (cfg.install_dir / "wp-config.php").write_bytes(b"tampered")

        checker = GovernanceChecker(cfg)
        result = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert result is not None
        exit_code, reason = result
        assert exit_code == 52
        assert "wp-config.php" in reason

    def test_exit_52_two_files_names_first_sorted(self, tmp_path):
        """Adjacent: two files modified → (52, names Caddyfile — first in sorted order)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        (cfg.install_dir / "Caddyfile").write_bytes(b"tampered caddyfile")
        (cfg.install_dir / "wp-config.php").write_bytes(b"tampered wp-config")

        checker = GovernanceChecker(cfg)
        result = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert result is not None
        exit_code, reason = result
        assert exit_code == 52
        # Sorted order: Caddyfile < docker-compose.yml < my.cnf < wp-config.php
        assert "Caddyfile" in reason

    def test_no_issue_after_revert(self, tmp_path):
        """Adversarial: file modified then reverted to original → None (clean)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        originals = {rel: rel.encode() for rel in CONFIG_FILE_PATHS}
        fake_hashes = {rel: _sha256_hex(data) for rel, data in originals.items()}
        for rel, data in originals.items():
            (cfg.install_dir / rel).write_bytes(data)

        # Tamper, then revert
        (cfg.install_dir / "my.cnf").write_bytes(b"tampered")
        checker = GovernanceChecker(cfg)
        r1 = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert r1 is not None and r1[0] == 52

        (cfg.install_dir / "my.cnf").write_bytes(originals["my.cnf"])
        r2 = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert r2 is None, f"After revert expected None (clean), got {r2}"


class TestGovernanceCheckExit53:
    """Named: file deleted → (53, reason names file).
    Adjacent: multiple files missing → (53, first sorted).
    Adversarial: file unreadable (dir) → (53).
    """

    def test_exit_53_on_missing_file(self, tmp_path):
        """Named: file deleted after baseline → (53, names file)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        (cfg.install_dir / "my.cnf").unlink()

        checker = GovernanceChecker(cfg)
        result = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert result is not None
        exit_code, reason = result
        assert exit_code == 53
        assert "my.cnf" in reason

    def test_exit_53_multiple_missing_names_first_sorted(self, tmp_path):
        """Adjacent: multiple missing → (53, names Caddyfile — first sorted)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        (cfg.install_dir / "Caddyfile").unlink()
        (cfg.install_dir / "wp-config.php").unlink()

        checker = GovernanceChecker(cfg)
        result = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert result is not None
        exit_code, reason = result
        assert exit_code == 53
        assert "Caddyfile" in reason

    def test_exit_53_when_file_is_directory(self, tmp_path):
        """Adversarial: path exists as directory (not file) → (53)."""
        cfg = _build_config(tmp_path)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        fake_hashes = {rel: _sha256_hex(rel.encode()) for rel in CONFIG_FILE_PATHS}
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        (cfg.install_dir / "docker-compose.yml").unlink()
        (cfg.install_dir / "docker-compose.yml").mkdir()

        checker = GovernanceChecker(cfg)
        result = checker._evaluate_config_file_hashes({"config_file_hashes": fake_hashes})
        assert result is not None
        assert result[0] == 53


# ===========================================================================
# H.0-A — Invariant tests (I-CFG-1, I-CFG-2)
# ===========================================================================

class TestICFG1:
    """Named: hashes match → no I-CFG-1 violations.
    Adjacent: no active baseline → no violations (invariant skips).
    Adversarial: hash mismatch → I-CFG-1 fires with path detail.
    """

    def test_i_cfg_1_passes_when_hashes_match(self, tmp_path):
        """Named: all files on disk match active baseline → no I-CFG-1 violations."""
        cfg = _build_config(tmp_path)
        fake_hashes = _make_active_baseline_on_disk(cfg)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        violations = check_all_invariants(cfg)
        cfg1 = [v for v in violations if v.invariant_id == "I-CFG-1"]
        assert not cfg1, f"I-CFG-1 false positive: {cfg1}"

    def test_i_cfg_1_skips_when_no_active_baseline(self, tmp_path):
        """Adjacent: no active baseline → no I-CFG-1 violations (nothing to check)."""
        cfg = _build_config(tmp_path)
        # Don't write any baseline or active pointer
        violations = check_all_invariants(cfg)
        cfg1 = [v for v in violations if v.invariant_id == "I-CFG-1"]
        assert not cfg1

    def test_i_cfg_1_fails_when_hash_diverges(self, tmp_path):
        """Adversarial: one file modified → I-CFG-1 violation naming the path."""
        cfg = _build_config(tmp_path)
        fake_hashes = _make_active_baseline_on_disk(cfg)
        cfg.install_dir.mkdir(parents=True, exist_ok=True)
        for rel in fake_hashes:
            (cfg.install_dir / rel).write_bytes(rel.encode())

        # Tamper
        (cfg.install_dir / "wp-config.php").write_bytes(b"tampered")

        violations = check_all_invariants(cfg)
        cfg1 = [v for v in violations if v.invariant_id == "I-CFG-1"]
        assert cfg1, "I-CFG-1 must fire on hash mismatch"
        assert any("wp-config.php" in str(v.details) for v in cfg1)


class TestICFG2:
    """Named: clean relative paths accepted.
    Adjacent: absolute path key → I-CFG-2 violation.
    Adversarial: path-traversal key → I-CFG-2 violation.
    """

    def test_i_cfg_2_accepts_clean_relative_paths(self, tmp_path):
        """Named: canonical CONFIG_FILE_PATHS pass _validate_relative_path."""
        for rel in CONFIG_FILE_PATHS:
            _validate_relative_path(rel)  # must not raise

    def test_i_cfg_2_rejects_absolute_paths(self, tmp_path):
        """Adjacent: absolute path key → BaselineError at load time."""
        with pytest.raises(BaselineError, match="governed config files"):
            _validate_relative_path("/etc/passwd")

    def test_i_cfg_2_rejects_path_traversal(self, tmp_path):
        """Adversarial: '..' in key → BaselineError at load time."""
        with pytest.raises(BaselineError, match="governed config files"):
            _validate_relative_path("../etc/passwd")


# ===========================================================================
# H.0-A — Schema / serialization tests
# ===========================================================================

class TestBaselineRecordSchema:
    """Named: round-trip with hashes.
    Adjacent: round-trip without hashes (None preserved).
    Adversarial: corrupted hash value refused at load time.
    """

    def test_round_trip_with_hashes(self, tmp_path, monkeypatch):
        """Named: create_draft with hashes → load back → dict equality."""
        from tests.conftest import _FAKE_CONFIG_HASHES
        cfg = _build_config(tmp_path)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        record = svc.load(str(bid))
        assert record.config_file_hashes == _FAKE_CONFIG_HASHES

    def test_round_trip_without_hashes_none(self, tmp_path):
        """Adjacent: BaselineRecord with config_file_hashes=None preserved."""
        record = BaselineRecord(
            baseline_id="b1",
            created_at="2026-01-01T00:00:00Z",
            status="draft",
            wp_version="6.5",
            plugins=[],
            themes=[],
        )
        assert record.config_file_hashes is None

    def test_load_v47_era_record_succeeds(self, tmp_path, monkeypatch):
        """Named: legacy baseline JSON (no config_file_hashes) → loads with field=None."""
        cfg = _build_config(tmp_path)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)

        # Write a v47-era baseline (no config_file_hashes field at all)
        baselines_dir = cfg.root_dir / "baselines"
        baselines_dir.mkdir(parents=True, exist_ok=True)
        bid = "legacy-baseline-v47"
        payload = {
            "baseline_id": bid,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "draft",
            "wp_version": "6.4",
            "plugins": [],
            "themes": [],
        }
        from wpgovern.core.baseline import _atomic_write_json
        bpath = baselines_dir / f"{bid}.json"
        _atomic_write_json(bpath, payload)
        signing.sign_runtime_artifact(bpath)

        record = svc.load(bid)
        assert record.config_file_hashes is None, (
            "Legacy baselines must load with config_file_hashes=None"
        )

    def test_load_rejects_corrupted_hash_value(self, tmp_path, monkeypatch):
        """Adversarial: hash value that doesn't match sha256:<64 hex> → BaselineError."""
        cfg = _build_config(tmp_path)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)

        baselines_dir = cfg.root_dir / "baselines"
        baselines_dir.mkdir(parents=True, exist_ok=True)
        bid = "corrupted"
        payload = {
            "baseline_id": bid,
            "created_at": "2026-01-01T00:00:00Z",
            "status": "draft",
            "wp_version": "6.5",
            "plugins": [],
            "themes": [],
            "config_file_hashes": {"docker-compose.yml": "not_a_hash"},
        }
        from wpgovern.core.baseline import _atomic_write_json
        bpath = baselines_dir / f"{bid}.json"
        _atomic_write_json(bpath, payload)
        signing.sign_runtime_artifact(bpath)

        with pytest.raises(BaselineError, match="sha256"):
            svc.load(bid)


# ===========================================================================
# H.0-B — _docker_wp cli profile tests
# ===========================================================================

class TestDockerWpCliProfile:
    """Named: _docker_wp produces 'docker compose run --rm -T cli wp ...' command.
    Adjacent: create_draft end-to-end also uses cli profile.
    """

    def test_docker_wp_uses_cli_profile(self, tmp_path, monkeypatch):
        """Named: _docker_wp must build cli-profile command, not exec php."""
        captured: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            captured.append(list(cmd))
            m = MagicMock()
            m.stdout = "6.5\n"
            return m

        monkeypatch.setattr(subprocess, "run", fake_run)
        cfg = _build_config(tmp_path)
        from wpgovern.core.signing import SigningService
        svc = BaselineService(config=cfg, signing=SigningService(config=cfg))
        svc._docker_wp(["core", "version"])

        assert captured
        cmd = captured[0]
        assert cmd == [
            "docker", "compose", "run", "--rm", "-T", "cli", "wp", "core", "version"
        ], f"H.0-B: wrong command shape: {cmd}"
        assert "exec" not in cmd, "Must not use 'exec' (old php-service pattern)"
        assert "php" not in cmd, "Must not reference 'php' service"

    def test_create_draft_wp_calls_use_cli_profile(self, tmp_path, monkeypatch):
        """Adjacent: create_draft's wp state capture uses cli profile (not exec php).

        Uses _wp_json_list and _wp_text mocks to avoid subprocess calls for wp-cli,
        then patches _docker_wp directly to capture the command shape.
        """
        from wpgovern.core.baseline import BaselineService

        captured_args: list[list[str]] = []
        original_docker_wp = BaselineService._docker_wp

        def capturing_docker_wp(self, wp_args):
            captured_args.append(["docker", "compose", "run", "--rm", "-T", "cli", "wp", *wp_args])
            # Simulate the real _docker_wp behavior for return values
            if "list" in wp_args and "--format=json" in wp_args:
                return "[]"
            return "6.5"

        cfg = _build_config(tmp_path)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)

        monkeypatch.setattr(BaselineService, "_docker_wp", capturing_docker_wp)

        svc.create_draft()

        assert captured_args, "create_draft must invoke _docker_wp"
        for cmd in captured_args:
            assert "run" in cmd, f"Expected 'run' in cmd: {cmd}"
            assert "cli" in cmd, f"Expected 'cli' in cmd: {cmd}"
            assert "exec" not in cmd, f"Must not use 'exec': {cmd}"
            assert "php" not in cmd, f"Must not reference 'php': {cmd}"


# ===========================================================================
# Utility tests for module-level helpers
# ===========================================================================

def test_sha256_hex_format():
    """_sha256_hex returns 'sha256:' + 64 lowercase hex chars."""
    result = _sha256_hex(b"hello")
    assert result.startswith("sha256:")
    assert len(result) == len("sha256:") + 64
    assert all(c in "0123456789abcdef" for c in result[7:])


def test_sha256_hex_deterministic():
    """_sha256_hex is deterministic for the same input."""
    assert _sha256_hex(b"same") == _sha256_hex(b"same")
    assert _sha256_hex(b"same") != _sha256_hex(b"different")


def test_validate_config_file_hashes_accepts_good_dict():
    """_validate_config_file_hashes accepts a correctly formatted complete dict."""
    good = {rel: "sha256:" + "a" * 64 for rel in CONFIG_FILE_PATHS}
    result = _validate_config_file_hashes(good, "test-id")
    assert result == good


def test_validate_config_file_hashes_rejects_bad_value():
    """_validate_config_file_hashes refuses non-sha256 hash values."""
    with pytest.raises(BaselineError, match="sha256"):
        _validate_config_file_hashes({"docker-compose.yml": "not_a_hash"}, "test")


def test_validate_config_file_hashes_rejects_traversal_key():
    """_validate_config_file_hashes refuses path-traversal keys (closed-set check)."""
    with pytest.raises(BaselineError, match="governed config files"):
        _validate_config_file_hashes({"../etc/passwd": "sha256:" + "a" * 64}, "test")


def test_config_file_paths_constant():
    """CONFIG_FILE_PATHS contains exactly the four expected paths."""
    assert set(CONFIG_FILE_PATHS) == {
        "docker-compose.yml", "Caddyfile", "my.cnf", "wp-config.php"
    }


def test_baseline_record_default_config_field():
    """Optional-field discipline: config_file_hashes defaults to None."""
    record = BaselineRecord(
        baseline_id="x",
        created_at="2026-01-01T00:00:00Z",
        status="draft",
        wp_version="6.5",
        plugins=[],
        themes=[],
    )
    assert record.config_file_hashes is None


# ===========================================================================
# H.0.1 — Integration tests (TestGovernanceCheckConfigHashIntegration)
# ===========================================================================

import wpgovern.core.baseline as bmod


class TestGovernanceCheckConfigHashIntegration:
    """H.0.1: end-to-end tests through real GovernanceChecker.check().

    Unlike the helper-level tests in this file (which call
    checker._evaluate_config_file_hashes directly), these tests run the
    full create → submit → approve → activate → check flow and verify
    that dedicated exit codes 52/53 fire end-to-end.

    These tests are what should have been in the original H.0 brief but
    were not — see H.0.1 finding from external review.
    """

    def _setup_active_baseline(self, tmp_path, monkeypatch):
        """Bootstrap trust, create + activate a baseline. Returns (cfg, install_dir)."""
        install_dir = tmp_path / "install"
        install_dir.mkdir()
        for rel_path in CONFIG_FILE_PATHS:
            (install_dir / rel_path).write_text(f"v1 content of {rel_path}\n")

        from wpgovern.config import WPGovernConfig
        cfg = WPGovernConfig(
            root_dir=tmp_path / "wpgovern",
            install_dir=install_dir,
        )
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)

        # Opt back into real _compute_config_file_hashes
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        svc.submit(str(bid))
        approval_id = svc.approve(str(bid))
        svc.activate(str(bid), approval_id)
        return cfg, install_dir

    def test_check_returns_0_when_files_match_baseline(self, tmp_path, monkeypatch):
        """Named: all four files unchanged after activation → exit 0."""
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 0, (
            f"expected 0, got {result.exit_code} ({result.reason})"
        )

    def test_check_returns_52_when_config_file_modified(self, tmp_path, monkeypatch):
        """Adjacent: one file modified post-activation → exit 52 (hash mismatch)."""
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        (install_dir / "Caddyfile").write_text("MODIFIED — should trip 52\n")
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 52, (
            f"expected 52, got {result.exit_code} ({result.reason})"
        )
        assert "Caddyfile" in result.reason

    def test_check_returns_53_when_config_file_deleted(self, tmp_path, monkeypatch):
        """Adjacent: delete one file post-activation → exit 53 (missing)."""
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        (install_dir / "Caddyfile").unlink()
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 53, (
            f"expected 53, got {result.exit_code} ({result.reason})"
        )
        assert "Caddyfile" in result.reason

    def test_check_returns_53_when_config_file_replaced_by_symlink(
        self, tmp_path, monkeypatch
    ):
        """Adversarial: regular file replaced by symlink post-activation → exit 53."""
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        target = tmp_path / "elsewhere.yml"
        target.write_text("elsewhere content")
        (install_dir / "Caddyfile").unlink()
        (install_dir / "Caddyfile").symlink_to(target)
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 53, (
            f"expected 53 (symlink), got {result.exit_code} ({result.reason})"
        )

    def test_check_returns_0_for_legacy_baseline_without_hash_field(
        self, tmp_path, monkeypatch
    ):
        """Adjacent: legacy v47 baseline without config_file_hashes → no 52/53 fired."""
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)

        # Strip config_file_hashes from the activated baseline record
        baselines_dir = cfg.root_dir / "baselines"
        baseline_files = [
            f for f in baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ]
        assert baseline_files, "Expected at least one baseline record file"
        record_path = baseline_files[0]
        record = json.loads(record_path.read_text())
        record.pop("config_file_hashes", None)
        record_path.write_text(json.dumps(record))

        # Re-sign so signature verification passes
        from wpgovern.core.signing import SigningService
        SigningService(config=cfg).sign_runtime_artifact(record_path)

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code not in (52, 53), (
            f"legacy baseline should not trigger 52/53; got {result.exit_code}"
        )

    def test_check_returns_52_not_21_when_config_hash_mismatch(
        self, tmp_path, monkeypatch
    ):
        """Adversarial: with fully-bootstrapped system, dedicated 52 fires before
        I-CFG-1 in the invariant catalog (which would return 21).

        v50 / H.0.2-3: strengthened with explicit invariant-gate reachability
        assertion to prevent the false-positive guard pattern where the gate
        skips entirely under root_dir override (the H0.1.1 defect).
        """
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)

        # v50 / H.0.2-3: explicit assertion that the invariant gate is reachable.
        # Before the H.0.2-1 fix, these assertions would fail because the gate
        # used config.active_pointer (hardcoded /opt/...) instead of the derived
        # paths.active_pointer. After the fix, both assertions pass and the
        # subsequent exit-52 check actually exercises the ordering claim.
        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        trust_dir = paths.root / "trust"
        assert trust_dir.is_dir(), (
            f"invariant gate setup invalid: trust_dir {trust_dir} does not exist"
        )
        assert paths.active_pointer.is_file(), (
            f"invariant gate setup invalid: active_pointer {paths.active_pointer} "
            f"does not exist"
        )

        # The actual ordering test
        (install_dir / "my.cnf").write_text("modified mysql conf\n")
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 52, (
            f"expected dedicated 52, got {result.exit_code} ({result.reason}) — "
            f"ordering issue: I-CFG-1 may be firing first via invariant catalog"
        )

    def test_check_returns_21_when_active_baseline_tampered_without_resigning(
        self, tmp_path, monkeypatch
    ):
        """v51 / H.0.3-5: tampered active baseline (no re-sign) must return exit 21.

        The original v50 test asserted only `exit_code != 52` (no misclassification).
        Direct PoC against v50 confirmed the actual behavior is stronger: exit 21
        with I-B-1 and I-B-2 violations firing. This test name and assertion now
        reflect the actual behavior, preventing future regressions back to exit 0.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        baseline_files = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ]
        assert baseline_files, "test setup invalid: no baseline record files found"
        record_path = baseline_files[0]
        record = json.loads(record_path.read_text())
        record.pop("config_file_hashes", None)
        record_path.write_text(json.dumps(record))
        # NOT re-signing — signature verification fails, I-B-1/I-B-2 catch it.

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21, (
            f"expected 21 (invariants_violated), got {result.exit_code} "
            f"({result.reason})"
        )
        assert "I-B-1" in result.reason or "I-B-2" in result.reason, (
            f"expected I-B-1 or I-B-2 in reason, got: {result.reason}"
        )

    def test_invariant_gate_uses_derived_paths_not_config_default(
        self, tmp_path, monkeypatch
    ):
        """v50 / H.0.2-1: explicit regression test for the path source-of-truth.

        The invariant catalog gate must use self.paths.active_pointer (derived
        from root_dir), not self.config.active_pointer (hardcoded /opt/...).
        Under root_dir override these diverge — the gate is silently False and
        the entire invariant catalog is skipped.
        """
        import pytest
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)

        # Sanity: confirm the path mismatch exists in this environment
        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        if cfg.active_pointer == paths.active_pointer:
            pytest.skip(
                "test environment has cfg.active_pointer == paths.active_pointer; "
                "cannot exercise the H.0.2-1 regression"
            )

        # Modify a config file to trigger a violation that I-CFG-1 would catch
        # if the gate is correctly reached. If the gate uses config.active_pointer
        # (broken), I-CFG-1 never runs and we get exit 0.
        (install_dir / "Caddyfile").write_text("modified after baseline\n")
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code != 0, (
            f"check() returned exit 0 with config file modified — invariant catalog "
            f"gate may be using config.active_pointer instead of paths.active_pointer "
            f"(H.0.2-1 not closed)"
        )

    def test_check_handles_missing_signature_sidecar_deterministically(
        self, tmp_path, monkeypatch
    ):
        """v51 / H.0.3-1: missing .sig.json sidecar must produce deterministic
        exit code (21), not an uncaught NotFoundError exception.

        PoC against v50: deleting the sidecar caused GovernanceChecker.check()
        to crash with NotFoundError because the helper only caught IntegrityError.
        """
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        baseline_files = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ]
        assert baseline_files, "test setup invalid: no baseline record files found"
        record_path = baseline_files[0]
        sig_path = Path(str(record_path) + ".sig.json")
        sig_path.unlink()

        # Must NOT raise; must return a deterministic result
        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21, (
            f"expected 21 (invariants), got {result.exit_code} ({result.reason})"
        )

    def test_check_rejects_signed_absolute_path_manifest(
        self, tmp_path, monkeypatch
    ):
        """v51 / H.0.3-2: signed manifest with absolute-path key must NOT be
        classified as ordinary drift. Schema violation → I-CFG-2 → exit 21.

        PoC against v50: signed manifest with {/etc/passwd: ...} returned exit 52,
        inspecting /etc/passwd outside the install_dir boundary.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        record["config_file_hashes"] = {"/etc/passwd": "sha256:" + "0" * 64}
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")  # re-sign

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code != 52, (
            f"absolute-path manifest misclassified as drift (52): {result.reason}"
        )
        assert result.exit_code == 21, (
            f"expected 21 (schema violation via I-CFG-2), got {result.exit_code}"
        )
        assert "I-CFG-2" in result.reason

    def test_check_rejects_signed_empty_manifest(self, tmp_path, monkeypatch):
        """v51 / H.0.3-3: signed empty manifest must fire I-CFG-2 → exit 21.

        PoC against v50: empty manifest returned exit 0 because the
        `if not hashes` check silently fell through to legacy treatment.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        record["config_file_hashes"] = {}
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21, (
            f"empty manifest must produce 21, got {result.exit_code} ({result.reason})"
        )
        assert "I-CFG-2" in result.reason

    def test_check_rejects_signed_partial_manifest(self, tmp_path, monkeypatch):
        """v51 / H.0.3-3: signed partial manifest must fire I-CFG-2 → exit 21.

        PoC against v50: partial manifest (only Caddyfile) + tamper of wp-config.php
        returned exit 0 because the omitted files weren't checked.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        caddy_hash = record["config_file_hashes"].get("Caddyfile")
        record["config_file_hashes"] = {"Caddyfile": caddy_hash}
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")

        # Tamper with an omitted file
        (install_dir / "wp-config.php").write_text("MODIFIED\n")

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21, (
            f"partial manifest + tampered omitted file must produce 21, "
            f"got {result.exit_code} ({result.reason})"
        )
        assert "I-CFG-2" in result.reason

    def test_check_rejects_signed_non_dict_manifest(self, tmp_path, monkeypatch):
        """v51 / H.0.3-3: signed manifest with non-dict type must fire I-CFG-2.

        PoC against v50: list-typed manifest returned exit 0 because the
        `if not isinstance(hashes, dict)` check silently fell through to
        legacy-baseline treatment.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        record["config_file_hashes"] = []  # not a dict
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21, (
            f"non-dict manifest must produce 21, got {result.exit_code} ({result.reason})"
        )
        assert "I-CFG-2" in result.reason

    def test_check_rejects_signed_null_manifest_with_drift(
        self, tmp_path, monkeypatch
    ):
        """v52 / H.0.4-1: signed config_file_hashes=null must NOT silently bypass.

        PoC against v51.1: signed null + tampered wp-config.php returned exit 0 ok.
        dict.get() treated null as field-absent (legacy). v52 uses explicit
        membership check to distinguish field-absent from field-present-with-null.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        record["config_file_hashes"] = None  # explicit null
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")

        # Tamper a governed file to verify enforcement IS being tested
        (install_dir / "wp-config.php").write_text("MODIFIED\n")

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21, (
            f"signed null manifest must NOT bypass; expected 21, "
            f"got {result.exit_code} ({result.reason})"
        )
        assert "I-CFG-2" in result.reason, (
            f"expected I-CFG-2 schema violation, got: {result.reason}"
        )

    def test_i_cfg_1_does_not_read_paths_from_malformed_manifest(
        self, tmp_path, monkeypatch
    ):
        """v52 / H.0.4-2: I-CFG-1 must schema-validate before iterating.

        PoC against v51.1: signed absolute-path manifest caused I-CFG-1 to compute
        install_dir / '/etc/hostname' = '/etc/hostname' (Path discards install_dir
        for absolute keys), then read the file and report its real hash. v52
        validates before iteration; malformed manifests are caught by I-CFG-2 only.
        """
        import json
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        record["config_file_hashes"] = {"/etc/hostname": "sha256:" + "0" * 64}
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")

        result = GovernanceChecker(config=cfg).check()
        assert result.exit_code == 21
        assert "I-CFG-2" in result.reason
        # I-CFG-1 must NOT fire — schema validation rejects the malformed manifest
        # before iteration, so no path is read outside CONFIG_FILE_PATHS.
        assert "I-CFG-1" not in result.reason, (
            f"I-CFG-1 fired on malformed manifest — should defer to I-CFG-2. "
            f"Reason: {result.reason}"
        )

    def test_i_cfg_2_reports_null_manifest_as_non_dict(
        self, tmp_path, monkeypatch
    ):
        """v52 / H.0.4-3: I-CFG-2 must report signed null manifest as non-dict."""
        import json
        from wpgovern.utils.invariants import check_all_invariants
        cfg, install_dir = self._setup_active_baseline(tmp_path, monkeypatch)
        from wpgovern.core.signing import SigningService
        signing = SigningService(config=cfg)

        from wpgovern.paths import build_paths
        paths = build_paths(cfg)
        record_path = [
            f for f in paths.baselines_dir.glob("baseline-*.json")
            if not f.name.endswith(".sig.json")
        ][0]
        record = json.loads(record_path.read_text())
        record["config_file_hashes"] = None
        record_path.write_text(json.dumps(record))
        signing.sign_file(record_path, domain="runtime")

        violations = check_all_invariants(cfg)
        i_cfg_2_violations = [v for v in violations if v.invariant_id == "I-CFG-2"]
        assert len(i_cfg_2_violations) >= 1, (
            f"expected at least one I-CFG-2 violation, got: {violations}"
        )
        # At least one violation must be the non-dict type complaint for NoneType
        non_dict_v = [
            v for v in i_cfg_2_violations
            if v.details.get("actual_type") == "NoneType"
        ]
        assert non_dict_v, (
            f"expected I-CFG-2 to report null as NoneType non-dict; "
            f"got violations: {[v.details for v in i_cfg_2_violations]}"
        )


class TestSymlinkRefusal:
    """Named: symlink → BaselineError.
    Adjacent: regular file at same path → succeeds.
    Adversarial: symlink pointing outside install_dir → BaselineError.
    """

    def test_create_draft_refuses_symlink_for_config_file(self, tmp_path, monkeypatch):
        """Named: symlink at config file path → BaselineError at create_draft time."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)

        # Replace one file with a symlink to itself (still within install_dir)
        target = tmp_path / "real_caddyfile"
        target.write_bytes(b"real content")
        (cfg.install_dir / "Caddyfile").unlink()
        (cfg.install_dir / "Caddyfile").symlink_to(target)

        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        with pytest.raises(BaselineError, match="symlink"):
            svc.create_draft()

    def test_create_draft_accepts_regular_file_at_same_path(self, tmp_path, monkeypatch):
        """Adjacent: regular file (not symlink) at same path → succeeds."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)
        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        bid = svc.create_draft()
        record = svc.load(str(bid))
        assert record.config_file_hashes is not None

    def test_create_draft_refuses_symlink_pointing_outside_install_dir(
        self, tmp_path, monkeypatch
    ):
        """Adversarial: symlink pointing outside install_dir → BaselineError."""
        import wpgovern.core.baseline as bmod
        monkeypatch.setattr(bmod, "_compute_config_file_hashes", _compute_config_file_hashes)

        cfg = _build_config(tmp_path)
        _make_config_files(cfg.install_dir)

        # Symlink pointing to /etc/passwd (outside install_dir)
        (cfg.install_dir / "wp-config.php").unlink()
        (cfg.install_dir / "wp-config.php").symlink_to("/etc/passwd")

        signing = _bootstrap_trust(cfg)
        svc = BaselineService(config=cfg, signing=signing)
        monkeypatch.setattr(BaselineService, "_wp_json_list", lambda self, a: [])
        monkeypatch.setattr(BaselineService, "_wp_text", lambda self, a: "6.5")

        with pytest.raises(BaselineError, match="symlink"):
            svc.create_draft()


# ===========================================================================
# H.0.1-4 — Validator tightening tests (closed-set membership)
# ===========================================================================

class TestValidatorTightening:
    """Closed-set membership: only the four CONFIG_FILE_PATHS are accepted."""

    def test_validator_accepts_all_four_canonical_paths(self, tmp_path):
        """Named: the four CONFIG_FILE_PATHS are accepted by _validate_relative_path."""
        for rel in CONFIG_FILE_PATHS:
            _validate_relative_path(rel)  # must not raise

    def test_validator_rejects_windows_backslash_path(self, tmp_path):
        """Adversarial: Windows-style backslash path rejected by closed-set check."""
        with pytest.raises(BaselineError, match="governed config files"):
            _validate_relative_path("foo\\bar")

    def test_validator_rejects_nul_byte(self, tmp_path):
        """Adversarial: NUL byte in path rejected by closed-set check."""
        with pytest.raises(BaselineError, match="governed config files"):
            _validate_relative_path("docker-compose.yml\x00malicious")

    def test_validator_rejects_empty_string(self, tmp_path):
        """Adversarial: empty string rejected by closed-set check."""
        with pytest.raises(BaselineError, match="governed config files"):
            _validate_relative_path("")

    def test_validator_rejects_arbitrary_relative_path(self, tmp_path):
        """Adversarial: valid-looking relative path not in CONFIG_FILE_PATHS rejected."""
        with pytest.raises(BaselineError, match="governed config files"):
            _validate_relative_path("foo.yml")


# ===========================================================================
# H.0.1-5 — Clearer install_dir-missing diagnostic tests
# ===========================================================================

class TestInstallDirDiagnostic:
    """Named: install_dir doesn't exist → clear error naming install_dir.
    Adversarial: install_dir is a file, not a directory → clear error.
    """

    def test_compute_hashes_raises_clear_error_when_install_dir_missing(
        self, tmp_path
    ):
        """Named: install_dir does not exist → error names install_dir, not a config file."""
        nonexistent = tmp_path / "no-such-dir"
        with pytest.raises(BaselineError) as exc_info:
            _compute_config_file_hashes(nonexistent)
        msg = str(exc_info.value)
        assert "install_dir" in msg or "does not exist" in msg, (
            f"Error should name install_dir problem, got: {msg}"
        )
        assert "docker-compose.yml" not in msg, (
            "Error should not mention a config file when install_dir is the problem"
        )

    def test_compute_hashes_raises_clear_error_when_install_dir_is_file(
        self, tmp_path
    ):
        """Adversarial: install_dir exists but is a file → clear error."""
        file_path = tmp_path / "not-a-dir"
        file_path.write_bytes(b"I am a file")
        with pytest.raises(BaselineError, match="not a directory|install_dir"):
            _compute_config_file_hashes(file_path)

