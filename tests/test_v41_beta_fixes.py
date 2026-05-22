"""
Regression tests for Phase β fixes.

β-1 — I-FS-5 covers all three trust private domains (runtime, release, journal)
β-2 — I-T-5 verifies symlink target is a regular file
β-3 — schema_version explicit handling: missing or wrong version raises JournalSchemaError
β-4 — README test counts CI guard catches all stale references (via test_ci_guards.py)
β-5 — .gitignore and release hygiene documented
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService


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
# β-1 — I-FS-5 covers all three domains
# ---------------------------------------------------------------------------

def test_beta1_ifs5_catches_runtime_and_release_mode_violations(env) -> None:
    """I-FS-5 must report mode violations across all three private domains.

    Pre-fix: I-FS-5 only checked trust/journal/private. Runtime and release
    private keys at 0o644 were not detected.
    """
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    (cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem").chmod(0o644)
    (cfg.root_dir / "trust" / "release" / "private" / "release-1.pem").chmod(0o644)
    (cfg.root_dir / "trust" / "journal" / "private" / "journal-1.pem").chmod(0o644)

    violations = check_all_invariants(cfg)
    fs5 = [v for v in violations if v.invariant_id == "I-FS-5"]

    domains_caught = set()
    for v in fs5:
        for d in ("runtime", "release", "journal"):
            if d in str(v.details).lower():
                domains_caught.add(d)

    assert "runtime" in domains_caught, f"I-FS-5 missed runtime: {fs5}"
    assert "release" in domains_caught, f"I-FS-5 missed release: {fs5}"
    assert "journal" in domains_caught, f"I-FS-5 missed journal: {fs5}"


def test_beta1_ifs5_clean_state_passes(env) -> None:
    """I-FS-5 must not fire on correct modes."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env
    violations = check_all_invariants(cfg)
    fs5 = [v for v in violations if v.invariant_id == "I-FS-5"]
    assert not fs5, f"I-FS-5 fired on clean state: {fs5}"


# ---------------------------------------------------------------------------
# β-2 — I-T-5 checks symlink target is a regular file
# ---------------------------------------------------------------------------

def test_beta2_it5_fires_on_broken_symlink_target(env) -> None:
    """I-T-5 must fire when the symlink's target file is missing.

    Pre-fix: I-T-5 checked name-match and path-inside-tree but not that the
    resolved target was an actual file. It relied on I-T-4 as a backstop —
    fragile. I-T-5 should be self-sufficient on its own contract.
    """
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    # Delete the private key but leave the symlink in place
    (cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem").unlink()

    violations = check_all_invariants(cfg)
    it5 = [v for v in violations if v.invariant_id == "I-T-5"]
    assert it5, f"I-T-5 must fire on broken symlink (missing target): {violations}"


def test_beta2_it5_fires_on_directory_target(env) -> None:
    """I-T-5 must fire when the symlink target is a directory."""
    from wpgovern.utils.invariants import check_all_invariants
    cfg, _ = env

    pem = cfg.root_dir / "trust" / "runtime" / "private" / "runtime-1.pem"
    pem.unlink()
    pem.mkdir()

    violations = check_all_invariants(cfg)
    it5 = [v for v in violations if v.invariant_id == "I-T-5"]
    assert it5, f"I-T-5 must fire when target is a directory: {violations}"


# ---------------------------------------------------------------------------
# β-3 — schema_version explicit handling
# ---------------------------------------------------------------------------

def test_beta3_missing_schema_version_raises(tmp_path: Path) -> None:
    """Records without schema_version must raise JournalSchemaError.

    Pre-fix: silently defaulted to current version, causing confusing
    'signature mismatch' downstream instead of naming the real problem.
    """
    from wpgovern.utils.journal import read_intent_record
    from wpgovern.errors import JournalSchemaError

    path = tmp_path / "test.intent"
    path.write_text(json.dumps({
        "txn_id": "test-txn",
        "started_at": "2026-01-01T00:00:00Z",
        "service": "TestService",
        "actor_id": None,
        "writes": [],
    }))

    with pytest.raises(JournalSchemaError, match="schema_version"):
        read_intent_record(path)


def test_beta3_wrong_schema_version_raises(tmp_path: Path) -> None:
    """Records with an unsupported schema_version must raise JournalSchemaError."""
    from wpgovern.utils.journal import read_intent_record
    from wpgovern.errors import JournalSchemaError

    path = tmp_path / "test2.intent"
    path.write_text(json.dumps({
        "schema_version": 99,
        "txn_id": "test-txn",
        "started_at": "2026-01-01T00:00:00Z",
        "service": "TestService",
        "actor_id": None,
        "writes": [],
    }))

    with pytest.raises(JournalSchemaError, match="schema_version"):
        read_intent_record(path)


def test_beta3_correct_schema_version_reads_successfully(tmp_path: Path) -> None:
    """Records with the current schema_version must read successfully."""
    from wpgovern.utils.journal import read_intent_record, JOURNAL_SCHEMA_VERSION

    path = tmp_path / "test3.intent"
    path.write_text(json.dumps({
        "schema_version": JOURNAL_SCHEMA_VERSION,
        "txn_id": "test-txn",
        "started_at": "2026-01-01T00:00:00Z",
        "service": "TestService",
        "actor_id": None,
        "writes": [],
        "deletes": [],
        "symlinks": [],
        "intent_integrity_hash": "",
        "intent_signature": "",
        "intent_signature_key_id": "",
    }))

    record = read_intent_record(path)
    assert record.schema_version == JOURNAL_SCHEMA_VERSION
    assert record.txn_id == "test-txn"
