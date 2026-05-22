"""
Hypothesis property-based tests for commit semantics and audit continuity.

Coverage:
- Commit succeeds and invariants hold (random write specs)
- Abort leaves no residue (staging and journal clean)
- Sequential commits preserve invariants
- Fresh-install invariants hold
- Invariant catalog detects stale .intent.staged
- Invariant catalog detects orphan .complete
- Invariant catalog detects unexpected journal file
- Invariant catalog detects two active trust keys
- Audit chain continuity under random events
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from wpgovern.audit.logger import AuditLogger
from wpgovern.audit.verifier import AuditVerifier
from wpgovern.config import WPGovernConfig
from wpgovern.core.trust import TrustService
from wpgovern.errors import IntegrityError
from wpgovern.utils.invariants import (
    InvariantViolation, assert_invariants_hold, check_all_invariants,
)
from wpgovern.utils.transaction import AtomicTransaction


# ---------------------------------------------------------------------------
# Shared strategy and fixture helper
# ---------------------------------------------------------------------------


def write_spec_strategy():
    """Generate a list of 1-4 (filename, content) pairs."""
    return st.lists(
        st.tuples(
            st.from_regex(r"[a-z][a-z0-9\-]{0,8}\.json", fullmatch=True),
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=40),
        ),
        min_size=1,
        max_size=4,
    )


def _make_config(tmp_path_factory) -> WPGovernConfig:
    root = tmp_path_factory.mktemp("hyp")
    cfg = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    trust = TrustService(config=cfg)
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")
    return cfg


# ---------------------------------------------------------------------------
# Commit property: invariants hold after successful commit
# ---------------------------------------------------------------------------


@given(specs=write_spec_strategy())
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_commit_succeeds_and_invariants_hold(
    tmp_path_factory, specs: list[tuple[str, str]]
) -> None:
    """After a successful commit, all invariants hold and targets have new content."""
    config = _make_config(tmp_path_factory)
    root = config.root_dir
    targets_dir = root / "targets"
    staging_root = root / "state" / ".transactions"
    targets_dir.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)
    trust = TrustService(config=config)

    # De-duplicate filenames
    seen: dict[str, str] = {}
    for filename, content in specs:
        seen[filename] = content
    target_content = seen

    # Write initial state
    for filename, content in target_content.items():
        (targets_dir / filename).write_text(f"old-{content}")

    with AtomicTransaction(
        staging_root,
        service_label="HypTest.commit",
        actor_id="hypothesis",
        journal_root=root,
        trust_service=trust,
    ) as txn:
        for filename, content in target_content.items():
            txn.stage_text(targets_dir / filename, f"new-{content}")
        txn.commit()

    # Verify new content
    for filename, content in target_content.items():
        assert (targets_dir / filename).read_text() == f"new-{content}"

    assert_invariants_hold(config)


# ---------------------------------------------------------------------------
# Abort property: no residue after abort
# ---------------------------------------------------------------------------


@given(specs=write_spec_strategy())
@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_abort_leaves_no_residue(
    tmp_path_factory, specs: list[tuple[str, str]]
) -> None:
    """After an aborted transaction, targets are unchanged and no journal files linger."""
    config = _make_config(tmp_path_factory)
    root = config.root_dir
    targets_dir = root / "targets"
    staging_root = root / "state" / ".transactions"
    targets_dir.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)
    trust = TrustService(config=config)

    seen: dict[str, str] = {}
    for filename, content in specs:
        seen[filename] = content

    # Write initial state
    for filename, content in seen.items():
        (targets_dir / filename).write_text(f"original-{content}")

    # Stage but do NOT commit — let context manager abort on exception
    try:
        with AtomicTransaction(
            staging_root,
            service_label="HypTest.abort",
            actor_id="hypothesis",
            journal_root=root,
            trust_service=trust,
        ) as txn:
            for filename, content in seen.items():
                txn.stage_text(targets_dir / filename, f"aborted-{content}")
            raise RuntimeError("simulated abort")
    except RuntimeError:
        pass

    # Targets must be unchanged
    for filename, content in seen.items():
        assert (targets_dir / filename).read_text() == f"original-{content}"

    # No journal intent files
    journal_dir = root / "state" / ".journal"
    if journal_dir.exists():
        assert list(journal_dir.glob("*.intent")) == [], \
            "No intent files should remain after abort"

    assert_invariants_hold(config)


# ---------------------------------------------------------------------------
# Sequential commits: invariants preserved across multiple transactions
# ---------------------------------------------------------------------------


@given(
    specs=st.lists(write_spec_strategy(), min_size=2, max_size=4),
    n_transactions=st.integers(min_value=2, max_value=4),
)
@settings(
    max_examples=15,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_sequential_commits_preserve_invariants(
    tmp_path_factory,
    specs: list[list[tuple[str, str]]],
    n_transactions: int,
) -> None:
    """Invariants hold after every commit in a sequence of transactions."""
    config = _make_config(tmp_path_factory)
    root = config.root_dir
    targets_dir = root / "targets"
    staging_root = root / "state" / ".transactions"
    targets_dir.mkdir(parents=True, exist_ok=True)
    staging_root.mkdir(parents=True, exist_ok=True)
    trust = TrustService(config=config)

    # Use each spec once (wrap if fewer specs than transactions)
    for i in range(n_transactions):
        batch = specs[i % len(specs)]
        seen: dict[str, str] = {}
        for filename, content in batch:
            seen[filename] = content

        with AtomicTransaction(
            staging_root,
            service_label="HypSeqTest.commit",
            actor_id="hypothesis",
            journal_root=root,
            trust_service=trust,
        ) as txn:
            for filename, content in seen.items():
                txn.stage_text(targets_dir / filename, f"v{i}-{content}")
            txn.commit()

        assert_invariants_hold(config)


# ---------------------------------------------------------------------------
# Targeted invariant violation detection
# ---------------------------------------------------------------------------


@pytest.fixture()
def hypothesis_config(tmp_path: Path) -> WPGovernConfig:
    root = tmp_path / "wpg"
    cfg = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    trust = TrustService(config=cfg)
    trust.generate_journal_key("journal-1")
    trust.activate_journal_key("journal-1")
    return cfg


def test_invariant_catalog_holds_on_fresh_install(
    hypothesis_config: WPGovernConfig,
) -> None:
    assert_invariants_hold(hypothesis_config)


def test_invariant_catches_stale_intent_staged(
    hypothesis_config: WPGovernConfig,
) -> None:
    import os
    journal_dir = hypothesis_config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    (journal_dir / "txn-x.intent.staged").write_text("stale\n")

    violations = [v for v in check_all_invariants(hypothesis_config)
                  if v.invariant_id == "I-FS-3"]
    assert len(violations) == 1


def test_invariant_catches_orphan_complete(
    hypothesis_config: WPGovernConfig,
) -> None:
    import os
    journal_dir = hypothesis_config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    (journal_dir / "txn-orphan.complete").write_text('{"txn_id":"txn-orphan"}\n')

    violations = [v for v in check_all_invariants(hypothesis_config)
                  if v.invariant_id == "I-J-3"]
    assert len(violations) == 1


def test_invariant_catches_unexpected_journal_file(
    hypothesis_config: WPGovernConfig,
) -> None:
    import os
    journal_dir = hypothesis_config.root_dir / "state" / ".journal"
    journal_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(journal_dir, 0o700)
    (journal_dir / "random-unknown.bin").write_text("unexpected\n")

    violations = [v for v in check_all_invariants(hypothesis_config)
                  if v.invariant_id == "I-NEG-JOURNAL"]
    assert len(violations) == 1


def test_invariant_catches_two_active_keys(
    hypothesis_config: WPGovernConfig,
) -> None:
    import json as _json
    trust = TrustService(config=hypothesis_config)
    trust.generate_runtime_key("runtime-a")
    trust.activate_runtime_key("runtime-a")

    store_path = hypothesis_config.runtime_trust_store
    store = _json.loads(store_path.read_text())
    pub_path = hypothesis_config.root_dir / "trust/runtime/public/runtime-b.pub"
    pub_path.write_text("fake-pub-key")
    store["keys"].append({
        "key_id": "runtime-b",
        "status": "active",
        "path": str(pub_path),
        "created_at": "2026-01-01T00:00:00Z",
        "usage": ["sign", "verify"],
    })
    store_path.write_text(_json.dumps(store, indent=2) + "\n")

    violations = [v for v in check_all_invariants(hypothesis_config)
                  if v.invariant_id == "I-T-1"]
    assert len(violations) >= 1


# ---------------------------------------------------------------------------
# Audit chain continuity under random events
# ---------------------------------------------------------------------------


@given(
    events=st.lists(
        st.tuples(
            st.sampled_from([
                "baseline.create", "baseline.activate", "approval.revoked",
                "trust.key.generated", "rollback.activate", "reconciliation.complete",
            ]),
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=10),
        ),
        min_size=1,
        max_size=15,
    )
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_audit_chain_continuity_under_random_events(
    tmp_path_factory,
    events: list[tuple[str, str]],
) -> None:
    """After any sequence of audit events, the chain verifies cleanly."""
    root = tmp_path_factory.mktemp("audit_hyp")
    config = WPGovernConfig(
        root_dir=root,
        install_dir=root / "install",
        runtime_trust_store=root / "trust/runtime/public/trusted-runtime-keys.json",
        release_trust_store=root / "trust/release/public/trusted-release-keys.json",
        active_pointer=root / "state/active.json",
        audit_log=root / "audit/audit.log",
        alert_sinks=({"type": "none"},),
    )
    logger = AuditLogger(config=config)

    for event_type, actor in events:
        logger.emit(
            event_type=event_type,
            actor=actor,
            outcome="success",
            details={},
        )

    verifier = AuditVerifier(config=config)
    result = verifier.verify()
    assert result.ok
    assert result.entries == len(events)
