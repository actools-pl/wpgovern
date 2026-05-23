# Phase 6 — Baseline & Approval

**Status:** Complete
**Tests:** 238 total (208 from Phases 0-5, 30 new), 0 failed
**Modules authored:** `core/baseline.py`, `policy/approval.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `core/baseline.py` | `BaselineService`, `BaselineRecord`, `BaselineError`, `BaselineId` |
| `policy/approval.py` | `ApprovalService`, `ApprovalRecord` |

---

## Design decisions

### `ApprovalRecord` and `BaselineRecord` — stdlib dataclasses in owning modules
No `models/` directory. Both are `@dataclass(slots=True)` defined in the module that owns their lifecycle.

### `ApprovalService.load()` is self-verifying
Every call to `load()` verifies the approval signature against the runtime trust domain before returning the record. There is no "load and separately verify" pattern — the safe path is the only path exposed by the default API.

`load_untrusted_for_inspection_only()` is the explicit unsafe variant for diagnostics and forensic inspection. Its name is deliberately verbose. Any caller using it must NOT use the returned record for enforcement decisions.

### Approval consumed on activation — no reuse
`prepare_consume()` validates the approval is consumable and returns the consumed payload without writing. The actual write happens inside `BaselineService.activate()`'s `AtomicTransaction` — the approval and all other activation artifacts are committed atomically. A second `require_approved()` after consumption raises `PolicyError("already consumed")`.

### Activation is a four-file atomic transaction with crash-recovery journal
`BaselineService.activate()` stages four signed JSON files and commits them via `AtomicTransaction(service_label="BaselineService.activate", trust_service=...)`:

1. Baseline record (status → active)
2. Approval record (status → consumed)
3. Active pointer (updated to new baseline)
4. Supersession record (audit trail)

A process kill at any point leaves either all files at their new state or the journal's recovery routine restores the originals on next startup.

### Reconciliation gate
`activate()` checks for `paths.reconciliation_required` before proceeding. If the file exists, activation is blocked with a clear error. The gate is checked inside the lock set.

### Audit emission inside the lock set
When `audit_logger` and `actor_context` are provided, `activate()` emits its `baseline.activate` record while still holding the four advisory locks. This closes the kill window between state commit and audit emission.

### Module-level `utc_now_iso` importable for monkeypatching
In `core/baseline.py`, `utc_now_iso` is imported at module level from `wpgovern.utils.time` and is also used by the module-level helper functions `_timestamped_id` and `_utcnow_compact`. Tests monkeypatch `baseline_module.utc_now_iso` to control timestamps. In `policy/approval.py`, `utc_now_iso` is defined as a local module-level function for the same reason.

---

## Invariants established in this phase

1. `ApprovalService.load()` always verifies the signature before returning a record.
2. An approval can only be consumed once — reuse raises `PolicyError`.
3. Baseline activation commits all four files atomically or none (crash-recovery journal).
4. `activate()` checks reconciliation gate before any state mutation.
5. `approve()` produces an approval bound to a specific baseline_id.
6. A revoked approval cannot be consumed.

---

## Test coverage summary

**`tests/test_approval.py`** (16 tests) — load signature verification, NotFoundError on missing, tamper detected, load_untrusted bypasses verify, require_approved (matching, consumed, revoked, type mismatch, expired TTL), consume (transitions, re-signs, prevents reuse), revoke (transitions, re-signs, empty reason, consumed approval), prepare_consume (path+payload without writing), invalid status, path-traversal approval_id.

**`tests/test_baseline.py`** (14 tests) — create_draft (fields, signed), submit (transition, re-sign, rejects non-draft), approve (bound signed approval, rejects non-submitted), activate (four files + signatures, supersession, mismatched approval, reconciliation gate, missing baseline signature, audit emission, silent without logger, mid-commit failure followed by recovery).

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
