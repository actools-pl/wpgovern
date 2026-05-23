# Phase 7 — Policy: Rollback, Break-glass, Reconciliation

**Status:** Complete
**Tests:** 268 total (238 from Phases 0-6, 30 new), 0 failed
**Modules authored:** `policy/rollback.py`, `policy/breakglass.py`, `policy/reconciliation.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `policy/rollback.py` | `RollbackService`, `RollbackError`, `RollbackActivationResult` |
| `policy/breakglass.py` | `BreakglassService`, `BreakglassError`, `BreakglassActivationResult`, `ReviewResult` |
| `policy/reconciliation.py` | `ReconciliationService`, `ReconciliationError`, `ReconciliationRecord` |

---

## Design decisions

### All three modules define `utc_now_iso()` at module level
Each module defines its own `utc_now_iso()` function (not imported) for the same reason as `policy/approval.py` in Phase 6: tests monkeypatch the module-level name to control timestamps. Tests that exercise the approval TTL check must also patch `approval_module.utc_now_iso` because `check_expiry()` uses that module's function. This is recorded here so no future test author is surprised.

### Reconciliation gate is atomic with emergency record
In `BreakglassService.activate()`, the `reconciliation_required` gate file is staged inside the same `AtomicTransaction` as the emergency record. A kill between staging cannot leave the emergency recorded without the gate raised, or vice versa.

### Reconciliation enforcement is signature-gated
`ReconciliationService.validate_breakglass_review()` verifies the emergency record signature AND the review record signature before trusting any field in either. A tampered or unsigned emergency record cannot be used to claim that a review happened.

### Non-break-glass reconciliation bypasses the review chain check
`validate_breakglass_review()` is a no-op when `reconciliation.source != "breakglass"`. Manual reconciliation records (e.g., written by an operator for a non-emergency event) complete without the review chain.

### `RollbackActivationResult`, `BreakglassActivationResult`, `ReviewResult` are str subclasses
This preserves CLI call-site compatibility where the return value is printed directly. Metadata fields are accessible as attributes.

### Reconciliation gate check is in RollbackService and BaselineService
Both `RollbackService.activate()` and `BaselineService.activate()` check `paths.reconciliation_required` before proceeding. This is the enforcement invariant: once a break-glass is active, no governance activation can proceed until reconciliation is complete.

---

## Invariants established in this phase

1. Break-glass activate and reconciliation-gate creation are atomic — they cannot be separated.
2. Break-glass reconciliation cannot complete unless the emergency is reviewed AND the review is signed.
3. Tampered emergency or review signatures block reconciliation completion.
4. Rollback is blocked when the reconciliation gate exists.
5. All activated artifacts (rollback record, emergency record, reconciliation record, consumed approval) are signed.
6. Approval TTL checks use `approval_module.utc_now_iso` — tests must patch that module too when controlling time.

---

## Test coverage summary

**`tests/test_rollback.py`** (8 tests) — approve (signed bound approval, nonexistent target, empty reason), activate (four files + signatures, reconciliation gate blocks, wrong approval type, audit emission, silent without logger).

**`tests/test_breakglass.py`** (13 tests) — approve (fields, invalid inputs), activate (all artifacts, missing active pointer, expired approval, audit emission), review (creates record + marks reviewed, missing emergency, empty outcome, empty findings, audit emission).

**`tests/test_reconciliation.py`** (9 tests) — non-breakglass completes and clears gate, breakglass fails (not reviewed, review missing, emergency tampered, review tampered, ID mismatch), breakglass succeeds with full valid chain, audit emission, gate blocks rollback activation.

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
