# Phase 10 — Status Checker & Reporter

**Status:** Complete
**Tests:** 363 total (342 from Phases 0-9, 21 new), 0 failed
**Modules authored:** `status/checker.py`, `status/reporter.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `status/checker.py` | `GovernanceChecker`, `GovernanceCheckResult` |
| `status/reporter.py` | `GovernanceReporter`, `GovernanceReport` |

---

## Exit-code contract

| Code | Condition |
|------|-----------|
| 0 | Governance OK |
| 10 | Reconciliation required |
| 11 | Break-glass review debt (expired approval or pending emergency review) |
| 12 | Journal staleness exceeded enforcement threshold (opt-in via `journal_staleness_enforce_seconds`) |
| 13 | Journal signing key unavailable |
| 20 | Trust store or active-pointer integrity failure |
| 30 | B4: disk full |
| 31 | B4: read-only filesystem |
| 32 | B4: permission denied |
| 33 | B4: recovery stuck, unclassified, or event record unreadable |
| 50 | Audit review overdue (only when `review_max_age_days` is configured) |
| 51 | Audit chain integrity failure (unconditional) |

## Check order

1. **Audit chain integrity (51)** — checked on every run regardless of config.
2. **B4 filesystem event (30–33)** — highest priority; system needs operator intervention.
3. **Audit review currency (50)** — only when `review_max_age_days` is configured.
4. **Trust & active-pointer (20)** — runtime trust store validation and active pointer signature.
5. **Journal trust key (13)** — journal signing key availability.
6. **Reconciliation required (10)** — gate file presence.
7. **Break-glass debt (11)** — expired unreviewed approval or pending emergency review.
8. **Journal staleness enforcement (12)** — only when `journal_staleness_enforce_seconds` is configured.
9. **OK (0)**

---

## Design decisions

### Audit chain integrity is unconditional (S-2)
Before v21, `verify()` was only called inside `_evaluate_review_currency()`, which returns `None` immediately when `review_max_age_days=None` (the default). This meant every default-config deployment ran governance-check without touching the audit chain. The fix moves the chain verification to step 1, before any other check, so a tampered chain is always surfaced regardless of config.

### Exit 51 is distinct from 50
Exit code 51 (chain integrity failure) is intentionally different from 50 (review overdue) so monitoring can route them to different escalation paths. A broken chain is a potential security incident; an overdue review is a process gap.

### B4 event resolved by `resolved_at` field
A B4 event file at `state/.last_b4_event.json` is only flagged as active if it lacks a `resolved_at` field. Operator runs `wpgovern b4-clear --confirm` which sets this field, returning the system to clean state.

### Journal staleness is warn-only by default
`_evaluate_journal_staleness()` always computes the journal status and includes it in the result. However, it only contributes to the exit code (12) when `journal_staleness_enforce_seconds` is explicitly configured. The warn-only case surfaces as `journal_status.status == "stale_warn"` in the result dict but does not change the exit code.

### Reconciliation (10) takes priority over journal staleness (12)
Steps 6 and 8 are ordered so that reconciliation is surfaced before journal staleness. An operator who sees exit 10 knows exactly what to do; showing exit 12 first would be misleading.

### `GovernanceChecker` v. `GovernanceReporter`
`GovernanceChecker.check()` is the machine-consumable API: deterministic, returns one exit code. `GovernanceReporter.report()` builds a richer structured dict for human review and integrations that need context — trust key lists, reconciliation record contents, emergency record payloads, audit chain entry count.

---

## Test coverage summary

**`tests/test_status.py`** (21 tests) — exit 0 (healthy), exit 51 (tampered chain, S-2), exit 51 ≠ 50, exit 51 skipped when log absent, exit 33 (unresolved B4), exit 33 not fired when resolved, exit 50 (overdue, no checkpoint), exit 0 (current checkpoint), exit 50 not fired without config, exit 20 (corrupt trust store, corrupt active pointer), exit 13 (no journal key), exit 10 (reconciliation gate), exit 11 (pending emergency review), exit 12 (staleness enforcement), reconciliation priority over staleness, reporter (all sections, summary, trust active_key_id, reconciliation gate, audit absent).

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
