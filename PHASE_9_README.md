# Phase 9 — Audit Verifier & Alerter

**Status:** Complete
**Tests:** 342 total (291 from Phases 0-8, 51 new), 0 failed
**Modules authored:** `audit/verifier.py`, `audit/alerter.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `audit/verifier.py` | `AuditVerifier`, `AuditVerificationResult`, `AuditReviewWindow`, `AUDIT_GENESIS_HASH`, `REVIEW_HIGHLIGHT_EVENT_TYPES` |
| `audit/alerter.py` | `AuditAlerter`, `alerter_from_config`, `BUILTIN_ALERT_TRIGGERS`, `BUILTIN_ALERT_PREFIXES`, `_should_alert` |

---

## Design decisions

### `AuditVerifier.verify()` — full chain, every record
Iterates the entire log once. For every non-empty line: checks `seq` continuity, `prev_hash` linkage against the previous record's `self_hash`, and re-derives `self_hash` from the record body (with `self_hash` excluded from the hash input). All errors are collected before raising `IntegrityError` so a single verify() call surfaces every violation, not just the first.

### `AuditVerifier.review_window()` — verifies both links AND self_hash in-window
The window covers records from the last checkpoint's `self_hash` to the log head (or the full log if no checkpoint exists). For every in-window record, verifies:
1. `prev_hash` continuity (chain link intact).
2. `self_hash` recomputation (record body not tampered).

This means a tampered record whose `prev_hash` was updated to preserve continuity is still detected via the `self_hash` mismatch. A checkpoint written over a tampered window would incorrectly attest to a clean period — the double-check prevents this.

### `BUILTIN_ALERT_TRIGGERS` is a `frozenset` — immutable by construction
The minimum safe set cannot be reduced by operator configuration. `alerter_from_config` builds on top of it; `extra_triggers` are additive only. A test pins the exact type and verifies that set-difference operations on the frozenset return a new set without mutating the original.

### `BUILTIN_ALERT_PREFIXES` catches subtypes
Any event whose `event_type` starts with `"breakglass."`, `"key-compromise"`, `"recovery.stuck"`, or `"recovery.refused"` fires an alert regardless of whether it's in the exact-match trigger set. This covers future `breakglass.*` subtypes without requiring store updates.

### Alert delivery is best-effort — never blocks governance
Every `maybe_alert()` call wraps per-sink delivery in `try/except`. A failing webhook, a full disk on the file sink, or a missing syslog module all produce a warning log entry and nothing else. The audit chain record is already written before `maybe_alert()` is called.

### `alerter_from_config()` converts tuple → list
`WPGovernConfig.alert_sinks` is stored as a tuple (frozen field). `AuditAlerter` expects a list. The factory converts before passing to the constructor.

---

## Invariants established in this phase

1. `AuditVerifier.verify()` checks `seq`, `prev_hash`, and `self_hash` for every record.
2. `review_window()` verifies both link continuity and hash recomputation inside the window — a tampered record is detected even if chain links were updated to preserve continuity.
3. `BUILTIN_ALERT_TRIGGERS` is a frozenset and cannot be mutated.
4. `extra_triggers` is purely additive — it cannot suppress any built-in trigger.
5. Alert delivery failure never raises to the caller and never breaks the audit chain.

---

## Test coverage summary

**`tests/test_audit_verifier.py`** (19 tests) — `AUDIT_GENESIS_HASH` value, `REVIEW_HIGHLIGHT_EVENT_TYPES` type and contents, `verify()` (intact chain, missing log, tampered record, seq gap, broken prev_hash), `last_checkpoint()` (absent log, no checkpoint in log, returns most recent of multiple), `review_window()` (full log without checkpoint, records after last checkpoint, empty when log absent, highlighted list, tampered record in window, broken prev_hash in window).

**`tests/test_alerter.py`** (32 tests) — `BUILTIN_ALERT_TRIGGERS` is frozenset, cannot be reduced, all built-in triggers fire (parametrized over all 14), non-trigger events do not fire (parametrized), prefix matching, extra_triggers extend, extra_triggers cannot suppress built-in, none sink, file sink (correct fields, appends), webhook failure does not raise, `alerter_from_config` (sinks + extra, defaults to stderr), alert payload carries hash, alert fires after chain write, non-trigger event does not fire, alerter failure does not break chain.

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
