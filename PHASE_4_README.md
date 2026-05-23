# Phase 4 — Journal & Recovery

**Status:** Complete  
**Tests:** 159 total (126 from Phases 0-3, 33 new), 0 failed  
**Modules authored:** `utils/journal.py`, `utils/recovery.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `utils/journal.py` | `JournalWriter`, `IntentRecord`, `IntentWrite`, `CompleteRecord`, `JOURNAL_SCHEMA_VERSION`, `JournalError`, `JournalSignatureError`, `VERIFY_*` constants, `compute_intent_integrity_hash`, `hash_file_bytes`, `read_and_hash_file`, `sign_intent_record`, `verify_intent_signature`, `sign_complete_record`, `verify_complete_signature`, `read_intent_record`, `read_complete_record`, `list_intent_records`, `list_complete_records` |
| `utils/recovery.py` | `RecoveryService`, `RecoveryResult`, `RecoveryOutcome`, `RecoveryError`, `RecoveryRefusedError` |

---

## Design decisions

### Schema versions

* `schema_version=1` — unsigned records. Written by pre-signing deploys. Normal recovery refuses v1 records — only `migrate-journal-v1-to-v2` acts on them.
* `schema_version=2` — signed records (current). `JOURNAL_SCHEMA_VERSION = 2`. Every `AtomicTransaction` with a `service_label` writes v2 records.

### Integrity model

`intent_integrity_hash` is SHA-256 of the canonical-JSON of the intent record excluding the hash and signature fields. Detects corruption and simple tamper attacks. The signature gate runs first in the recovery sequence; the integrity hash check is defense-in-depth after authentication.

`intent_signature` / `complete_signature` — ed25519 over the same canonical bytes. Recovery refuses on any signature failure with `service=None` (the record body is untrusted until the signature passes).

### Recovery sequence (per intent)

1. Read intent. Malformed → refuse (service=None).
2. Schema version check. v1 → refuse.
3. **Signature gate** — any failure → refuse (service=None; body untrusted).
4. Integrity hash check (defense-in-depth; service=intent.service after auth).
5. Complete record check: signature, txn_id binding, schema_version.
6. Classify writes: already_replaced / still_old / divergent.
7. Outcome: abandoned / completed (via complete record or kill-point-3 completion) / rolled_back / refused.

### Fatal-on-refused contract

`recover()` raises `RecoveryRefusedError` on any refusal — un-ignorable through control flow. `RecoveryRefusedError.result` carries the full `RecoveryResult`. `recover_with_diagnostics()` returns the result unconditionally — for operator tooling.

### Rollback all-or-nothing

`_roll_back_partial()` reads and verifies ALL backups before restoring any of them. A partial rollback (some targets at old state, others at new) is worse than a partial commit. Single-read per backup file closes the TOCTOU between hash verification and restore.

### Test isolation from Phase 5

Tests use `_FakeTrustService` — a minimal duck-type that generates real ed25519 key pairs via openssl. This tests actual journal signing/verification without depending on Phase 5's `TrustService`. The fake service provides: `lock_manager`, `verify_journal_trust()`, `active_private_key_path()`, `public_key_for_key_id()`, `key_status()`.

### Timestamp convention

Test fixtures use `started_at="2026-01-01T12:00:00Z"` (clearly in the past) to avoid the one-hour future-timestamp check in `_check_future_started_at()`.

---

## Invariants established in this phase

1. Intent records are written before any target file in the replace loop.
2. Complete records are written after all replaces succeed (or reconstructed by recovery).
3. Recovery refuses `schema_version != 2` records during normal startup.
4. Recovery refuses any intent whose signature does not verify against a known, non-revoked journal key.
5. Recovery refuses any intent whose content matches neither the old nor new hash (divergent).
6. `recover()` raises `RecoveryRefusedError` when any intent is refused — the contract is un-ignorable.
7. Rollback restores all targets atomically or none (all-or-nothing via verify-then-restore).
8. Audit emit failure does not block recovery — payload is written to `audit-emit-failures/`.

---

## Test coverage summary

**`tests/test_journal.py`** (17 tests) — intent format and integrity hash, integrity hash changes on field change, pre-set hash mismatch rejection, backup store (existing/first-write/disappear/fsync), complete record format, cleanup, file modes (0o600/0o700), record round-trip, schema_version=1 preserved on read, AtomicTransaction journal integration (with/without service_label, kill point 2).

**`tests/test_recovery.py`** (16 tests) — no-op (no dir / empty dir), abandoned, completed (complete record present / kill point 3), rolled_back, refused (divergent / unknown schema / tampered intent / v1 schema), `recover()` raises `RecoveryRefusedError`, result carries diagnostics, `recover_with_diagnostics()` never raises, orphan backup sweep, orphan complete sweep, audit emit failure fallback.

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
