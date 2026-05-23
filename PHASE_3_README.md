# Phase 3 — Audit Logger & FS Hardening

**Status:** Complete  
**Tests:** 126 total (70 from Phases 0-2, 56 new), 0 failed  
**Modules authored:** `audit/logger.py`, `audit/fs_hardening.py`

---

## What this phase delivers

| Module | Exports |
|--------|---------|
| `audit/logger.py` | `AuditLogger`, `AuditRecord`, `AuditError`, `AUDIT_ALLOWED_FIELDS`, `AUDIT_GENESIS_HASH`, `AUDIT_MAX_DETAILS_SIZE`, `AUDIT_FAILURE_ALLOWED_EVENT_PREFIX`, `_SERVICE_LABEL_RE` |
| `audit/fs_hardening.py` | `AuditFSHardener`, `AuditFSStatus`, `AuditHardeningError` |

---

## Design decisions

### `AuditRecord` — stdlib dataclass in `logger.py`
`AuditRecord` is a `@dataclass(slots=True)` defined in `audit/logger.py`. There is no
`models/` directory. Fields: `seq`, `timestamp`, `event_type`, `actor`, `outcome`,
`details`, `prev_hash`, `self_hash`. Two methods: `without_self_hash()` for hash
computation; `as_dict()` for serialization.

### Hash chain
`self_hash = SHA-256(canonical_JSON(record_without_self_hash))`. Each record's
`prev_hash` is the `self_hash` of the preceding record. The first record's
`prev_hash` is `AUDIT_GENESIS_HASH` (64 zero-hex-digits). This detects blind
tampering. It does not detect consistent rewrite — that is the "audit transparency"
future pass (KNOWN_LIMITS).

### `AUDIT_ALLOWED_FIELDS` — single frozenset
Defined once at module level as one frozenset. No per-version partitioning or
"vN additions" comments. 58 fields covering all governance domains.

### `sanitise_details()` — B-6 design (external review finding)
Two checks apply. Everything else passes through:

1. **Field-name check**: if the *key name* (lowercased) is in `_SECRET_FIELD_NAMES`
   (`password`, `secret`, `token`, `private_key`, `credential`, `api_key`, `secret_key`),
   raise `AuditError` immediately — before the allowlist filter.

2. **PEM-marker check**: if a string *value* contains a PEM private-key header
   (`BEGIN PRIVATE KEY`, `BEGIN RSA PRIVATE KEY`, etc.), raise `AuditError`.

Operator reason and justification text is **never** rejected on content. The named
regression: `{"reason": "Per password rotation policy"}` is accepted. Pre-v21 value-
content substring matching caused legitimate governance operations to fail after state
was already mutated, leaving the system inconsistent with no audit record.

### `failure` outcome scoping
`outcome="failure"` is only valid when `event_type` starts with `"recovery."`.
All other event types with `outcome="failure"` raise `AuditError`. Unknown outcome
values (not in `{"success", "failure", "warning", "info", "skipped"}`) also raise.

### Alert firing — after chain write, outside the lock
The alerter is imported lazily inside `log()` and invoked after the audit lock is
released. Any alerter exception is absorbed. Alerting must never block or corrupt
governance operations.

### `AuditFSHardener` — graceful degradation
When `chattr` or `lsattr` are absent (test environments, non-Linux), all chattr
operations return `False` (or raise `AuditHardeningError` with `strict=True`).
`status()` reports `append_only_supported=False`. `ensure_restrictive_permissions()`
always works — it only uses stdlib `os.chmod`.

---

## Invariants established in this phase

1. Every record's `prev_hash` equals the `self_hash` of its predecessor, or `AUDIT_GENESIS_HASH` for the first record.
2. `self_hash` is always recomputable from `without_self_hash()` using `compute_hash()`.
3. `sanitise_details()` never rejects operator reason/justification text on content.
4. `sanitise_details()` always rejects field names in `_SECRET_FIELD_NAMES`.
5. `sanitise_details()` always rejects PEM private-key material in string values.
6. `outcome="failure"` is only valid for `recovery.*` event types.
7. A failed `emit()` call due to bad details leaves the chain unchanged.
8. `AuditFSHardener` does not raise when `chattr`/`lsattr` are absent (non-strict).

---

## Test coverage summary

**`tests/test_audit_logger.py`** (45 tests) — hash chain, AuditRecord, sanitise_details (B-6, PEM, non-printable, types, size, service regex), outcome validation, emit resilience, allowlist completeness pins, LOCK_ORDER pin.

**`tests/test_audit_fs_hardening.py`** (11 tests) — permission creation/repair/idempotency, AuditLogger permission enforcement, chattr absent/failure graceful degradation, status reporting, harden() audit emission.

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
