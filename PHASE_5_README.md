# Phase 5 — Trust Domain & Signing

**Status:** Complete  
**Tests:** 208 total (159 from Phases 0-4, 49 new), 0 failed  
**Modules authored:** `core/trust.py`, `core/signing.py`, `core/actor.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `core/trust.py` | `TrustService`, `TrustError`, `TrustKeyRecord`, `TrustStore`, `TrustDomain`, `KeyStatus` |
| `core/signing.py` | `SigningService`, `VALID_VERIFY_STATUSES` |
| `core/actor.py` | `resolve_actor_context`, `MAX_ACTOR_FIELD_LEN` |

---

## Design decisions

### `TrustKeyRecord` and `TrustStore` — stdlib dataclasses in `trust.py`
Both are `@dataclass(slots=True)` defined in their owning module. There is no `models/` directory anywhere in this reconstruction.

### Three domains, one service
`TrustService` handles `"runtime"`, `"release"`, and `"journal"` using domain as a parameter. No subclassing. Domain-specific wrappers (`generate_runtime_key`, `activate_journal_key`, etc.) delegate to the three core methods (`generate_key`, `activate_key`, `revoke_key`).

### Release domain usage semantics
Active release keys use `["verify"]` usage; active runtime and journal keys use `["sign", "verify"]`. Enforced by `validate_store()` and set by `activate_key()`.

### `VALID_VERIFY_STATUSES = frozenset({"active", "retired_verify_only"})`
This is the fail-closed allow-list for verification. Any key status not in this set — including `"preactive"`, `"revoked"`, and any future unknown status — cannot verify a signature. There is no blocklist, no fallback, and no bypass.

### `active_private_key_path()` — FC-5 desync detection
Before returning the symlink-resolved path, cross-checks the symlink's stem (`<key_id>.pem`) against the trust store's `active_key_id`. A mismatch raises `TrustError` with a message directing the operator to re-run `trust-key-activate`. This detects the silent integrity failure that occurs when `activate_key` writes the JSON but is killed before updating the symlink.

### `validate_store()` runs after every mutation
`activate_key()` and `revoke_key()` both call `validate_store()` after committing the new store JSON. This means every mutation leaves the store in a verified-clean state.

### `resolve_actor_context()` — fallback, trim, validate
Falls back to `getpass.getuser()` when `actor_id` is `None` or whitespace-only. Trims all fields. Rejects values over `MAX_ACTOR_FIELD_LEN = 256` characters or containing non-printable characters (tab is accepted).

### Private key directory mode
`init_store()` explicitly sets `os.chmod(private_dir, 0o700)` on the private key directory. Without this, `mkdir` respects the process umask (typically 0o755), leaving private key material world-readable in the directory listing.

---

## Invariants established in this phase

1. Every trust store mutation leaves the store in a `validate_store()`-passing state.
2. `VALID_VERIFY_STATUSES` is exactly `{"active", "retired_verify_only"}` — immutable frozenset.
3. Any key in `"preactive"`, `"revoked"`, or any other status cannot verify signatures.
4. `active_private_key_path()` raises `TrustError` when the symlink and trust store disagree (FC-5).
5. Private key directories are mode 0o700.
6. The currently active key cannot be directly revoked.

---

## Test coverage summary

**`tests/test_trust.py`** (28 tests) — init per domain, correct store structure, private dir mode, generate preactive with correct usage, duplicate key_id rejection, activate (transition, retire previous, symlink update, rejects non-preactive), revoke (transition, clears usage, rejects active, rejects empty reason), `active_private_key_path` (happy path, symlink missing, FC-5 desync), `validate_store` (passes on healthy store, duplicate key_ids, missing active_key_id, invalid active usage), key_id validation (empty, path traversal, slash).

**`tests/test_signing.py`** (14 tests) — `VALID_VERIFY_STATUSES` completeness, sign+verify happy path, tampered file fails, revoked key fails, preactive key fails, retired_verify_only passes, missing artifact, missing sig, unknown key_id, `verify_active_pointer`, sign/verify release manifest.

**`tests/test_actor_identity.py`** (8 tests) — getuser fallback, whitespace trimming, explicit actor_id, whitespace-only returns None, too-long actor_id, non-printable in change_ticket, tab accepted in reason, complete dict shape.

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
