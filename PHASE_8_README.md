# Phase 8 — Key Compromise & Trust Backup

**Status:** Complete
**Tests:** 291 total (268 from Phases 0-7, 23 new), 0 failed
**Modules authored:** `core/key_compromise.py`, `core/trust_backup.py`

---

## What this phase delivers

| Module | Primary exports |
|--------|----------------|
| `core/key_compromise.py` | `KeyCompromiseService`, `KeyCompromiseError`, `CompromiseResult` |
| `core/trust_backup.py` | `create_trust_backup`, `restore_trust_backup`, `TrustBackupError`, `_openssl_encrypt` |

---

## Design decisions

### KeyCompromiseService — no trust locks held during TrustService calls
`TrustService` acquires its own domain locks internally for each lifecycle step (generate/activate/revoke). `KeyCompromiseService` must **not** hold any trust-domain lock while calling these methods. `fcntl.flock` is per-open-file-description, not re-entrant — acquiring the same lock from two different `open()` calls on the same file in the same process deadlocks. The governance + artifact-re-sign locks are acquired **after** all three TrustService steps complete.

### Runtime vs release domains
The runtime compromise re-signs all active governance artifacts (active pointer, baselines, approvals, supersessions, rollbacks, emergency records, reconciliation records). The release compromise generates and activates the replacement key but does not re-sign governance artifacts — release keys are only used for release manifest verification, not runtime governance operations.

### Forensic report signed with the new key
The compromise report is written and then signed with the replacement (now active) key, not the compromised key. This anchors the report in the new trust chain.

### Partial failure recorded but does not abort
If one artifact fails to re-sign, the failure is recorded in `report.failed_artifacts` and the report `status` is `"completed_with_failures"`. Recovery continues. This is consistent with the KNOWN_LIMITS entry for S-7.

### KNOWN_LIMITS: S-7 (deferred)
Key-compromise partial failure can leave the key in a wrong state. If the process is killed between `generate_key` and `revoke_key`, the key state is inconsistent. This is the known deferred limitation documented in the phase plan KNOWN_LIMITS table.

### Passphrase newline rejection (B-5)
`_openssl_encrypt` rejects passphrases containing `\n`, `\r`, or NUL before calling openssl. `openssl enc -pass stdin` reads the passphrase up to the first newline — a passphrase like `"correct\nhorse"` silently uses only `"correct"` for key derivation, producing a weaker key without any error. Protection at the API level covers callers using the Python API directly, not only the CLI.

### Content validation on restore (S-9)
`_validate_restored_trust` checks each required trust store file for: parseable JSON, `type` field, `version` field, non-empty `keys` list, non-empty `active_key_id`, and all referenced public key files present on disk. A backup containing only `{}` passes existence checks but contains no usable key material; it is refused before the quarantine is released.

### Atomic restore: quarantine before replace
With `force=True`, `restore_trust_backup`:
1. Extracts to staging dir.
2. Validates content (`_validate_restored_trust`).
3. Renames live trust dir to quarantine.
4. Renames staged trust dir to live location.
5. On failure at step 4, restores from quarantine.
6. On success, removes quarantine.

This ensures the live trust material is always either at its original location or at the new location — never absent.

---

## Invariants established in this phase

1. `KeyCompromiseService` never holds trust-domain locks when calling `TrustService` lifecycle methods.
2. The forensic report is signed with the replacement (active) key, not the compromised key.
3. Partial re-sign failure does not abort the compromise protocol — it is recorded in the report.
4. Passphrases with `\n`, `\r`, or NUL are rejected before they reach openssl.
5. Empty or structurally deficient trust stores are refused before a restore commits.
6. A failed force-restore leaves the original trust material intact.

---

## Test coverage summary

**`tests/test_key_compromise.py`** (12 tests) — revokes compromised / activates replacement, store state verification, re-signs active pointer, writes and signs forensic report, identical key_ids rejected, missing key rejected, already-revoked rejected, empty reason rejected, partial failure recorded in report, release domain (no artifact re-sign), audit record emitted.

**`tests/test_trust_backup.py`** (13 tests) — encrypted file with metadata, missing trust dir raises, passphrase with `\n` rejected (B-5), NUL byte rejected (B-5), clean passphrase accepted (B-5 green path), round-trip restore, wrong passphrase, refuses without force, force replaces, path traversal rejected, empty JSON stores refused (S-9), incomplete backup refused, atomic restore atomicity (failure restores original).

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." S-7 (key-compromise partial failure) remains deferred.
