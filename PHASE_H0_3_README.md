# Phase H.0.3 — Schema Validation + Missing-Sidecar Hardening

**Status:** Complete  
**Tests:** 773 total (768 from v50, 5 new), 0 failed  
**CI Guards:** 10 (unchanged)  
**Invariants:** 29 (I-CFG-2 strengthened in place)  
**Modules modified:** `wpgovern/status/checker.py`, `wpgovern/core/baseline.py`, `wpgovern/utils/invariants.py`  
**Test file modified:** `tests/test_h0_config_file_hashing.py` (1 renamed+strengthened, 5 new)  
**README corrected:** `PHASE_H0_2_README.md`

---

## Three integrity gaps closed

All three were verified by direct PoC against v50 code before this fix.

### H.0.3-1 — Missing sidecar crashes governance-check (Medium-High)

**The defect:** `_read_active_baseline_record_payload()` caught only `IntegrityError`.
`SigningService.verify_file()` raises `NotFoundError` when the `.sig.json` sidecar
is missing. Result: crash with unhandled exception instead of deterministic exit code.

**The fix:** `except (IntegrityError, NotFoundError)` — both treated as
"verification failure." Missing sidecar produces exit 21 (I-B-1 fires) instead
of a crash.

### H.0.3-2 — Signed manifest with absolute-path key inspects arbitrary paths (High)

**The defect:** `_evaluate_config_file_hashes()` iterated the raw `hashes` dict
directly. `Path(install_dir) / "/etc/passwd"` → `Path("/etc/passwd")` (Python
discards the left operand when the right operand is absolute). A signed-but-
malformed manifest with `{"/etc/passwd": "sha256:..."}` caused governance-check
to inspect `/etc/passwd` and return exit 52 (config drift) or exit 0, not a
schema violation.

**The fix:** Schema-validate via `_validate_config_file_hashes()` before iterating.
`BaselineError` on any schema problem → return None → invariant catalog → I-CFG-2
→ exit 21. The iteration now uses `validated.items()` not `hashes.items()`.

### H.0.3-3 — Signed empty/partial/non-dict manifests silently bypass checks (High)

**Three PoC-verified variants:**
- `config_file_hashes={}` → exit 0 (empty dict is falsy, `if not hashes` skipped)
- Partial manifest (only Caddyfile) + wp-config.php tamper → exit 0 (omitted files
  not checked)
- `config_file_hashes=[]` → exit 0 (list, not dict, fell through as "legacy")

**The fix:** `hashes is None` (field truly absent) → legacy skip. Any other shape
goes through `_validate_config_file_hashes()` which now enforces exact-set equality:
`set(hashes.keys()) == set(CONFIG_FILE_PATHS)`. Applied at both:
- Load time (`_validate_config_file_hashes` in `baseline.py`)
- Check time (`_evaluate_config_file_hashes` in `checker.py` — defense in depth)

---

## I-CFG-2 strengthened (H.0.3-4)

I-CFG-2 now explicitly reports:

| Shape | Reported as |
|-------|------------|
| Field is None (absent) | No violation (legacy baseline) |
| Field is not a dict (list, str, etc.) | `config_file_hashes must be a dict` + return |
| Key set ≠ CONFIG_FILE_PATHS | `key set does not match CONFIG_FILE_PATHS` with missing/extra |
| Entry type not str→str | `entry has non-string type` |
| Value not sha256:<hex> | `value is not a valid sha256:<hex> digest` |

Each as a separate `InvariantViolation` so the catalog output identifies every
structural problem, not just the first one encountered.

---

## Test changes

### Renamed + strengthened: `test_check_returns_21_when_active_baseline_tampered_without_resigning`

Previously `test_check_does_not_return_0_when_active_baseline_tampered`, asserting
`exit_code != 52`. Renamed and strengthened to assert `exit_code == 21` with
I-B-1 or I-B-2 in reason — reflecting verified behavior per PoC [4].

### Five new regression tests in `TestGovernanceCheckConfigHashIntegration`

| Test | Closes | Adversarial variant |
|------|--------|-------------------|
| `test_check_handles_missing_signature_sidecar_deterministically` | H.0.3-1 | Delete sidecar |
| `test_check_rejects_signed_absolute_path_manifest` | H.0.3-2 | Tamper + re-sign with absolute path |
| `test_check_rejects_signed_empty_manifest` | H.0.3-3 | Tamper + re-sign with `{}` |
| `test_check_rejects_signed_partial_manifest` | H.0.3-3 | Tamper + re-sign with partial set |
| `test_check_rejects_signed_non_dict_manifest` | H.0.3-3 | Tamper + re-sign with `[]` |

The "tamper AND re-sign" pattern is now permanently captured in three tests.
This catches schema-validation gaps that the "tamper without re-sign" pattern
(v49's PoC discipline) misses. Methodology Note 2 is now encoded at two
adversarial-setup variants.

---

## README correction (H.0.3-5b)

`PHASE_H0_2_README.md` inaccurately stated that I-B-1 and I-B-2 "still use
`config.active_pointer`" and "may silently skip under `root_dir` override."
Corrected to reflect verified behavior: both invariants are root-aware and
DO catch the tamper-without-resigning case.

---

## Test count

| Suite | v50 | v51 |
|-------|-----|-----|
| Fast (no Hypothesis) | 752 | 757 |
| Full (with test extras) | 768 | 773 |
| CI guards | 10 | 10 |

---

*v51 is the canonical Python foundation. After external review, H.1 brief builds against v51.*
