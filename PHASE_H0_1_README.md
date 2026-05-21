# Phase H.0.1 — v48 Wiring Fix and Hardening

**Status:** Complete  
**Tests:** 766 total (749 from v48, 17 new), 0 failed  
**CI Guards:** 10 total (9 from v48, 1 new)  
**Modules modified:** `wpgovern/status/checker.py`, `wpgovern/core/baseline.py`, `wpgovern/utils/invariants.py`  
**Test file extended:** `tests/test_h0_config_file_hashing.py`  
**CI guard added:** `test_h0_has_integration_tests_for_governance_check`

---

## Purpose

External review of v48 surfaced a deployment-blocking defect: the config-file hash check introduced in H.0 does not fire end-to-end, despite all unit tests passing. Two interlocking wiring bugs:

1. `_evaluate_config_file_hashes` was passed the active pointer payload (`{baseline_id, activated_at, …}`) which never contains `config_file_hashes`. It always saw `hashes=None` and silently returned clean.

2. Even if the pointer bug were fixed, I-CFG-1 in the invariant catalog runs at Step 8.5 — before the dedicated config-file check at Step 8.6. On a fully-bootstrapped system I-CFG-1 fires first and returns generic exit 21, making dedicated exit codes 52/53 unreachable.

H.0.1 closes both halves plus three additional hardening items.

---

## What was closed

### H.0.1-1 — `_read_active_baseline_record_payload` (checker.py)

New helper added alongside existing `_read_active_baseline_payload`. Unlike the pointer-reading version, this method follows the pointer to `baselines_dir/{baseline_id}.json` and returns the full baseline record payload — including `config_file_hashes`. Used in Step 8.5 for the dedicated config-file check.

### H.0.1-2 — Step 8.5 / Step 8.6 reorder (checker.py)

Dedicated config-file check (→ exit 52/53) moved to Step 8.5, firing BEFORE the generic invariant catalog (Step 8.6, was Step 8.5). Rationale: dedicated exit codes exist to give monitoring/alerting a granular signal; routing through exit 21 defeats the design. I-CFG-1 remains in the catalog for diagnostic use by callers that invoke `check_all_invariants()` directly.

### H.0.1-3 — Symlink refusal at compute and check time

`_compute_config_file_hashes` (baseline.py): symlink check fires before `exists()` / `is_file()` (both follow symlinks). A symlink at a governed path raises `BaselineError("… is a symlink … refused")`.

`_evaluate_config_file_hashes` (checker.py): if a regular file was replaced by a symlink post-baseline, returns `(53, "config_file_replaced_by_symlink:…")`.

### H.0.1-4 — Closed-set validator replaces regex (baseline.py + invariants.py)

`_validate_relative_path` now checks `rel_path not in CONFIG_FILE_PATHS`. Automatically refuses absolute paths, traversal sequences, Windows backslashes, NUL bytes, empty strings. `_TRAVERSAL_PATTERN` regex removed. I-CFG-2 invariant description updated to "config_file_hashes keys are members of CONFIG_FILE_PATHS".

### H.0.1-5 — Clearer install_dir-missing diagnostic (baseline.py)

`_compute_config_file_hashes` pre-checks `install_dir.exists()` and `install_dir.is_dir()` with specific error messages before iterating files. Operator no longer sees "config file missing" when the real problem is a missing install directory.

---

## New tests (17)

| Class / function | Count | What it verifies |
|---|---:|---|
| `TestGovernanceCheckConfigHashIntegration` | 6 | End-to-end through real `GovernanceChecker.check()` including the ordering fix (52 not 21) and legacy baseline case |
| `TestSymlinkRefusal` | 3 | Symlink at config path → BaselineError; regular file OK; symlink outside install_dir → BaselineError |
| `TestValidatorTightening` | 5 | Closed-set: canonical paths accepted; Windows backslash, NUL byte, empty string, arbitrary relative path refused |
| `TestInstallDirDiagnostic` | 2 | Missing install_dir → clear error naming install_dir; file-as-install_dir → clear error |
| `test_h0_has_integration_tests_for_governance_check` (CI guard) | 1 | Integration test class exists and calls `.check()` |

The canonical test for H.0.1 is `test_check_returns_52_not_21_when_config_hash_mismatch`. If it returns 52, the ordering fix is correct. If it returns 21, the ordering hasn't been applied.

---

## Test count

| Suite | v48 | v49 |
|-------|-----|-----|
| Fast (no Hypothesis) | 733 | 750 |
| Full (with test extras) | 749 | 766 |
| CI guards | 9 | 10 |

---

## What is not in H.0.1 scope

Per brief Section 3:
- wp-content hashing — still delegated
- H0.7 diagnostic detail (mtime/size) — deferred to operational experience
- Autouse fixture scope — addressed by integration tests, not fixture change
- R4 broader fix — still deferred
- Removing I-CFG-1 from the catalog — I-CFG-1 stays; ordering is the fix

---

*v49 is the canonical Python foundation for the bash arc. H.1 (bash installer skeleton) builds on this codebase.*
