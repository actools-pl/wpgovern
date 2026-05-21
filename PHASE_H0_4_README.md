# Phase H.0.4 — Field-Membership Discrimination + I-CFG-1 Path Safety

**Status:** Complete  
**Tests:** 776 total (773 from v51.1, 3 new), 0 failed  
**CI Guards:** 10 (unchanged)  
**Invariants:** 29 (I-CFG-1 and I-CFG-2 strengthened in place)  
**Modules modified:** `wpgovern/status/checker.py`, `wpgovern/utils/invariants.py`, `wpgovern/core/baseline.py`  
**Test file modified:** `tests/test_h0_config_file_hashing.py` (3 new tests in integration class)

---

## Two High blockers closed

### H.0.4-1 — Field-absent vs field-present-null (High)

**The defect:** `dict.get("config_file_hashes")` returns `None` in two situations:

1. The field is absent entirely — this is a legacy v47 baseline (acceptable; skip enforcement)
2. The field is present with value `null` — this is a malformed H.0-era manifest (must be rejected)

`get()` cannot distinguish these. A signed baseline with `config_file_hashes: null` plus
tampered wp-config.php returned `exit 0, reason='ok'` under v51.1. Verified by PoC.

**The fix:** Replace `dict.get()` + `is None` check with `"key" in dict` membership check
at three call sites:

| Call site | File | Change |
|-----------|------|--------|
| `_evaluate_config_file_hashes` | `checker.py` | `if "config_file_hashes" not in active_baseline: return None` |
| `_i_cfg_2` | `invariants.py` | `if "config_file_hashes" not in payload: return violations` |
| `_parse_baseline` | `baseline.py` | `if "config_file_hashes" in payload: validate()  else: raw_hashes = None` |

Field-absent remains the ONLY legacy-baseline acceptance path. Field-present-with-null
flows through `_validate_config_file_hashes()`, which raises `BaselineError("must be a dict,
got NoneType")`. The caller's `BaselineError` catch routes to the invariant catalog → I-CFG-2
→ exit 21.

### H.0.4-2 — I-CFG-1 path-escape on absolute-path manifests (High)

**The defect:** I-CFG-1 iterated `config_file_hashes` directly without schema validation.
For a signed manifest with `{"/etc/hostname": "sha256:..."}`, the expression
`install_dir / "/etc/hostname"` resolves to `Path("/etc/hostname")` — Python's `Path`
operator discards the left operand when the right operand is an absolute path. I-CFG-1
then read `/etc/hostname` and computed its real hash, reporting the mismatch as a hash
drift violation (I-CFG-1 in reason, not I-CFG-2). Verified by PoC — `abs_path: /etc/hostname`
with real file hash in details.

**The fix:** I-CFG-1 now calls `_validate_config_file_hashes(raw_hashes, "active-baseline")`
before iterating. On `BaselineError`, returns empty violations (I-CFG-2 owns structural
reporting). After validation, every key is guaranteed to be a member of `CONFIG_FILE_PATHS`
— path-escape is impossible.

### H.0.4-3 — I-CFG-2 null manifest reported as NoneType (automatic)

After H.0.4-1's change, I-CFG-2 receives `None` as the raw value when the field is present
with null. `isinstance(None, dict)` is False — the existing non-dict check fires:

```python
violations.append(InvariantViolation(
    invariant_id="I-CFG-2",
    description="config_file_hashes must be a dict",
    details={"actual_type": "NoneType", "baseline_id": baseline_id},
))
```

No additional code change required. Verified by the new `test_i_cfg_2_reports_null_manifest_as_non_dict`.

---

## New tests

| Test | Closes | Adversarial variant |
|------|--------|-------------------|
| `test_check_rejects_signed_null_manifest_with_drift` | H.0.4-1 | Tamper + re-sign with `null` + governed file modified |
| `test_i_cfg_1_does_not_read_paths_from_malformed_manifest` | H.0.4-2 | Tamper + re-sign with absolute-path key; assert `I-CFG-1` NOT in reason |
| `test_i_cfg_2_reports_null_manifest_as_non_dict` | H.0.4-3 | Direct invariant call; assert `NoneType` in violation details |

The `test_i_cfg_1_does_not_read_paths_from_malformed_manifest` test uses the
**call-site discipline** introduced in v52: it verifies behavior at the specific invariant
site (`assert "I-CFG-1" not in result.reason`), not just the top-level exit code. This
prevents future regressions where schema discipline applies at one site but not another.

---

## Exit code reachability preserved

The dedicated config-file check (`_evaluate_config_file_hashes`) runs BEFORE the invariant
catalog in `GovernanceChecker.check()`. Exit codes 52 (hash mismatch) and 53 (file missing)
fire correctly for the common drift cases. I-CFG-1 in the invariant catalog catches drift
the dedicated check missed for any reason (defense in depth) — it does NOT shadow the 52/53
codes for the standard drift case.

This is verified by existing integration tests:
- `test_check_returns_52_when_config_file_modified`
- `test_check_returns_53_when_config_file_deleted`
- `test_check_returns_53_when_config_file_replaced_by_symlink`

The dedicated-check-first ordering was a deliberate design choice from H.0.1 hardening (v49).
v52 preserves it.

---

## Test count

| Suite | v51.1 | v52 |
|-------|-------|-----|
| Fast (no Hypothesis) | 757 | 760 |
| Full (with test extras) | 773 | 776 |
| CI guards | 10 | 10 |

---

*v52 is the canonical Python foundation. After external review, H.1 brief builds against v52.*
