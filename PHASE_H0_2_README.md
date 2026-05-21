# Phase H.0.2 — Invariant Gate + Signature Verification Hardening

**Status:** Complete  
**Tests:** 768 total (766 from v49, 2 new), 0 failed  
**CI Guards:** 10 total (unchanged; one fixed)  
**Invariants:** 29 (unchanged)  
**Modules modified:** `wpgovern/status/checker.py`, `wpgovern/utils/invariants.py`  
**Test files modified:** `tests/test_h0_config_file_hashing.py`, `tests/test_ci_guards.py`

---

## Two interlocking integrity gaps closed

### H.0.2-1 — Invariant catalog gate path mismatch (High)

**The defect:** `GovernanceChecker.check()` decided whether to run the invariant
catalog using:

```python
trust_dir = self.config.root_dir / "trust"
active_ptr = self.config.active_pointer   # ← hardcoded /opt/wpgovern/state/active.json
```

But `BaselineService.activate()` writes the active pointer using
`self.paths.active_pointer` — derived from `root_dir` via `build_paths(config)`.
Under `root_dir` override (the standard test pattern and non-default installation
pattern), these two paths diverge. `active_ptr.is_file()` evaluates to False
(the hardcoded `/opt/…` path doesn't exist), the gate is silently skipped, and
the entire invariant catalog — including I-CFG-1 — never runs.

The same mismatch existed in I-CFG-1 and I-CFG-2 in `invariants.py`.

**The fix:**

```python
# checker.py — invariant gate
trust_dir = self.paths.root / "trust"
active_ptr = self.paths.active_pointer     # ← derived from root_dir

# invariants.py — I-CFG-1 and I-CFG-2
from wpgovern.paths import build_paths
_paths = build_paths(config)
active_ptr = _paths.active_pointer         # ← derived from root_dir
```

**Confirmed by PoC:** Direct modification of v49 code with `root_dir` override
+ active baseline present returns exit 0. After fix, the invariant catalog runs
and violations are caught.

### H.0.2-2 — Active baseline signature not verified (Medium-High)

**The defect:** `_read_active_baseline_record_payload()` read the baseline record
JSON via `_safe_read_json()` without verifying its signature. The config-file
hash check (which runs before the invariant catalog since H.0.1) trusts whatever
JSON the file contains. A tampered baseline with malicious `config_file_hashes`
produces exit 52 (config drift report) while masking the more fundamental
governance artifact integrity failure.

**The fix:** Added signature verification before returning the record:

```python
from wpgovern.errors import IntegrityError
try:
    self.signing.verify_file(baseline_path, domain="runtime")
except IntegrityError:
    return None   # caller skips hash check; invariant catalog runs next
```

When verification fails, `_read_active_baseline_record_payload` returns None.
The dedicated config-file hash check skips (no record → no hashes to compare).
The invariant catalog runs next with the appropriate exit code class.

**Exit code classification preserved:** Integrity failures get exit 20/21;
config drift gets 52/53. The two classes don't conflate.

---

## Three test changes

### H.0.2-3a — Strengthened: `test_check_returns_52_not_21_when_config_hash_mismatch`

Added explicit gate-reachability assertions before the ordering claim:

```python
trust_dir = paths.root / "trust"
assert trust_dir.is_dir(), "invariant gate setup invalid: trust_dir does not exist"
assert paths.active_pointer.is_file(), "invariant gate setup invalid: active_pointer does not exist"
```

Before H.0.2-1, these assertions would fail — exposing the false-positive guard
pattern where the test claimed to verify ordering but the gate was never reached.

### H.0.2-3b — New: `test_check_does_not_return_0_when_active_baseline_tampered`

Adversarial setup per Methodology Note 2: modifies baseline JSON on disk without
re-signing. Asserts exit code ≠ 52 (tampered baseline must not be classified as
config drift). Permanent regression coverage for the misclassification defect class.

### H.0.2-3c — New: `test_invariant_gate_uses_derived_paths_not_config_default`

Explicit regression for the path source-of-truth. Uses the `root_dir`-override
pattern to exercise the divergence case — skips if `cfg.active_pointer ==
paths.active_pointer` (same-path environments). Modifies a config file and asserts
exit code ≠ 0 (invariant catalog must be reached).

### H.0.2-4 — Fixed: `test_readme_test_counts_consistent`

Added `returncode` checks on both subprocess calls. Calls `pytest.fail()` with
a clear diagnostic when collection fails (e.g., missing test extras), instead of
misreporting the failure as stale README counts.

---

## What remains deferred

### H.0.3 closure note (added post-v50 external review)

The original v50 scope note stated that I-B-1 and I-B-2 in `invariants.py`
"still use `config.active_pointer`" and "may silently skip under `root_dir`
override." External review and direct PoC confirmed this was inaccurate:

- I-B-1 uses `config.root_dir / "baselines"` — root-aware, not hardcoded.
- I-B-2 uses `config.root_dir / "state" / "active.json"` — root-aware.

Under `root_dir` override, both invariants DO run and DO catch the
tamper-without-resigning case. The standard tamper scenario (modify active
baseline JSON without re-signing) returns exit 21 with I-B-1 and I-B-2
violations — not exit 0 as the original note feared.

Reference: see test
`test_check_returns_21_when_active_baseline_tampered_without_resigning`
in `tests/test_h0_config_file_hashing.py`.

### Still deferred per brief Section 3

- **Removing `WPGovernConfig.active_pointer`** — marked as informational/legacy;
  R4 broader fix scope.
- **Stale "Check order" docstring** in `checker.py` — future docs pass.
- **wp-content hashing** — still delegated per v1.1.

---

## Test count

| Suite | v49 | v50 |
|-------|-----|-----|
| Fast (no Hypothesis) | 750 | 752 |
| Full (with test extras) | 766 | 768 |
| CI guards | 10 | 10 |

---

*v50 is the canonical Python foundation. H.1 brief builds against v50.*
