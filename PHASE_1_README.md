# Phase 1 — Config & Paths

**Status:** Complete  
**Tests:** 36 passed, 0 failed  
**Modules authored:** `wpgovern/config.py`, `wpgovern/paths.py`

---

## What this phase delivers

- `config.py` — `WPGovernConfig` frozen dataclass, `DEFAULT_CONFIG` singleton
- `paths.py` — `Paths` frozen dataclass, `WPGovernPaths` alias, `build_paths()` factory
- `tests/test_config.py` — 14 tests
- `tests/test_paths.py` — 22 tests
- `tests/conftest.py` — minimal shared test configuration

---

## Design decisions

### `WPGovernConfig` — field grouping
Fields are grouped by logical domain with a single block comment per group.
No "vN:" prefixes anywhere. The groups are:

1. **Core filesystem paths** — `root_dir`, `install_dir`, `runtime_trust_store`,
   `release_trust_store`, `active_pointer`, `audit_log`
2. **Journal / crash-recovery** — `journal_staleness_warn_seconds` (default 3600),
   `journal_staleness_enforce_seconds` (default `None`)
3. **Audit alerting** — `alert_sinks`, `alert_extra_triggers` (both default `None`)
4. **Audit review checkpoint** — `review_max_age_days` (default `None`)

### `alert_sinks` and `alert_extra_triggers` — tuples, not lists
Both fields are `tuple[..., ...] | None` so they are hashable and safe inside a
frozen dataclass. The sink dict type uses `dict[str, Any]`; sink dicts are not
frozen (they come from operator config, not from governance operations).

### `alert_extra_triggers` extends, never reduces
Documented in the field docstring. The minimum safe trigger set lives in
`AuditAlerter` (Phase 9) and cannot be reduced by setting this field to a subset.

### `review_max_age_days = None` means no enforcement
Default config never enforces review age. Setting a value activates enforcement
(exit code 50 in `governance-check`, Phase 10). Documented in field docstring
and in KNOWN_LIMITS.

### `Paths` — three trust domains
All three trust domains (runtime, release, journal) have the same directory
convention: `trust/<domain>/private/` and `trust/<domain>/public/`. Each domain
exposes: `*_private_dir`, `*_public_dir`, `*_trust_store`, `*_active_private_key`.

### Alias properties — why they exist
Short aliases (`approvals`, `rollbacks`, `audit_log`, etc.) are retained for
CLI/shell-era compatibility. They are defined here once and nowhere else.
Every alias resolves to exactly the same `Path` object as its canonical
property — verified by tests.

### `build_paths(config)` — graceful fallback
If `config` has neither `root_dir` nor `root`, `build_paths()` returns
`Paths()` with the default root. This prevents `AttributeError` in bootstrap
paths where config may not yet exist.

### `WPGovernPaths = Paths` — alias, not a subclass
One assignment at module level. The alias is not a subclass, not a re-export —
it is literally `Paths`. `WPGovernPaths is Paths` is `True`. Verified by test.

---

## Invariants established in this phase

1. `WPGovernConfig` is frozen — no service or test can mutate it after construction.
2. All config field defaults are stable and match the v21 reference exactly.
3. `Paths` is frozen — all path properties are pure computations from `root`.
4. Every alias property returns the identical `Path` as its canonical counterpart.
5. `build_paths(x)` never raises for any of the four accepted input forms.
6. `WPGovernPaths is Paths` — the alias is not a separate class.
7. No `models/` directory exists. No Pydantic import anywhere.

---

## Test coverage

### `tests/test_config.py` (14 tests)

| Test | What it verifies |
|------|-----------------|
| `test_default_instantiation_succeeds` | `WPGovernConfig()` does not raise |
| `test_default_config_is_wpgovernconfig_instance` | `DEFAULT_CONFIG` type |
| `test_core_path_fields_are_path_instances` | all six core path fields are `Path` |
| `test_journal_staleness_warn_default_is_3600` | warn default = 3600 |
| `test_journal_staleness_enforce_default_is_none` | enforce default = None |
| `test_alert_sinks_default_is_none` | alerting default = None |
| `test_alert_extra_triggers_default_is_none` | triggers default = None |
| `test_review_max_age_days_default_is_none` | review default = None |
| `test_config_is_frozen` | mutation raises `FrozenInstanceError` |
| `test_config_accepts_custom_root_dir` | custom `root_dir` accepted |
| `test_journal_staleness_accepts_none_for_both_fields` | both None accepted |
| `test_alert_sinks_accepts_tuple_of_sink_dicts` | tuple[dict] accepted |
| `test_alert_extra_triggers_accepts_tuple_of_strings` | tuple[str] accepted |
| `test_review_max_age_days_accepts_positive_integer` | positive int accepted |

### `tests/test_paths.py` (22 tests)

| Test | What it verifies |
|------|-----------------|
| `test_default_paths_instantiates` | `Paths()` does not raise |
| `test_root_dir_alias_equals_root` | `root_dir == root` |
| `test_runtime_trust_store_under_runtime_public` | path composition |
| `test_release_trust_store_under_release_public` | path composition |
| `test_journal_trust_store_under_journal_public` | path composition |
| `test_active_pointer_under_state_dir` | path composition |
| `test_audit_log_alias_equals_audit` | alias identity |
| `test_approvals_alias_equals_approvals_dir` | alias identity |
| `test_rollbacks_alias_equals_state_rollbacks` | alias identity |
| `test_supersessions_alias_equals_state_supersessions` | alias identity |
| `test_emergency_alias_equals_state_emergency` | alias identity |
| `test_emergency_reviews_alias_equals_state_emergency_reviews` | alias identity |
| `test_reconciliation_alias_equals_state_reconciliation` | alias identity |
| `test_trust_runtime_private_alias_equals_runtime_private_dir` | alias identity |
| `test_trust_release_public_alias_equals_release_public_dir` | alias identity |
| `test_wpgovernpaths_is_paths_class` | `WPGovernPaths is Paths` |
| `test_build_paths_none_returns_default_paths` | None → default root |
| `test_build_paths_existing_paths_returns_same_object` | identity preservation |
| `test_build_paths_string_uses_as_root` | str → custom root |
| `test_build_paths_path_object_uses_as_root` | Path → custom root |
| `test_build_paths_config_uses_root_dir` | config.root_dir → custom root |
| `test_custom_root_propagates_to_all_derived_paths` | all paths under custom root |

---

## Running the tests

```bash
cd wpgovern_recon
pip install -e .
pytest tests/test_config.py tests/test_paths.py -v
# 36 passed
```

Full suite (Phase 0 + Phase 1):

```bash
pytest -v
# 36 passed
```

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
