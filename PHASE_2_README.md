# Phase 2 — Utility Layer

**Status:** Complete  
**Tests:** 70 total (36 from Phase 1, 34 new), 0 failed  
**Modules authored:** `utils/time.py`, `utils/fs.py`, `utils/jsonio.py`, `utils/locking.py`, `utils/transaction.py`

---

## What this phase delivers

Five utility modules that every subsequent phase depends on.

| Module | Exports |
|--------|---------|
| `utils/time.py` | `utc_now_iso()` |
| `utils/fs.py` | `ensure_parent()` |
| `utils/jsonio.py` | `read_json()` |
| `utils/locking.py` | `LockManager`, `LockHandle`, `LockError`, `LockTimeoutError`, `LOCK_ORDER` |
| `utils/transaction.py` | `AtomicTransaction`, `TransactionError`, `StagedWrite` |

---

## Design decisions

### `utc_now_iso()` — seconds precision, Z suffix
Format: `YYYY-MM-DDTHH:MM:SSZ`. All governance timestamps use this format so
audit log entries and JSON payloads are consistently sortable without parsing.

### `read_json()` — wraps JSONDecodeError as ValidationError
Callers catching `WPGovernError` see malformed-JSON errors the same way they
see other validation failures. `FileNotFoundError` propagates unwrapped — it
is a different condition (missing artifact vs corrupt artifact).

### `LOCK_ORDER` — canonical acquisition order
Eleven lock names in a fixed order. `acquire_many()` always sorts to this
order regardless of caller-specified order. No call site should ever nest
`acquire()` calls manually — always use `acquire_many()`.

KNOWN_LIMITS: `fcntl.flock` is advisory and not NFS-safe.

### `AtomicTransaction` — kill-point safe, three modes
1. **No journal** (`service_label=None`): plain stage-then-replace. No
   journal records written.
2. **Journal-enabled** (`service_label=...`, `trust_service=...`): writes a
   signed intent record before the replace loop and a signed complete record
   after. Recovery handles partial commits at next startup.

Construction with `service_label` but without `trust_service` raises
`ValueError` immediately — not at commit time. This prevents unsigned journal
records that recovery would later refuse.

### B4 preflight in `AtomicTransaction.commit()`
Before any I/O, `_b4_preflight()` checks that target parent directories are
writable and that the journal volume has ≥10 MB free. Errors surface with
`phase="preflight"` so operators see the condition before any state is written.

### `TransactionError` lives in `utils/transaction`, not `errors.py`
The error hierarchy in `errors.py` covers governance-level failures. 
`TransactionError` is a transaction-layer implementation detail — it extends
`WPGovernError` so wide handlers still catch it.

---

## Invariants established in this phase

1. `utc_now_iso()` always returns a 20-character `YYYY-MM-DDTHH:MM:SSZ` string.
2. `read_json()` raises `ValidationError` on malformed JSON; never returns partial data.
3. All locks are acquired in `LOCK_ORDER` regardless of caller-specified order.
4. `AtomicTransaction` with `service_label` requires `trust_service` at construction.
5. An `AtomicTransaction` that exits without `commit()` leaves all targets unchanged.
6. A committed `AtomicTransaction`'s staging directory is always removed on exit.

---

## Test coverage

**`tests/test_locking.py`** (14 tests)

| Test | What it verifies |
|------|-----------------|
| `test_lock_manager_creates_locks_dir_on_construction` | dir creation |
| `test_acquire_returns_lock_handle` | handle type and name |
| `test_acquire_releases_lock_on_context_exit` | re-acquirable after exit |
| `test_acquire_many_holds_all_locks_inside_block` | all handles present |
| `test_acquire_many_deduplicates_repeated_names` | one handle per unique name |
| `test_acquire_many_returns_handles_in_lock_order` | canonical ordering |
| `test_acquire_many_releases_all_locks_on_exit` | all re-acquirable after exit |
| `test_validate_lock_name_rejects_empty_string` | empty name → LockError |
| `test_validate_lock_name_rejects_forward_slash` | path traversal → LockError |
| `test_validate_lock_name_rejects_double_dot` | path traversal → LockError |
| `test_validate_lock_name_rejects_backslash` | path traversal → LockError |
| `test_sorted_lock_names_rejects_unknown_name` | unknown → LockError |
| `test_sorted_lock_names_returns_known_names_in_order` | canonical sort |
| `test_acquire_timeout_raises_locktimeouterror` | contention → timeout |

**`tests/test_transaction.py`** (9 tests)

| Test | What it verifies |
|------|-----------------|
| `test_commit_writes_all_staged_json_files_to_targets` | happy path, two files |
| `test_commit_writes_staged_text_file_to_target` | stage_text happy path |
| `test_committed_file_has_restrictive_mode` | mode=0o600 preserved |
| `test_abort_on_exception_preserves_existing_target` | rollback on raise |
| `test_context_exit_without_commit_aborts_and_leaves_target_unchanged` | implicit abort |
| `test_staging_write_failure_preserves_existing_target` | fail before commit |
| `test_commit_failure_cleans_staging_and_raises_transaction_error` | os.replace fail |
| `test_double_commit_raises_transaction_error` | closed guard |
| `test_service_label_without_trust_service_raises_value_error` | construction guard |

**`tests/test_fs_utils.py`** (11 tests)

| Test | What it verifies |
|------|-----------------|
| `test_ensure_parent_creates_missing_parent_directory` | deep mkdir |
| `test_ensure_parent_is_idempotent_when_parent_exists` | no error if exists |
| `test_ensure_parent_accepts_string_path` | str accepted |
| `test_read_json_returns_parsed_dict` | dict payload |
| `test_read_json_returns_parsed_list` | list payload |
| `test_read_json_raises_validation_error_on_malformed_json` | bad JSON |
| `test_read_json_raises_file_not_found_for_missing_file` | missing file |
| `test_utc_now_iso_returns_string` | type check |
| `test_utc_now_iso_ends_with_z` | UTC marker |
| `test_utc_now_iso_is_parseable_by_fromisoformat` | parseable |
| `test_utc_now_iso_format_is_seconds_precision` | 20-char format |

---

## Running the tests

```bash
cd wpgovern_recon
pip install -e .
pytest tests/test_locking.py tests/test_transaction.py tests/test_fs_utils.py -v
# 34 passed

pytest -v
# 70 passed (includes Phase 0 + 1)
```

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
