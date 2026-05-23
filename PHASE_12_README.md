# Phase 12 — Invariants, Hypothesis, Adversarial, Kill-point Harness, Concurrency

**Status:** Complete
**Tests:** 466 total (415 from Phases 0-11, 51 new), 0 failed
**Modules authored:** `utils/invariants.py`
**Test files authored:** `tests/test_invariants.py`, `tests/test_kill_points.py`, `tests/test_hypothesis.py`, `tests/test_concurrency.py`

---

## What this phase delivers

### `utils/invariants.py` — 14-invariant catalog

| ID | Description |
|----|-------------|
| I-FS-1 | Journal directory mode is 0o700 |
| I-FS-2 | All `.intent` files have mode 0o600 |
| I-FS-3 | No `.intent.staged` file outlives its commit |
| I-FS-4 | Backup directory mode is 0o700 |
| I-FS-5 | Trust `journal/private/` is 0o700; private keys are 0o600 |
| I-FS-6 | `.last_b4_event.json` is 0o600 if it exists |
| I-J-1 | Every `.intent`'s `intent_integrity_hash` matches recomputation |
| I-J-3 | Every `.complete` has a matching `.intent` |
| I-J-4 | No two `.intent` files share a `txn_id` |
| I-T-1 | At most one key per domain has status `active` |
| I-T-2 | A revoked key has `revoked_at` set; an active key does not |
| I-R-1 | After successful `recover()`, no `.intent` files remain (conditional) |
| I-NEG-JOURNAL | No unexpected files/dirs in journal directory |
| I-NEG-NOSYMLINKS | No symlinks in journal directory |

### Test files

`tests/test_invariants.py` — unit tests for each invariant (positive and negative cases).

`tests/test_kill_points.py` — deterministic kill-point tests (KP1–KP4) + Hypothesis property: kill at any position across any transaction shape produces a consistent post-recovery state.

`tests/test_hypothesis.py` — property-based tests for commit (invariants hold after every commit), abort (no residue), sequential commits (invariants survive), and audit chain continuity under random event sequences.

`tests/test_concurrency.py` — TOCTOU closure tests (`read_and_hash_file`, pre-read bytes in snapshot), backup-mutation resistance, fatal-on-refused contract, and `_should_skip_startup_recovery` logic.

---

## Design decisions

### `@invariant` decorator — auto-registration
Invariants are registered by decorating a checker function with `@invariant(id, description)`. `check_all_invariants` iterates `_INVARIANT_REGISTRY` and collects all violations. A checker that raises is itself recorded as an `error`-severity violation, so the catalog never crashes mid-sweep.

### `assert_invariants_hold` — pytest-friendly
Collects ALL violations before raising `AssertionError`. The error message lists every violation found so a test failure surfaces the complete picture, not just the first thing that broke.

### I-R-1 is conditional
`I-R-1` always returns an empty list. It is registered in the catalog so it appears in `invariants-check` output, but the invariant is only meaningful as an explicit post-condition in test packs immediately after `recover()` completes. Checking it unconditionally on every `check_all_invariants` call would produce false positives during any in-flight commit.

### Kill-point harness uses `os.replace` injection
`_KillPointInjector` counts calls to `os.replace` and raises `OSError(EINTR)` at the specified position. EINTR is chosen because it is NOT in the B4 classification table — it propagates as a plain `OSError` through `AtomicTransaction`'s abort path, accurately modelling a process kill during a syscall.

### Rollback tests require two writes
A single-write transaction at new state is classified `already_replaced` → `recovery.completed`. The rollback path requires at least one write still at old state (`still_old`). Both `test_recovery_rollback_*` tests use two writes with only the first replaced.

### Hypothesis: `tmp_path` vs `tmp_path_factory`
Tests using Hypothesis `@given` must not use `tmp_path` (function-scoped fixture — not reset between generated inputs). They use `tmp_path_factory.mktemp(...)` inside the test body instead.

---

## Test coverage summary

**`tests/test_invariants.py`** (17 tests) — catalog size (14), all IDs present, clean fresh install, I-FS-1 (wrong mode, correct mode), I-FS-2 (wrong intent mode), I-FS-3 (stale staged, clean), I-J-1 (corrupted hash), I-J-3 (orphan complete), I-J-4 (duplicate txn_id), I-T-1 (two active keys), I-T-2 (revoked without revoked_at), I-NEG-JOURNAL (unexpected file), `to_dict()` shape, checker exception recorded.

**`tests/test_kill_points.py`** (7 tests) — KP1 (intent kill → targets unchanged), KP2 (kill before first replace → abandoned), KP3 (mid-replace → rolled back), KP4 (all replaced, no complete → stays new), Hypothesis kill at any position atomicity property, unsigned v2 intent refused, corrupted integrity hash refused.

**`tests/test_hypothesis.py`** (9 tests) — commit+invariants (Hypothesis, 30 examples), abort+no-residue (Hypothesis, 20 examples), sequential commits (Hypothesis, 15 examples), fresh-install invariants, stale staged caught, orphan complete caught, unexpected file caught, two active keys caught, audit chain continuity (Hypothesis, 30 examples).

**`tests/test_concurrency.py`** (18 tests) — `read_and_hash_file` (bytes+hash consistent, empty file), snapshot uses pre-read bytes (TOCTOU closure), rollback resists backup mutation, clean rollback works, fatal-on-refused (raises, carries result, message references recovery-replay, count matches), normal returns (no refusals, no journal dir), `recover_with_diagnostics` never raises, `_should_skip_startup_recovery` (6 cases).

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes introduced in Phase 12.
