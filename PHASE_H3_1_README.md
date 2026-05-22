# Phase H.3.1 — H.3 Hardening Pass

**Status:** Complete  
**Bats tests:** 198 (was 189; +9 new)  
**Python tests:** 776 (unchanged)  
**New bash file:** `core/credentials.sh`  
**Modified files:** `wpgovern-install.sh`, `modules/stack/credentials.sh`, `modules/db/credentials.sh`, `modules/db/wait.sh`, `modules/db/users.sh`, 6 bats test files

---

## Context

H.3 closed the credentials-not-in-logs guarantee in normal shell mode. Seven blockers escaped, identified during external review. Two trace to brief-authorship gaps; five are implementation/test discipline gaps.

---

## Ten items closed

### H.3.1-1 — Cross-phase resumability crash (High)

**Defect:** `_wpgovern_credentials_persist` was defined in `modules/stack/credentials.sh`, which is only sourced inside the `if ! phase_complete "stack"` block. Running the db phase on a fresh run (with host+stack already complete) caused `command not found: _wpgovern_credentials_persist` → rc=127.

**Fix:** Extracted to `core/credentials.sh`. Sourced unconditionally immediately after `core/state.sh` in the entry script. Available across ALL phase boundaries with no conditional logic.

**Brief-authorship note:** The H.3 brief said "reuse the existing helper" without addressing how it becomes available cross-phase. The correct brief discipline: when specifying cross-module reuse, specify the loading path too.

### H.3.1-2 — Credentials leak under `set -x` / xtrace (High)

**Defect:** `bash -x` or inherited xtrace prints expanded commands before execution — including `-p"$SENTINEL"` in every `docker compose exec ... mariadb -uroot -p"$PW" ...`. Two sentinel matches on stderr per mariadb invocation.

**Fix:** `_wpgovern_disable_xtrace_for_credentials()` in `core/credentials.sh`. Uses `case "$-" in *x*)` to detect xtrace. Logs a non-secret WARNING then `set +x`. Applied at the top of every credential-sensitive function: `wait_for_ready`, `ensure_backup_password`, `generate_age_key`, `encrypt_state`, `verify_application_user`, `create_backup_user`, `stack::credentials::ensure`.

**Design decision:** fail-soft (warn + disable), not fail-closed. Operators debugging with `bash -x` should still be able to run the installer. The warning is non-secret.

### H.3.1-3 — Existing wpbackup trusted without privilege verification (High)

**Defect:** idempotency check only confirmed existence (`SELECT 1 FROM mysql.user`). An existing wpbackup with wrong privileges (or dangerous ones like `ALL PRIVILEGES`, `SUPER`) was silently skipped.

**Fix:** `_wpgovern_db_verify_backup_grants()` calls `SHOW GRANTS FOR 'wpbackup'@'%'` and checks: required grants present (REPLICATION CLIENT, PROCESS, SELECT, LOCK TABLES on wordpress.*) AND forbidden grants absent (ALL PRIVILEGES, GRANT OPTION, SUPER, FILE, RELOAD, SHUTDOWN, CREATE ROUTINE, ALTER). Fails closed on either condition.

### H.3.1-4 — Backup user grant broader than least privilege (Medium-High)

**Brief-authorship note:** The H.3 brief specified privileges by name without specifying scope. Implementation defaulted to `ON *.*` for all four privileges.

**Fix:** Split grant statements:
```sql
GRANT REPLICATION CLIENT, PROCESS ON *.* TO 'wpbackup'@'%';
GRANT SELECT, LOCK TABLES ON `wordpress`.* TO 'wpbackup'@'%';
```
Operational privileges (`REPLICATION CLIENT`, `PROCESS`) are global by nature. Data access privileges (`SELECT`, `LOCK TABLES`) are scoped to `wordpress.*`.

### H.3.1-5 — Entry-script DB integration test used no-op stubs (Medium-High)

The H.3.1-1 crash escaped because the integration test replaced real modules with `{ return 0; }` stubs. Fixed by H.3.1-1 (cross-phase resumability test uses real db modules) and H.3.1-2 (xtrace test also uses real modules).

### H.3.1-6 — CI guard passable with `|| true` (Medium)

**Defect:** All function calls in the CI guard used `|| true` — the sentinel scan could pass even if functions never ran or crashed silently.

**Fix:** Two separate tests:
- **Success-path test:** no `|| true`. Every function must return 0. Test fails if any function fails.
- **Failure-path test:** forces encrypt_state to fail (corrupt key). Verifies no sentinel leaks even on the failure path.

### H.3.1-7 — Timeout test exercised a parallel function (Medium)

**Defect:** `test_h3_wait.bats` defined `wpgovern::db::wait_for_ready_fast` — a separate function never used in production — and tested that instead of the real function.

**Fix:** `wait.sh` now accepts `WPGOVERN_DB_WAIT_TIMEOUT` and `WPGOVERN_DB_WAIT_INTERVAL` env overrides (defaults: 180/5). Test sets `WPGOVERN_DB_WAIT_TIMEOUT=2 WPGOVERN_DB_WAIT_INTERVAL=1` and calls the real production function.

### H.3.1-8 — Test count consistency

H.3 claimed 25 new tests; actual count was 22. H.3.1 adds 9 more, well past the claimed 25. Documented here. No prompt changes needed.

### H.3.1-9 — Pipeline-free password generation (Medium)

**Fix:** `openssl rand -base64 32 | tr -d '/=+' | head -c 32` → `openssl rand -hex 32`. Applied at all three sites in stack/credentials.sh (×2) and db/credentials.sh (×1). Audit test in test_h3_credentials.bats verifies no pipeline pattern remains.

### H.3.1-10 — Stack health-check false-positive on empty output (Carry-forward from H.2)

**Defect:** `_wpgovern_stack_wait_healthy` counted unhealthy containers. Zero unhealthy = healthy. Empty `docker compose ps` output → zero unhealthy → false healthy.

**Fix:** Positive-state check: require `total_count == 4 AND healthy_count == 4`. Empty output handled explicitly (continue loop). Test verifies the loop calls `docker compose ps` more than once when initial calls return empty.

---

## New methodology lessons (to register after H.3.1 closes)

1. **When a brief specifies "reuse a helper from another module," it must also specify the loading path.** Default question: can the calling code path execute with the helper unavailable? If yes, the helper belongs in `core/`.

2. **When a brief specifies a configuration value by name, it must also specify scope where security-relevant.** Privilege scope (`*.*` vs `wordpress.*`), file permissions, network bindings — silence invites overbroad defaults.

3. **Internal verification must probe alternative invocation modes.** Credentials-not-in-logs requires: (a) normal mode, (b) `set -x`, (c) inherited xtrace from parent. Sentinel-grep in one mode is not the complete guarantee.

---

## Test count

| Suite | H.3 | H.3.1 |
|-------|-----|-------|
| Bats | 189 | 198 |
| Python | 776 | 776 |

---

## H.3.1.1 test-correction note

**H.3.1 implementation was correct — verified by direct PoC across all 10 blockers.** Six bats regression tests failed due to test-architecture defects, not implementation defects. H.3.1.1 corrects the tests only; no production files changed.

**Three failure classes fixed:**

1. **Tests 172+173 (`test_h3_ci_credentials.bats`):** `run bash -c "..." 2>&1 | tee "$file"` — the `| tee` pipe outside `run` broke `$status` capture and prevented `$combined_file` from being populated. Fixed with runner script pattern: write invocation to a `.sh` file, `run bash "$runner_script" 2>&1`, use `$output` directly. Also replaced `grep -qF "$s" && { return 1; }` with `if grep -qF; then return 1; fi` (set -e in bats test bodies treats grep's non-zero exit as failure).

2. **Tests 176+177 (`test_h3_credentials.bats`):** `setup()` sourced `core/bootstrap.sh`, `core/state.sh`, `modules/stack/credentials.sh`, `modules/db/credentials.sh` — but not `core/credentials.sh`. When `generate_age_key` ran its first line `_wpgovern_disable_xtrace_for_credentials`, the function was undefined (rc=127). Fixed by adding `source "${CORE_DIR}/credentials.sh"` to `setup()` and to the inline `bash -c` sentinel subshell.

3. **Tests 184+185 (`test_h3_entry_script_db_phase.bats`):** Test 184 — `setup()` pre-populates `WPGOVERN_DB_BACKUP_PASSWORD` with a 30-char value, but the test needs it BLANK to exercise the generation path. Fixed by overriding the env file in the test body with blank backup password and ≥32-char root/wp passwords. Test 185 — `bash -x -c "export VAR=...; ..."` leaks sentinels via xtrace of the test's own export statements before installer code runs. Fixed by exporting variables in the test body (outside xtrace scope), then running only function calls under `bash -x << INNER`; sentinel scan restricted to output after the WARNING line.

**Methodology note registered:** the H.3.1-1 defect class (missing helper source) re-appeared in the regression tests for H.3.1-1. Any test that invokes a production function in an isolated subshell must source every file that function transitively depends on. The test's isolated subshell is structurally equivalent to a production execution context — the same dependency graph must be loaded.
