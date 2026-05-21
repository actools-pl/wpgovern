# Phase H.1.2 / v53.2 — Second Bash Hardening Pass

**Status:** Complete  
**Bats tests:** 104 (was 100; 4 net new + 1 replaced)  
**Python tests:** 776 (unchanged from v52.1)  
**Files modified:** `wpgovern-install.sh`, `core/bootstrap.sh`, `modules/host/firewall.sh`, `modules/host/docker.sh`, `wpgovern.env.example`, three bats test files

---

## Context

v53.1 closed eight of eleven items cleanly. Three blockers escaped — each the SAME defect class as something already supposed to be closed:

- H.1.2-1 = H.1.1-2 defect class: whitelist removal step was incomplete
- H.1.2-2 = H.1.1-3 defect class: H.1.1-7 introduced new substring grep instead of using the exact-match pattern H.1.1-3 established
- H.1.2-3 = H.1.1-1 defect class: explicit checked pattern required; errexit reliance used instead

Lesson 2's third refinement (call-site coverage): when fixing a defect class, audit ALL parallel surfaces, not just the one flagged. v53.2 corrects by being explicit about every site in scope.

---

## What was closed

### H.1.2-1 — WPGOVERN_FORCE_FIREWALL truly CLI-only (High) — THREE SITES

**Site 1 — `core/bootstrap.sh`:** `WPGOVERN_FORCE_FIREWALL` removed from `_WPGOVERN_ENV_ALLOWED`. An env file containing this key now produces `ERROR: unknown key 'WPGOVERN_FORCE_FIREWALL'`.

**Site 2 — `wpgovern.env.example`:** The commented `WPGOVERN_FORCE_FIREWALL="false"` entry replaced with a CLI-only usage note.

**Site 3 — `wpgovern-install.sh`:** After env load, unconditionally sets `export WPGOVERN_FORCE_FIREWALL="false"`. Only the `--force-firewall` CLI flag sets it true. Guards against stale shell-inherited values.

### H.1.2-2 — UFW idempotency exact-field matching (Medium-High)

`_wpgovern_ufw_rule_present()` helper added to `firewall.sh`. Uses awk field matching: `port_spec` must equal the exact port field — `2222/tcp` cannot satisfy a required `22/tcp` rule. All three idempotency check sites (SSH/80/443) now call this helper.

### H.1.2-3 — Docker GPG parse guard (Medium-High) — THREE FAILURE PATHS

```bash
# Parse failure → mark_phase_failed "docker gpg key parse failed"
if ! actual_fpr="$(gpg ... | awk ...)"; then ...

# Empty fingerprint → mark_phase_failed "docker gpg fingerprint missing"
if [[ -z "$actual_fpr" ]]; then ...

# Mismatch → mark_phase_failed "docker gpg fingerprint mismatch"
if [[ "$actual_fpr" != "$_DOCKER_GPG_EXPECTED_FPR" ]]; then ...
```

### H.1.2-4 — sh guard POSIX syntax (Low-Medium)

`[[ -z "${BASH_VERSION:-}" ]]` → `[ -z "${BASH_VERSION:-}" ]`. POSIX `[ ]` works under sh/dash; `[[ ]]` would itself fail.

### H.1.2-5 — flock before state::init (Medium)

Lock acquisition moved to before `source core/state.sh`. Ubuntu preflight remains before lock (refuse non-Ubuntu before writing anything).

### H.1.2-6 — Behavioral test rigor (5 tests added/replaced)

| Test | File | Type | Replaces |
|------|------|------|---------|
| H.1.2-1 positive: real entry script with `--force-firewall` witness file | entry_script | behavioral real | simulated H.1.1-2 test |
| H.1.2-4: `sh wpgovern-install.sh` produces clear error | entry_script | behavioral | new |
| H.1.2-1 negative: env FORCE_FIREWALL rejected by whitelist | bootstrap | behavioral | new |
| H.1.2-2: 2222/tcp does NOT satisfy 22/tcp | host_module | behavioral | new |
| H.1.2-3: malformed GPG key records phases_failed | host_module | behavioral | new |

---

## Methodology notes

**Lesson 6 refinement (May 2026):** safety-critical surfaces require negative-case probing. The v53.1 closure claimed `WPGOVERN_FORCE_FIREWALL` was removed from the whitelist, but the positive case (CLI flag works) was tested without probing the negative case (env-file bypass). v53.2 adds the negative test and confirms it catches the defect.

**Lesson 2 third refinement:** fix the defect class at every surface, not just the flagged one. H.1.2-2 and H.1.2-3 both escaped because parallel surfaces weren't audited when H.1.1-3 and H.1.1-1 were closed.

---

## Scope-deferred items

- `WPGOVERN_OS_RELEASE_FILE` override for bats portability — nice-to-have, not blocking
- No new exit codes, no new host modules, no advance H.2 work

---

## Test count

| Suite | v53.1 | v53.2 |
|-------|-------|-------|
| Bats | 100 | 104 |
| Python | 776 | 776 |
