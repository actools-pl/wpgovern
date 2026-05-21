# Phase H.1.1 / v53.1 — Bash Installer Hardening

**Status:** Complete  
**Bats tests:** 100 (was 81; 19 new + 2 replaced)  
**Python tests:** 776 (unchanged from v52.1)  
**Files modified:** `wpgovern-install.sh`, `core/bootstrap.sh`, `core/state.sh`, `modules/host/firewall.sh`, `modules/host/docker.sh`, `modules/host/logrotate.sh`, four bats test files  

---

## Context

Three-window external review of H.1 (v53) converged on "do not close H.1 yet." Five blocking defects and six non-blocking hardening items identified, all in the same defect family: infrastructure primitives that don't fully enforce the discipline they claim. All five blockers verified by direct PoC against v53 code. v53.1 closes all eleven items.

---

## What was closed

### H.1.1-1 — State write atomicity (High blocker)

**Defect:** The pattern `jq ... > "$tmp" && mv "$tmp" "$state_file"` relies on global errexit propagation. In bash, `set -e` is suppressed inside `if` blocks, `while` conditions, `&&`/`||` chains, and function calls from those contexts. Direct PoC: calling `mark_phase_complete` from inside `if ...; then` with a bad state-file schema produced a 0-byte state file and a success return.

**Fix:** Every write function now uses:
```bash
local tmp
tmp="$(mktemp "${state_file}.tmp.XXXXXX")"
if ! jq ... "$state_file" > "$tmp"; then
    rm -f "$tmp"
    return 1
fi
mv "$tmp" "$state_file"
```
Explicit checked write. Returns non-zero regardless of caller's errexit context. Cleans up temp file on failure. `mktemp` also addresses H.1.1-9 (unique temp per invocation eliminates shared-`.tmp` race).

### H.1.1-2 — CLI/env precedence for --force-firewall (High blocker)

**Defect:** `export WPGOVERN_FORCE_FIREWALL="$_force_firewall"` was executed BEFORE `load_env`, so the env file's `WPGOVERN_FORCE_FIREWALL=false` silently overwrote the explicit CLI flag.

**Fix:** Entry script now loads env FIRST, then applies CLI override after:
```bash
wpgovern::bootstrap::load_env "$_env_file"
if [[ -n "$_force_firewall_cli" ]]; then
    export WPGOVERN_FORCE_FIREWALL="true"
fi
```
`--force-firewall` is CLI-only — removed from whitelist parser's allowed list. The H.1.1-13 real integration test would have caught this bug in v53.

### H.1.1-3 — Firewall SSH-port handling (High blocker)

**Defect:** `ufw allow OpenSSH` always adds port 22 regardless of `WPGOVERN_SSH_PORT`. Listener check used `grep ":${ssh_port}"` which matches `:22` inside `:2222`.

**Fix:**
- UFW rule: `ufw allow "${ssh_port}/tcp"` (where `ssh_port="${WPGOVERN_SSH_PORT:-22}"`)
- Listener check: `ss -H -ltn "sport = :${ssh_port}"` (exact-port filter)
- State fact: `host.firewall.ssh_port` records the governed port as evidence

### H.1.1-4 — Docker GPG fingerprint verification (Medium-High blocker)

**Defect:** GPG key downloaded directly to `/etc/apt/keyrings/docker.asc` with no fingerprint check (TOFU — trust on first use).

**Fix:** Download to temp → verify fingerprint via `gpg --show-keys --with-colons | awk -F: '/^fpr:/{print $10;exit}'` → compare against expected `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` → `mark_phase_failed` + `return 1` on mismatch → `install -m 0644 "$tmp_key"` on match. Records verified fingerprint as `host.docker.gpg_fingerprint`.

### H.1.1-5 — jq bootstrap preflight (Medium-High blocker)

**Defect:** `state::init` calls `jq` but runs before `packages::install`. An interrupted first run that created a state file before jq was installed would fail on the next run with a misleading "corrupt state file" error.

**Fix:** jq preflight inserted in entry script before `source core/state.sh`. Auto-installs jq if missing (root) or produces clear error (non-root). This is the only apt operation outside `packages.sh` and is documented as such.

### H.1.1-6 — logrotate fail-closed (Medium)

Checks `command -v logrotate` before writing config. `mark_phase_failed` + `return 1` on binary-missing or validation-failure. Adds `host.logrotate.config_path` fact.

### H.1.1-7 — UFW idempotency rule verification (Medium)

Active UFW → verifies SSH-port/80/443 ALLOW rules and default deny incoming are present. Falls through to full reconfiguration if any rule is missing.

### H.1.1-8 — Ubuntu 24.04 host preflight (Medium)

Reads `/etc/os-release` before any state writes. Errors clearly on non-Ubuntu or non-24.04. Records `host.os.id`, `host.os.version_id`, `host.os.kernel` in state.

### H.1.1-9 — Concurrent-run safety (Medium)

`exec 9>"${WPGOVERN_INSTALL_DIR}/.wpgovern-installer.lock"` + `flock -n 9`. Non-blocking: errors clearly if another run is active. The `mktemp`-based temp files (H.1.1-1) also address the shared-`.tmp` race at the write level.

### H.1.1-10 — Env file whitelist parser (Medium)

Replaces `set -a; source "$env_file"; set +a` with a line-by-line parser that:
- Accepts only keys in the declared allowlist
- Refuses values containing `` ` $ ; | & < > ``
- Rejects malformed lines
- Unwraps single/double-quoted values
- Skips blank lines and comments

Removes `WPGOVERN_FORCE_FIREWALL` from the allowlist (now CLI-only per H.1.1-2 decision).

### H.1.1-11 — sh invocation guard (Low)

`if [[ -z "${BASH_VERSION:-}" ]]` before `set -euo pipefail`. Clear error message when invoked via `sh` or `dash`.

---

## Test additions

### H.1.1-12 — Regression tests (19 new, behavioral)

| Test | File | Defect |
|------|------|--------|
| `mark_phase_complete returns non-zero on jq failure` | state_machine | H.1.1-1 |
| `mark_phase_complete preserves original state on jq failure (if-context)` | state_machine | H.1.1-1 |
| `state writes leave no orphan .tmp files on failure` | state_machine | H.1.1-1 |
| `load_env rejects unknown keys` | bootstrap | H.1.1-10 |
| `load_env rejects shell metacharacters in values` | bootstrap | H.1.1-10 |
| `load_env accepts quoted values and unwraps them` | bootstrap | H.1.1-10 |
| `load_env skips blank lines and comments` | bootstrap | H.1.1-10 |
| `load_env rejects malformed lines without equals sign` | bootstrap | H.1.1-10 |
| `firewall.sh uses WPGOVERN_SSH_PORT variable in ufw allow rule` | host_module | H.1.1-3 |
| `firewall.sh listener check uses exact-port ss filter` | host_module | H.1.1-3 |
| `firewall.sh records ssh_port fact in state` | host_module | H.1.1-3 |
| `docker.sh verifies GPG fingerprint before install` | host_module | H.1.1-4 |
| `docker.sh fails closed on GPG fingerprint mismatch` | host_module | H.1.1-4 |
| `docker.sh records verified GPG fingerprint in state` | host_module | H.1.1-4 |
| `logrotate.sh checks logrotate binary before writing config` | host_module | H.1.1-6 |
| `logrotate.sh calls mark_phase_failed on validation failure` | host_module | H.1.1-6 |
| `logrotate.sh records config path in state` | host_module | H.1.1-6 |

### H.1.1-13 — Real integration tests (2 new, 2 replaced)

The two manual orchestration tests from v53 (`entry script writes phases_complete: host after successful run` and `running host phase twice is idempotent`) are **replaced** by tests that actually invoke `bash wpgovern-install.sh`:

| Test | What it catches |
|------|----------------|
| `entry script run end-to-end writes phases_complete: host` | Exercises real arg parsing, real env loading order, real CLI/env interaction — would have caught H.1.1-2 in v53 |
| `entry script second run skips host phase (idempotent)` | Real re-run idempotency |
| `--force-firewall CLI flag overrides env file value false` | Specific regression for H.1.1-2 |
| `entry script jq preflight appears before state::init` | H.1.1-5 ordering |

---

## Scope-deferred items

Per brief Section 3:

- **State file signing/tamper-detection:** The state file is an installer checkpoint, not a signed governance artifact. Trust model for H.1: the operator is the single trusted actor; tampering by anyone else is out of the H.1 threat model. A future hardening pass MAY add state signing if operational experience demands it.
- **Host fact richness** (package versions, sysctl checksums, UFW rule summaries): engineering value but not blocking. Deferred to H.2 brief authorship.
- **`--dry-run` flag:** Useful for operational testing, separate concern.

---

## Test count

| Suite | v53 (H.1) | v53.1 (H.1.1) |
|-------|-----------|---------------|
| Bats tests | 81 | 100 |
| Python tests | 776 | 776 |

---

*v53.1 is the canonical bash foundation for H.2. Docker Compose stack generation begins next.*
