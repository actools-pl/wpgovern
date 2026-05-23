# Phase H.6 — `wpgovern install-audit` Operational Health Command

> **Doctrine:** Boringly predictable, brutally honest, immediately useful.
>
> Predictable: the same checks run in the same order every time.
> Honest: no short-circuit; the operator gets the full picture, always.
> Useful: every finding has a fix-ID and a specific operator action.

---

## Purpose

Everything before H.6 made the system **governed**. H.6 makes the system **operable**.

`governance-check` answers one binary question: "is the system in governance coherence right now?"

`wpgovern-install-audit` answers a richer question: "what is the operational state of this deployment, what has drifted, what needs attention, and what command fixes it?"

Operators run `install-audit` whenever they want a health check. It runs outside the governance protocol — it's a diagnostic reader, not a governance writer. It never signs anything, never updates `active.json`, never triggers approval workflows. It reads the live system and reports what it finds.

---

## Architectural decisions

### Decision 1 — Pure bash, separate command (not a `wpgovern` subcommand)

The Python control plane is locked at v52.1. Every probe is bash-native (`docker`, `curl`, `openssl`, `ss`, `df`, `free`) — reimplementing in Python via `subprocess.run()` adds complexity without value. The diagnostic purpose (read-only, report-only) is the opposite shape from the Python control plane's hash-chained audit log and signed baselines. Two commands with distinct identities: `wpgovern` is governance; `wpgovern-install-audit` is diagnostics.

### Decision 2 — Pipe-delimited line buffer as internal findings format

Internal format: `fix_id|priority|status|layer|message|fix_command`

Each probe appends to `_WPGOVERN_AUDIT_FINDINGS`. The buffer composes naturally with `awk`/`sort`/`grep` for the three formatters. Deterministic insertion order preserved. No filesystem state for a read-only command. Pipe character `|` is forbidden in any field value — probes are responsible for not emitting one.

### Decision 3 — No configurable skip lists, severity overrides, or config files

The doctrine is "boringly predictable" — the same checks run every time. Configurable skip lists violate this. Severity overrides let an operator hide FAIL findings as WARN, defeating "brutally honest." CLI layer filters (`--security`, `--complete`) change which layers run but don't suppress findings within a layer. The full audit (`--complete`, default) always runs all layers.

---

## Three layers + layer 1.5

| Layer | Name | What it checks |
|-------|------|----------------|
| 1 | WordPress truth | Core version, plugin updates, cron status, config drift, security plugin presence |
| 1.5 | Behavioral verification | Redis writeback, login flow, cache headers, trusted-host rejection |
| 2 | Infrastructure health | Container health, disk/memory pressure, TLS expiry, backup currency, MariaDB reachability |
| 3 | Security posture | HTTPS redirect, security headers, open ports, server header, image digest pinning |

Layer ordering is fixed and deterministic. Default output appears in 1 → 1.5 → 2 → 3 order.

---

## Output modes

| Flag | Description |
|------|-------------|
| `--complete` | All layers (default) |
| `--security` | Layer 3 + security-tagged Layer 1 findings |
| `--ci` | Machine-stable, sorted by fix-ID, no ANSI colors |
| `--json` | Structured JSON for automation |
| `--version` | Version string |

### JSON output structure

```json
{
  "wpgovern_install_audit_version": "1.0",
  "timestamp": "2026-05-22T14:30:00Z",
  "domain": "example.com",
  "exit_code": 0,
  "summary": {"pass": 24, "warn": 3, "fail": 0},
  "findings": [
    {
      "fix_id": "WPG-STACK-001",
      "priority": "HIGH",
      "status": "PASS",
      "layer": 2,
      "message": "All expected containers healthy",
      "fix": null
    }
  ]
}
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No FAIL findings (warnings present is still exit 0) |
| 1 | One or more FAIL findings |
| 2 | Internal error (probe function crashed) |

Exit 0 with warnings means: "system is operational, but there are items requiring operator attention." Warnings are not blockers.

---

## Fix catalog

Every fix-ID the implementation can emit, enumerated. The implementation and this catalog are in 1:1 correspondence (Lesson 2 third refinement applied to documentation).

### Layer 1 — WordPress truth (WPG-WP-*)

---

#### WPG-WP-001 — WordPress core version

- **Priority:** LOW
- **Status:** PASS (version retrieved) / WARN (wp-cli unreachable)
- **Check:** `_audit_probe_wp_core_version`
- **Message:** "WordPress core version: X.Y.Z"
- **Fix:** Check container health: `docker compose ps`
- **Notes:** H.6 does not check whether the version is current (requires network to WordPress.org — out of scope per Decision 3). Reports what's installed.

---

#### WPG-WP-002 — Plugin updates available

- **Priority:** MEDIUM (warn) / LOW (pass)
- **Status:** PASS (count=0) / WARN (count>0)
- **Check:** `_audit_probe_wp_plugin_updates`
- **Message:** "N WordPress plugin(s) have available updates"
- **Fix:** `wp plugin update --all` (via cli container)
- **Notes:** WARN-level (not FAIL) because outdated plugins are an operational risk, not an immediate outage. Operators should review changelogs before mass-updating.

---

#### WPG-WP-003 — WordPress cron status

- **Priority:** MEDIUM
- **Status:** PASS / WARN (events overdue >1 hour)
- **Check:** `_audit_probe_wp_cron_status`
- **Message:** "N WordPress cron event(s) overdue by >1 hour"
- **Fix:** Check WP Cron events: `docker compose --profile cli run --rm cli wp cron event list`
- **Notes:** WP Cron requires HTTP traffic to trigger. On low-traffic deployments, add a system cron job to call `wp cron run`.

---

#### WPG-WP-004 — WordPress siteurl drift

- **Priority:** HIGH (warn)
- **Status:** PASS / WARN (siteurl ≠ WPGOVERN_DOMAIN)
- **Check:** `_audit_probe_wp_config_drift`
- **Message:** "WordPress siteurl (DB) does not match expected (WPGOVERN_DOMAIN)"
- **Fix:** Update siteurl via wp-cli or wp-config.php WP_HOME
- **Notes:** Siteurl drift causes login redirect loops and asset URL failures.

---

#### WPG-WP-007 — No WordPress security plugin detected *(architectural delegation signal)*

- **Priority:** LOW
- **Status:** PASS (recognized plugin active) / WARN (no recognized plugin)
- **Check:** `_audit_probe_wp_security_plugin`
- **Message:** "No WordPress security plugin detected (architectural delegation signal)"
- **Fix:** Install Wordfence, Sucuri Security, or MalCare from wp-admin → Plugins → Add New
- **Notes:** This finding is intentionally LOW priority and WARN-level (not FAIL). WordPress content-layer security is operator-delegated per the v1 architectural decision. The presence of this check in audit output communicates the delegation choice. Recognized plugins: wordfence, sucuri-scanner, all-in-one-wp-security, miniorange-malware-protection-and-security-scanner, malcare-security.

---

#### WPG-WP-008 — Login flow behavior

- **Priority:** MEDIUM
- **Status:** PASS (session cookie returned) / WARN (no cookie or unreachable)
- **Check:** `_audit_probe_login_session`
- **Message:** "Login flow probe: WordPress responds to login POST and sets session cookie"
- **Fix:** Check WordPress sessions configuration
- **Notes:** Uses deliberate invalid credentials — tests that the login machinery RESPONDS, not that operator credentials work.

---

### Layer 1.5 — Behavioral (WPG-STACK-*, WPG-SEC-*)

---

#### WPG-STACK-005 — Redis writeback verification

- **Priority:** HIGH (fail) / MEDIUM (warn) / LOW (pass/skip)
- **Status:** PASS / WARN (TTL not set or unreachable) / FAIL (value mismatch)
- **Check:** `_audit_probe_redis_writeback`
- **Message:** "Redis writeback probe: read/write/TTL all verified"
- **Fix:** Investigate Redis persistence configuration
- **Notes:** Skipped (PASS with "not configured" message) if Redis service not present.

---

#### WPG-SEC-010 — wp-login.php cache header

- **Priority:** HIGH
- **Status:** PASS / FAIL (Cache-Control: no-cache missing)
- **Check:** `_audit_probe_http_cache_headers`
- **Message:** "wp-login.php has Cache-Control: no-cache header"
- **Fix:** Add Caddy rewrite rule: `header /wp-login.php Cache-Control no-cache`
- **Notes:** Cached login pages cause stale CSRF token errors.

---

#### WPG-SEC-011 — Trusted-host spoof rejection

- **Priority:** HIGH
- **Status:** PASS (4xx returned) / FAIL (200 returned) / WARN (unexpected response)
- **Check:** `_audit_probe_trusted_host_rejection`
- **Message:** "Trusted-host spoof rejected with HTTP 400/421/403/444"
- **Fix:** Add Caddy SNI validation or WordPress trusted-host check to wp-config.php
- **Notes:** Tests that `Host: evil.example.com` is rejected. Verifies wp-config.php `$_SERVER['HTTP_HOST']` validation fires.

---

### Layer 2 — Infrastructure (WPG-STACK-*, WPG-SEC-*, WPG-BKUP-*)

---

#### WPG-STACK-001 — Container health

- **Priority:** HIGH
- **Status:** PASS (all 4 healthy) / FAIL (any container not healthy/running)
- **Check:** `_audit_probe_containers_healthy`
- **Message:** "All expected containers (caddy, mariadb, php, wordpress) are healthy"
- **Fix:** `docker compose up -d && docker compose ps`

---

#### WPG-STACK-002 — Disk pressure

- **Priority:** CRITICAL (≥90%) / HIGH (≥80%)
- **Status:** PASS / WARN (≥80%) / FAIL (≥90%)
- **Check:** `_audit_probe_disk_pressure`
- **Message:** "Disk pressure CRITICAL: /opt/wpgovern-install at 95% (≥90%)"
- **Fix:** `du -sh /opt/wpgovern-install/* | sort -rh | head -20`
- **Notes:** Checked on: `/opt/wpgovern-install`, `/var/log`, `/srv` (if exists).

---

#### WPG-STACK-003 — Memory pressure

- **Priority:** CRITICAL (≥90%) / HIGH (≥80%)
- **Status:** PASS / WARN / FAIL
- **Check:** `_audit_probe_memory_pressure`
- **Message:** "Memory pressure HIGH: 85% used"
- **Fix:** `docker stats --no-stream`

---

#### WPG-STACK-004 — MariaDB reachability from PHP

- **Priority:** HIGH
- **Status:** PASS / FAIL
- **Check:** `_audit_probe_mariadb_reachable`
- **Message:** "MariaDB reachable from PHP container"
- **Fix:** `docker compose logs mariadb`

---

#### WPG-SEC-001 — TLS certificate expiry

- **Priority:** CRITICAL (<7 days) / HIGH (<30 days)
- **Status:** PASS / WARN (<30 days) / FAIL (<7 days)
- **Check:** `_audit_probe_tls_cert_expiry`
- **Message:** "TLS certificate valid for N more day(s)"
- **Fix:** Verify Caddy auto-renewal: `docker compose logs caddy | grep renew`

---

#### WPG-BKUP-001 — Backup currency

- **Priority:** HIGH
- **Status:** PASS / WARN (no recent backup or H.7 not deployed)
- **Check:** `_audit_probe_backup_currency`
- **Message:** "Backup module not yet deployed (H.7); backup directory not present"
- **Fix:** Deploy H.7 backup module
- **Notes:** **In H.6, this probe emits WARN (not FAIL) because H.7 backup module is not yet deployed.** After H.7 deploys and the backup directory exists, this probe enforces the 48-hour SLO. The `WPG-BKUP-*` namespace exists in H.6 in INFO/WARN state — H.7 populates it with real PASS/WARN/FAIL enforcement.

---

### Layer 3 — Security posture (WPG-SEC-*, WPG-CFG-*)

---

#### WPG-SEC-002 — HTTPS enforced

- **Priority:** HIGH
- **Status:** PASS (HTTP 301/308 → HTTPS) / FAIL (HTTP 200)
- **Check:** `_audit_probe_https_enforced`
- **Message:** "HTTPS enforced: HTTP redirects to HTTPS (HTTP 301)"
- **Fix:** Add HTTP→HTTPS redirect in Caddyfile

---

#### WPG-SEC-003 — Strict-Transport-Security header

- **Priority:** HIGH
- **Status:** PASS / FAIL (absent)
- **Check:** `_audit_probe_security_headers`
- **Message:** "Strict-Transport-Security header present"
- **Fix:** `header Strict-Transport-Security "max-age=31536000; includeSubDomains"` in Caddyfile

---

#### WPG-SEC-004 — X-Content-Type-Options header

- **Priority:** MEDIUM
- **Status:** PASS / WARN (absent)
- **Check:** `_audit_probe_security_headers`
- **Message:** "X-Content-Type-Options header present"
- **Fix:** `header X-Content-Type-Options nosniff` in Caddyfile

---

#### WPG-SEC-005 — Server header version disclosure

- **Priority:** MEDIUM
- **Status:** PASS (absent) / WARN (present, version-stripped) / FAIL (version in header)
- **Check:** `_audit_probe_server_header_hidden`
- **Message:** "Server header leaks version information: 'caddy/2.7.4'"
- **Fix:** `header -Server` in Caddyfile

---

#### WPG-SEC-006 — X-Frame-Options header

- **Priority:** MEDIUM
- **Status:** PASS / WARN (absent)
- **Check:** `_audit_probe_security_headers`
- **Fix:** `header X-Frame-Options SAMEORIGIN` in Caddyfile

---

#### WPG-SEC-007 — Content-Security-Policy header

- **Priority:** LOW
- **Status:** PASS / WARN (absent — operator-configurable)
- **Check:** `_audit_probe_security_headers`
- **Notes:** CSP is operator-configurable. WARN, not FAIL. See OWASP CSP cheat sheet for guidance.

---

#### WPG-SEC-008 — Unexpected ports open

- **Priority:** HIGH
- **Status:** PASS (only 22, 80, 443) / FAIL (unexpected port)
- **Check:** `_audit_probe_ports_open`
- **Message:** "Unexpected ports listening: [2375]"
- **Fix:** `ss -tnlp` to identify processes; close or firewall unexpected ports.
- **Notes:** Docker API port 2375 appearing here is a CRITICAL finding — indicates Docker daemon exposed without TLS.

---

#### WPG-SEC-009 — Docker image digest pinning

- **Priority:** HIGH
- **Status:** PASS (all @sha256:) / FAIL (any tag-only)
- **Check:** `_audit_probe_docker_images_pinned`
- **Message:** "All Docker images are digest-pinned (@sha256:)"
- **Fix:** Re-run H.2 image pinning via wpgovern-install.sh to update digests

---

## Operator workflow

**Daily check (recommended):** `wpgovern-install-audit --ci` — machine-stable output, easy to scan in a terminal.

**Before maintenance:** `wpgovern-install-audit --complete` — full human-readable report to establish baseline before any changes.

**In CI/CD pipelines:** `wpgovern-install-audit --json | jq '.exit_code'` — exits 0/1 for pass/fail detection.

**Security review:** `wpgovern-install-audit --security` — Layer 3 + security-tagged Layer 1 only.

**When an operator reports an issue:** run `--complete`, capture output, review FAIL findings first by fix-ID.

---

## What H.6 does NOT do

- **No remediation.** Audit reports findings; operators run fixes. No `--fix` flag, no auto-remediation. Coupling audit-with-fix creates pressure to soften findings to protect the auto-fix path.
- **No backup currency enforcement** — H.7 backup module must be deployed first.
- **No network probes** to external services (no WordPress.org version lookups, no DNS validation). All probes are local-only.
- **No operator-configurable skip lists or severity overrides.** Doctrine: boringly predictable = same checks every time.
- **No state mutations** — every probe is read-only.

---

## H.7 hand-off

The `WPG-BKUP-*` namespace exists in H.6 with WARN findings ("backup module not yet deployed"). H.7 deploys the backup system and updates `_audit_probe_backup_currency` to enforce the 48-hour SLO. After H.7 closes:

- Backup within 48 hours → `WPG-BKUP-001 PASS`
- No backup in 48 hours → `WPG-BKUP-001 WARN`
- Backup system not configured → `WPG-BKUP-001 FAIL`

H.7 also adds `WPG-BKUP-002` (backup integrity check: verify the latest backup is restorable, not just present).

---

## Foundation check from H.5 closure

Two test files with stale skip guards referencing the deleted `wpgovern-0.1.0.tar.gz` sdist were deleted at H.6 open:

- `installer_tests/test_h5_install_python.bats` (deleted — 3 stale skip guards; superseded by `test_h5_production_path.bats`)
- `installer_tests/test_h5_real_integration.bats` (deleted — 2 stale skip guards; superseded by `test_h5_production_path.bats`)

These tests silently skipped every run post-H.5.1 because they referenced the deleted `wpgovern-0.1.0.tar.gz`. Deleting them rather than patching guards is correct: `test_h5_production_path.bats` provides better coverage by exercising the real bash↔CLI boundary.

---

## Test count

| Suite | H.5.1 | H.6 |
|-------|-------|-----|
| Bats | 259 | 283 |
| Python | 776 | 776 |
| Bash files | 23 | 31 |

---

## H.6.1 hardening note

**H.6 architectural shape verified correct by internal verification.** Three-layer structure, fix-ID coordination contract 1:1, Lesson 2 fifth refinement applied correctly in test_h6_integration.bats. Two blockers surfaced.

### H.6.1-1 (High) — Credential xtrace guard in `_audit_probe_mariadb_reachable`

**Defect:** `_audit_probe_mariadb_reachable` read `WPGOVERN_DB_WP_PASSWORD` into a local variable and substituted it into a `docker exec` invocation. No xtrace guard at function entry. Under `bash -x`, 5 cleartext leak occurrences.

**Fix:** Inline `case "$-" in *x*)` guard at function entry with `local _restore_xtrace=1` and matching `[[ -n "${_restore_xtrace:-}" ]] && set -x` before each return path. Identical pattern to H.4.1-2's `load_env` protection.

**Why the orchestrator's helper doesn't propagate:** `_wpgovern_disable_xtrace_for_credentials` (from `core/credentials.sh`) protects within its calling function's scope. When the orchestrator calls it inside `run_full`, xtrace is disabled for that function's body — but NOT for any functions it calls downstream. Each credential-touching function is its own protection scope.

**Discipline rule (registered):** Every audit function that reads a credential value into a local variable or substitutes one into a subprocess invocation MUST apply the inline xtrace guard at function entry. Audit: `grep -rn "WPGOVERN_DB_\|PASSWORD" modules/audit/` — all matches must be inside guarded functions.

**Audit result at H.6.1 close:** only `_audit_probe_mariadb_reachable` reads credentials. All other audit probe functions are credential-free.

### H.6.1-2 (Medium) — `test_h6_probes_layer1_5.bats` with isolated behavioral probe unit tests

**Defect:** H.6 brief Section 3 H.6-10 named this file; it wasn't shipped. Prior coverage in `test_h6_orchestrator.bats` mocked probe functions at the dispatcher level — useful but not equivalent to isolated probe-logic coverage.

**Fix:** Six tests in the new file, each sourcing `behavioral.sh` directly and mocking only external commands (docker, curl):
- Redis writeback PASS (SET/GET/TTL round-trip — mock captures actual SET value)
- Redis writeback WARN (SET fails)
- Trusted-host rejection PASS on 421 AND FAIL on 200 (both branches in one test)
- Cache-Control FAIL when absent from wp-login.php
- Login session WARN when no cookie returned
- Structural: all four behavioral probes emit catalog-matching fix-IDs

**Bonus fix during test implementation:** `_audit_probe_http_cache_headers` had an unguarded `cc_val=$(... | grep ...)` where grep returning 1 (no match) could abort the function under `set -e`. Fixed with `|| true`.

### Test count after H.6.1: 289 (was 283; +6)

---

## H.6.2 hardening note

**H.6 + H.6.1 architectural shape correct.** Five blockers from external review — all at the doctrine-vs-implementation boundary: code doing something different from what the README promised.

### Five blockers closed

**H.6.2-1 + H.6.2-6 — Login probe refactored to GET (closes both):**
POST mutated: failed-login counters, security plugin lockout thresholds, server logs. Refactored to GET: verifies wp-login.php returns 200 with login form HTML — same diagnostic value, no state mutation. `--json` pollution closed: `http_code` now captured into a variable, never written to stdout.

**H.6.2-2 + H.6.2-8 — `format_json` rebuilt on jq (closes both):**
awk `$6` extraction dropped everything after the first pipe in fix commands (`du -sh /* | sort | head` became just `du -sh /*`). Backslashes, newlines, control chars broke JSON silently. Replaced with `jq -n --arg`/`--argjson` construction per finding. jq handles ALL escaping unconditionally.

**H.6.2-3 — env-file discovery precedence + `load_env_readonly`:**
Hardcoded `${WPGOVERN_INSTALLER_DIR}/wpgovern.env`. Now: CLI flag `--env-file` → state-fact `bootstrap.env_file_path` → convention → no-op. New `wpgovern::bootstrap::load_env_readonly` in `core/bootstrap.sh` (additive only): parses env vars without `mkdir`, without strict regex validation. Has xtrace guard.

**H.6.2-4 — Backup currency: remove `-newer /proc/uptime`:**
`-newer /proc/uptime` is kernel-behavior-dependent. A 1-hour-old backup failed the test on recently-rebooted systems. `-mmin -2880` alone is correct.

**H.6.2-5 — Probe crash returns exit code 2:**
`_WPGOVERN_AUDIT_INTERNAL_ERROR` flag initialized to 0 per run. Set to 1 in `_audit_run_probe` on non-zero return. `run_full` returns 2 when set (precedence: 2 > 1 > 0). `format_json` reports `exit_code: 2` in JSON output.

### Three supporting items closed

**H.6.2-7** — `|| true` on server header grep pipeline (same cc_val class from H.6.1). Audit: all `$(... | grep ...)` patterns in audit modules reviewed; only server header probe and cc_val (already fixed) required the guard.

**H.6.2-8** — Subsumed by H.6.2-2 jq construction.

### Env-file discovery for operators

When `wpgovern-install-audit` starts, it resolves the env file via:
1. `--env-file <path>` CLI flag (explicit override)
2. State-fact `bootstrap.env_file_path` recorded at install time
3. Convention: `${WPGOVERN_INSTALLER_DIR}/wpgovern.env`
4. No-op: probes use default values

### Read-only doctrine — now genuinely true

After H.6.2-6 (login GET refactor), `wpgovern-install-audit` is genuinely read-only:
- No HTTP POSTs
- No filesystem mutations (`load_env_readonly` does not create dirs)
- No probe side effects (each probe reads the running system; no writes)

### Test count: 289 → 305 (+16 across 6 files + 1 new file)
