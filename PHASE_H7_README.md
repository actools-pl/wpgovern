# Phase H.7 — Backup, Governance-Aware Restore, and Deployment Close

> **The final bash-arc phase. After H.7, v1 ships.**
>
> H.7 makes the system **recoverable**. The deployment arc is complete:  
> Governed → Operable → Recoverable.

---

## Purpose

Three loss scenarios must be survivable:

| Scenario | RPO/RTO |
|----------|---------|
| Data loss (row mistake to full DB corruption) | RPO ≤ 1 hour |
| Host loss (box dies, disk fails, ransomware) | RTO ≤ 30 minutes |
| Operator key loss (age private key destroyed) | **NOT RECOVERABLE — by design** |

Key loss is operator-owned. WPGovern surfaces the responsibility via `WPG-DR-01` and the operational runbook. The risk transfer is explicit and visible.

---

## Architectural decisions

### Decision 1 — Stream encryption (no plaintext SQL on disk)

`mariadb-dump ... | age -r <pubkey> -o file.sql.age` — plaintext exists only in kernel pipe buffers, never on disk. Governance tarball similarly streamed through age. The encrypted files land directly; there is no intermediate `.sql` file to recover from disk forensics.

### Decision 2 — Single restore script with internal phases

`wpgovern-restore <backup_ts>` runs five internal phases in sequence:
1. **validate** — backup files exist, non-empty, private key present, mariadb running
2. **install-check** — all H.1-H.6 phases complete on this box (restore assumes fresh install already done)
3. **governance state** — decrypt + extract governance tarball; preserve current `phases_complete`
4. **database** — decrypt + load SQL; apply available binlog files (PITR)
5. **verify** — `governance-check` + `install-audit`; document findings

**Critical order:** governance state BEFORE database. The restore module deliberately sequences in this order — if database is restored first and governance state second, the audit chain over the database operations during restore is lost.

### Decision 3 — Operator attestation for age key backup

`wpgovern-restore ack-key-backup [--location-hint "..."]` records `dr.key_backed_up_at` in state. `WPG-DR-01` emits WARN until this is run; PASS after. The PASS message says "acknowledged" not "verified" — WPGovern cannot reach off-server storage to verify the key is actually safe. The attestation is the operator's responsibility, explicitly documented.

---

## Twelve new bash modules

| Module | Purpose |
|--------|---------|
| `keygen.sh` | age keypair generation (idempotent — never rotates on re-run) |
| `full_backup.sh` | Streaming full backup (SQL + governance tarball, both age-encrypted) |
| `full_backup_entry.sh` | Entry script for systemd full backup service |
| `binlog_rotate.sh` | Hourly binlog rotation with encrypt→verify→delete ordering |
| `binlog_rotate_entry.sh` | Entry script for systemd binlog service |
| `restore_test.sh` | Backup integrity verification (decrypt → test schema → drop) |
| `restore.sh` | Five-phase governance-aware restore |
| `restore_entry.sh` | Entry script + CLI dispatcher for `wpgovern-restore` shim |
| `status.sh` | Backup status command (human + JSON output) |
| `install_shim.sh` | Places `/usr/local/bin/wpgovern-restore` (atomic, H.4.1-3 discipline) |
| `install_systemd.sh` | Installs and enables systemd backup timers |
| `install_runbook.sh` | Installs `RUNBOOK.md` from template |

Plus: `systemd/` unit files (4), `runbook_template.md`.

---

## Install-audit integration

Three fix-IDs activated or added in H.7:

### WPG-BKUP-001 — Full backup currency (activated from H.6 placeholder)

Was: WARN "backup module not yet deployed."  
Now:
- **PASS** — last full backup ≤ 24 hours ago
- **WARN** — last full backup 24-48 hours ago
- **FAIL** — last full backup > 48 hours ago OR backup dir absent

Uses `backup.last_full_at` state fact as authoritative source; falls back to filesystem scan.

### WPG-BKUP-002 — Backup restore-test integrity (activated from H.6 catalog forward-reference)

- **PASS** — restore-test passed within last 7 days
- **WARN** — restore-test passed 7-30 days ago, OR last test failed
- **FAIL** — restore-test never run, OR last passed > 30 days ago

Fix: `wpgovern-restore restore-test`

### WPG-DR-01 — age private key backup acknowledgment (new)

- **WARN** — `dr.key_backed_up_at` state fact not set
- **PASS** — state fact set via `wpgovern-restore ack-key-backup`

Fix: back up `/etc/wpgovern/age.key` off-server, then: `wpgovern-restore ack-key-backup --location-hint "your location"`

**Wording discipline:** PASS message says "acknowledged" not "verified." WPGovern cannot verify off-server backup. The attestation is the operator's.

---

## Five new env vars

| Var | Default | Purpose |
|-----|---------|---------|
| `WPGOVERN_DB_BACKUP_PASSWORD` | (required) | Read-only backup DB user password |
| `WPGOVERN_AGE_PRIVATE_KEY_PATH` | `/etc/wpgovern/age.key` | age private key (mode 0600, operator-owned) |
| `WPGOVERN_AGE_PUBLIC_KEY_PATH` | `/etc/wpgovern/age.pub` | age public key (mode 0644) |
| `WPGOVERN_BACKUP_DIR` | `/srv/wpgovern/backups` | Encrypted backup storage |
| `WPGOVERN_RCLONE_REMOTE` | (none) | Optional rclone remote for offsite sync |

---

## Critical disciplines applied in H.7

**Verified-before-deleted (binlog rotation):**
```
encrypt → verify .age non-empty → THEN rm plaintext binlog
```
If encryption produces an empty `.age` file, the plaintext binlog is preserved. Never delete before verify. Enforced structurally and tested in `test_h7_binlog_rotate.bats`.

**Private key NOT in governance tarball:**
The tarball uses `--exclude="${privkey_path}"`. Including the private key would mean anyone with the backup files can decrypt them — defeating encryption-at-rest. Tested in `test_h7_full_backup.bats` by extracting the tarball and asserting `age.key` is absent.

**Idempotency for keypair generation:**
`generate_keypair` checks if `${WPGOVERN_AGE_PRIVATE_KEY_PATH}` exists at mode 0600. If so, skips generation entirely. Re-running the installer NEVER rotates keys — that would make all existing backups unrecoverable.

**Lesson 2 sixth refinement at every credential-touching function:**
`full_backup.sh`, `binlog_rotate.sh`, `restore_test.sh`, `restore.sh` — all functions reading `WPGOVERN_DB_BACKUP_PASSWORD` or the age private key content have the inline `case "$-" in *x*)` guard at function entry.

---

## wpgovern-restore subcommands

```
wpgovern-restore <backup_ts>              # Full governance-aware restore
wpgovern-restore ack-key-backup           # Acknowledge off-server key backup
  [--location-hint "<string>"]
wpgovern-restore restore-test             # Verify most recent backup is restorable
wpgovern-restore list                     # List available backups
wpgovern-restore --version
wpgovern-restore --help
```

Exit codes for full restore:
- `0` — complete, all verifications passed
- `10` — validate phase failed (files missing/corrupt, key unavailable)
- `11` — install-check failed (wpgovern-install.sh not complete on this box)
- `12` — governance state restore failed
- `13` — database restore failed
- `14` — post-restore verification failed (governance-check or install-audit)

---

## Deployment close

`test_h7_final_security.bats` is the deployment-close gate. It passes iff:

- No BW01 warnings (no top-level `local` outside functions)
- Single H.7 phase dispatch in entry script
- Single H.6 phase dispatch in entry script
- All 7 phases present in entry script
- age private key excluded from governance tarball (structural audit)
- All credential-touching backup functions have xtrace guard
- Governance state restored before database (structural ordering audit)
- Stream encryption — no intermediate `.sql` file writes
- Verified-before-deleted ordering in binlog rotation
- WPG-DR-01 PASS message uses "acknowledged" not "verified"
- All module files have syntax OK

**If test_h7_final_security.bats passes, the bash arc is shippable.**

---

## Operational runbook

Installed at `${WPGOVERN_INSTALL_DIR}/RUNBOOK.md` (mode 0644) from `modules/backup/runbook_template.md`. Sections: quick reference, routine operations, failure modes by fix-ID, disaster recovery procedures for all three loss scenarios, backup verification cadence, key backup responsibilities, emergency contacts placeholder.

---

## RPO/RTO claim verification

**RPO ≤ 1 hour** — binlog rotation timer runs hourly. Restore applies available binlog files in sequence after the full SQL restore (point-in-time recovery). Test scenario: insert data after full backup → trigger binlog rotation → restore → verify inserted row present.

**RTO ≤ 30 minutes** — documented benchmark. Fresh Hetzner CX22-class box: run installer (~5-8 min) + run restore on a small database (~2-5 min) = well within 30 minutes. Large deployments (>10GB database) may need longer data-transfer times not counted in RTO.

---

## Test count

| Suite | H.6.2 | H.7 |
|-------|-------|-----|
| Bats | 305 | 358 |
| Python | 776 | 776 |
| Bash files | 31 | 42 |

---

## H.7.1 hardening note

**H.7 architectural shape correct.** External review (sixth deployment of the four-role layered architecture) returned do-not-close with nine blockers + three late-stage internal findings + one supporting item. All at production-correctness surfaces — not architectural gaps.

### Nine external review blockers closed

**H.7.1-1 — backup_user → wpbackup (9 sites, 4 files):**
H.3 creates `'wpbackup'@'%'`; H.7 modules used `--user=backup_user`. On any real H.3-installed system, backup auth would fail entirely. `grep -rn "backup_user" modules/backup/` = 0. Static regression test in `test_h7_1_hardening.bats` ensures the mismatch cannot recur silently.

**H.7.1-2 — Keygen wrong-mode recovery (no rotation):**
Prior code: key exists at 0644 → `age-keygen` overwrites it. All existing backups become unrecoverable. Fix: Path B. Existing key with wrong mode → `chmod 600` + `age-keygen -y` to derive public key → no rotation. Key contents unchanged; existing backups remain decryptable.

**H.7.1-3 — Governance tarball PIPESTATUS:**
`{ tar ... || true; } | age` masked fatal tar exit 2, producing empty governance backups. Fix: `{ tar ... | age; }` with explicit `tar_exit="${PIPESTATUS[0]}"`. tar exit 1 (file changed) = WARN; tar exit ≥2 = FAIL + rm .age file.

**H.7.1-4 — Binlog discovery: SHOW MASTER STATUS (inverted predicate fixed):**
`-newer binlog.index` selected zero closed binlogs after FLUSH (binlog.index gets fresh mtime; closed binlogs retain original timestamps). Fix: `SHOW MASTER STATUS` before FLUSH → record active binlog, FLUSH, get new active, encrypt all except new active. Hourly RPO now genuine.

**H.7.1-5 — PITR target-range filtering:**
Prior code applied ALL binlogs in the directory. Fix: `mariadb-dump --master-data=2` records binlog position; `full_backup.sh` extracts it via `age -d | head -c 4096 | grep CHANGE MASTER TO`; records `backup.<ts>.binlog_file` state fact. `_restore_phase_database` reads the fact and applies only binlogs lex-sorted AFTER the recorded file. No more unbounded PITR.

**H.7.1-6 — Decryptability validation in validate phase:**
Corrupt file or wrong key now surfaced as exit 10 (validate) not exit 12/13 (governance/database). `age -d ... | head -c 256 > /dev/null` for both SQL and governance backups. Minimal cost; proves the age header is valid.

**H.7.1-7 — State path discovery via shared helper (latent H.6.2-3 defect):**
Both `restore_entry.sh` and `modules/audit/entry.sh` defaulted to `/var/lib/wpgovern/.state.json`. The installer writes state to `${WPGOVERN_INSTALL_DIR}/.wpgovern-installer-state.json` (default `/opt/wpgovern-install/`). New `wpgovern::state::resolve_default_state_file` helper in `core/state.sh` (additive only): env var → installer default → return 1. Both entry scripts updated. `grep -n "/var/lib/wpgovern/.state.json"` in either entry = 0.

**H.7.1-8 — Systemd fail-closed:**
`|| true` on `daemon-reload`, `enable`, `start` masked systemctl failures. Timers could be inactive while install phase recorded success. Fix: each `systemctl` call wrapped in `if !`. Test: mock systemctl exit 1 → `install_systemd` returns non-zero.

**H.7.1-9 — Restore subcommand validation:**
`*) backup_ts="$1"` treated any unknown token as a timestamp. `wpgovern-restore nonsense` would attempt a restore against timestamp "nonsense". Fix: `[[ "$1" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]` before accepting as timestamp; non-matching exits 2 with error + help.

### Three late-stage internal findings closed

**H.7.1-10 — restore_test: explicit cleanup at each return (supporting):**
EXIT trap cleaned up on shell exit only. For sourced/long-running contexts, test schema could persist until process exit. Fix: explicit `_restore_test_cleanup` before each early return; EXIT trap retained as backstop; `trap - EXIT` after explicit success-path cleanup.

**H.7.1-11 — Logical-completion verification (streaming):**
`[[ ! -s "$sql_backup" ]]` size-only check was insufficient — headers-only dumps produce non-empty .age files. Two streaming sentinels added: (1) `age -d ... | grep -qE "CREATE TABLE.*wp_options"` — WP schema was dumped; (2) `age -d ... | tail -5 | grep -q "Dump completed on"` — clean termination. Both required. Streaming form: memory-bounded for large backups.

**H.7.1-12 — Concurrent state mutation: flock:**
The midnight boundary race: systemd's daily and hourly timers both fire at 00:00:00. Concurrent `set_fact` calls on different keys produce a read-modify-write race; one update is lost. Fix: `flock -x 8` subshell wraps `set_fact`, `mark_phase_complete`, `mark_phase_failed`. FD 8 (installer main uses FD 9). Read functions (`get_fact`, `phase_complete`) NOT flocked. Lock file: `/var/lock/wpgovern-state.lock` (override via `WPGOVERN_STATE_LOCK`). Test: two concurrent `set_fact` calls in background → both updates present in final state.

**H.7.1-13 — Container readiness polling in entry scripts:**
`After=docker.service` waits for docker daemon; does NOT wait for MariaDB container to accept TCP. On post-reboot timer fire, backup may attempt before container is ready. Fix: 30-second polling loop using `docker compose exec -T mariadb mariadb-admin ping --silent` before invoking backup module. If MariaDB never becomes ready, backup module surfaces an explicit failure (not a silent miss).

### Five H.7 doctrine claims: all now hold

| Claim | Pre-H.7.1 | Post-H.7.1 |
|-------|-----------|------------|
| RPO ≤ 1 hour | ✗ Binlog discovery inverted (zero encrypted) | ✓ H.7.1-4 + H.7.1-5 + H.7.1-13 |
| Encrypted at rest | ✗ Governance tarball false-success on tar exit 2 | ✓ H.7.1-3 |
| Verified, not just stored | ✗ Size-only check | ✓ H.7.1-11 sentinels |
| RTO ≤ 30 minutes | ✓ (documented benchmark) | ✓ unchanged |
| WPG-DR-01 operator attestation | ✓ wording correct | ✓ unchanged |

### Test count: 358 → 385 (+27 in test_h7_1_hardening.bats)

### Three methodology candidates earn formalization eligibility at H.7 closure

After H.7.1 closes and H.7 closes on internal verdict, three methodology refinements register:
1. **Doctrine-vs-implementation audit** → Lesson 11 (new lesson; ~9 instances across H.6+H.7)
2. **Four-role layered review architecture effectiveness** → Lesson 9 second refinement (third consecutive observation: H.5/H.6/H.7)
3. **Pattern-match assumption / discipline-travel** → Lesson 2 eighth refinement (second observation: H.4+H.7 state-path defect traveled from audit entry to restore entry)

---

## H.7.1 hardening note

**H.7 architectural shape correct.** Nine blockers from external review (sixth deployment of layered architecture / third consecutive four-role deployment) + three from late-stage internal verification + one supporting item. All at concrete production-correctness surfaces — not architecture, not doctrine wording, not test hygiene.

### The five doctrine claims: pre/post H.7.1 status

| Doctrine claim | Pre-H.7.1 | Post-H.7.1 |
|---|---|---|
| RPO ≤ 1 hour | **Partial**: binlog discovery inverted (zero binlogs encrypted); PITR applied all binlogs unconditionally | **Full**: SHOW MASTER STATUS correctly identifies closed binlogs; PITR applies only binlogs after full-backup position |
| Encrypted at rest | **Partial**: governance tarball `|| true` masked fatal tar failures; logically-empty dumps encrypted as "valid" | **Full**: PIPESTATUS on tar pipeline; two streaming sentinels (wp_options + Dump completed) |
| RTO ≤ 30 min | Documented (unchanged) | Documented (unchanged) |
| Governance-before-database restore order | ✓ | ✓ |
| WPG-DR-01 "acknowledged" wording | ✓ | ✓ |

### Thirteen items closed

**H.7.1-1** — `backup_user` → `wpbackup` at 9 sites in 4 files. H.3 creates `'wpbackup'@'%'`; using `backup_user` caused complete authentication failure on real systems. Regression: `grep -rn "backup_user" modules/backup/` = 0.

**H.7.1-2** — Keygen wrong-mode recovery. Existing key at 0644 → `chmod 600 + age-keygen -y` (derive public key). Never overwrites the private key. Prior code re-ran `age-keygen` on wrong-mode, destroying all existing backups.

**H.7.1-3** — Governance tarball PIPESTATUS. `{ tar ... | age ...; }` + `PIPESTATUS[0]`/`PIPESTATUS[1]`. tar exit 1 = WARN (file changed, acceptable). tar exit ≥2 or age exit ≠0 = FAIL + cleanup. Prior `|| true` accepted empty governance backups.

**H.7.1-4** — Binlog discovery: `SHOW MASTER STATUS` before + after `FLUSH BINARY LOGS`. Iterates all binlogs in directory; skips the post-FLUSH active one. Prior `-newer binlog.index` was inverted — selected zero files after FLUSH because FLUSH refreshes `binlog.index` mtime.

**H.7.1-5** — PITR target-range. `full_backup.sh` extracts `MASTER_LOG_FILE` from first 4KB of encrypted dump (mariadb-dump `--master-data=2`); records `backup.${ts}.binlog_file` state fact. `restore.sh` reads the fact and applies only binlogs lex-sorted after that position.

**H.7.1-6** — Decryptability validation. `_restore_phase_validate` does `age -d -i key file | head -c 256 > /dev/null` for both backup files. Corrupt file or wrong key → exit 10 (validate phase). Prior: exits 12 or 13 (governance/database phases, too late).

**H.7.1-7** — State path discovery. `wpgovern::state::resolve_default_state_file` added to `core/state.sh` (additive only). Precedence: `WPGOVERN_STATE_FILE` env → `${WPGOVERN_INSTALL_DIR}/.wpgovern-installer-state.json` → fail. Both `modules/audit/entry.sh` AND `modules/backup/restore_entry.sh` use it. The `/var/lib/wpgovern/.state.json` fallback was wrong (installer writes to `WPGOVERN_INSTALL_DIR`, default `/opt/wpgovern-install/`). This is also the latent H.6.2-3 defect that survived H.6 closure — the second observation for the "discipline-travel" methodology candidate.

**H.7.1-8** — Systemd fail-closed. Removed all `|| true` from `daemon-reload`, `enable`, and `start` calls. Now: `if ! systemctl ...; then mark_phase_failed; return 1; fi`. Prior code silently succeeded even if no timers became active.

**H.7.1-9** — Subcommand validation. `[[ "$1" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]` before treating `$1` as a backup timestamp. Unknown input → exit 2 + help message. Prior code: `wpgovern-restore nonsense` initiated a destructive restore attempt.

**H.7.1-10 (supporting)** — Restore-test explicit cleanup. `_restore_test_cleanup` called before each early return path AND before success return. EXIT trap retained as backstop. `trap - EXIT` clears the trap after explicit cleanup.

**H.7.1-11** — Logical-completion verification. Streaming two-sentinel check after SQL backup: `age -d | grep -qE "CREATE TABLE.*wp_options"` + `age -d | tail -5 | grep -q "Dump completed on"`. File-size check alone accepted headers-only dumps (empty database scenario). Both sentinel checks required; either failure → rm .age + return 1.

**H.7.1-12** — Concurrent state mutation: `flock -x 8` subshell wraps read-modify-write in `set_fact`, `mark_phase_complete`, `mark_phase_failed`. FD 8 (installer main uses FD 9). Lock file: `${WPGOVERN_STATE_LOCK:-/var/lock/wpgovern-state.lock}`. Read functions (`get_fact`, `phase_complete`) NOT wrapped. The midnight boundary race (daily + hourly timer both fire at 00:00:00 and concurrently update state) is now safe.

**H.7.1-13** — Container readiness polling. Both `full_backup_entry.sh` and `binlog_rotate_entry.sh` poll `docker compose exec -T mariadb mariadb-admin ping --silent` for up to 30 seconds before invoking the backup module. Mitigates the `Persistent=true` boot-race where `docker.service` started ≠ MariaDB container accepting connections.

### Test count: 358 → 385 (+27 in test_h7_1_hardening.bats)

### Methodology candidates earning formalization at H.7 closure

Three candidates reach formalization eligibility after H.7.1:

1. **Doctrine-vs-implementation audit** (Lesson 11): second observation across H.6+H.7, nine total instances across both phases. All four test types: CLI semantics, encryption semantics, concurrency semantics, scheduling semantics.

2. **Four-role layered review architecture** (Lesson 9 second refinement): third consecutive observation at H.5/H.6/H.7. Each fresh-surface phase surfaced findings internal verification missed.

3. **Discipline-travel between sibling modules** (Lesson 2 eighth refinement): second observation at H.4+H.7. The `/var/lib/wpgovern/.state.json` wrong default survived from H.6.2-3 into H.7.1-7 because the same discipline gap wasn't explicitly verified when writing `restore_entry.sh`.

---

## H.7.2 hardening note — final hardening pass of the bash arc

**H.7.1 production code correct; five production-correctness defects surfaced by bounded external review (Role C + Role D, single round). The bash arc closes after H.7.2.**

### Five closure blockers

**H.7.2-1 — PIPESTATUS broken under `set -euo pipefail` (H.7.1-3 fix never engaged):**
The bare `{ tar ... | age; }; local tar_exit="${PIPESTATUS[0]}"` pattern aborts before `local tar_exit` runs when the pipeline returns non-zero under `set -euo pipefail`. The "tar exit 1 acceptable" semantics from H.7.1-3 never engaged. Fix: `set +e` / pipeline / `local _pipe_status=("${PIPESTATUS[@]}")` / `set -e` bracket. Captures PIPESTATUS array safely before `set -u` can trigger `PIPESTATUS[1]: unbound variable`.

**H.7.2-2 — Backup timer entry scripts still used `/var/lib/wpgovern` fallback:**
H.7.1-7 applied `resolve_default_state_file` to `modules/audit/entry.sh` + `modules/backup/restore_entry.sh` (the named-in-brief files). The two systemd-driven timer entries (`full_backup_entry.sh`, `binlog_rotate_entry.sh`) — the operational risk surface — were never touched. When systemd fires the daily/hourly timers, `WPGOVERN_STATE_FILE` is not exported into the spawned process; the fallback hit the wrong path. Fix: both timer entries now call `resolve_default_state_file`. CI guard added: `grep -rn "/var/lib/wpgovern/.state.json" modules/` = 0 enforced by `test_h7_2_hardening.bats`. Note: this is a defect in the H.7.1 internal verification scope (orchestrator-side), not in the implementation itself.

**H.7.2-3 — Default binlog path didn't match actual Docker MariaDB layout:**
`/var/lib/mysql/binlogs` is the native-host path; the Docker deployment mounts `${install_dir}/mariadb/data:/var/lib/mysql` and configures `log-bin = /var/lib/mysql/binlog` (singular). Host-side binlogs live at `${install_dir}/mariadb/data/binlog.*`. Fix: default changed to `${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}/mariadb/data`. RPO ≤ 1 hour doctrine claim now holds against real deployment topology.

**H.7.2-4 — `age -d | head -c 256` causes SIGPIPE on large backups under pipefail:**
When `head -c 256` exits after reading 256 bytes, age receives SIGPIPE. Under `set -o pipefail`, SIGPIPE (rc=141) propagates as pipeline failure. Valid large backups falsely failed decryptability validation. Fix: full decrypt to `/dev/null` — `age -d -i "$privkey_path" "$file" >/dev/null 2>&1`. No SIGPIPE; no size boundary; validate is not a hot path.

**H.7.2-5 — PITR fail-open when `backup.${ts}.binlog_file` state-fact missing:**
If the state-fact is empty and binlogs exist, the H.7.1-5 PITR code fell through to applying ALL binlogs — reintroducing the H.7 data-corruption path. Fix: explicit guard before iteration: if `base_binlog` is empty AND `available_binlogs > 0`, refuse with exit 13 and an operator-actionable error message naming the missing state-fact. If no binlogs exist, fall through cleanly (full-backup-only restore works correctly).

### Methodology notes registered at H.7 closure

Three candidates formalized:
1. **Lesson 11 (NEW)** — Doctrine-vs-implementation audit
2. **Lesson 9 second refinement** — Four-role layered review architecture (empirically effective at hardening, not just fresh-surface phases)
3. **Lesson 2 eighth refinement** — Pattern-match assumption / discipline-travel between sibling modules

One candidate held for next arc:
- **Internal-verification scope must enumerate sibling files** — two observations (H.7 backup_user gap + H.7.1 timer entry gap), same verification pattern. Held for Veritas LMS arc.

### Final test/bash counts

| | Bats | Python | Bash files |
|--|--|--|--|
| H.7 shipped | 358 | 776 | 42 |
| After H.7.1 | 385 | 776 | 42 |
| After H.7.2 | **398** | **776** | **42** |

### Deployment-close gate (updated)

`test_h7_final_security.bats` is a necessary gate. After H.7.2, the full closure gate is:

1. `test_h7_final_security.bats` passes (structural cross-arc security properties)
2. `test_h7_1_hardening.bats` passes (27 H.7.1 regression tests)
3. `test_h7_2_hardening.bats` passes (13 H.7.2 regression tests, including CI guard)
4. `grep -rn "/var/lib/wpgovern/.state.json" modules/` = 0
5. 3× bats deterministic, 10/10 H.2 compose, 10/10 wp-config determinism
6. Python 776/776, zero diff vs H.4.1 baseline

**The bash arc is complete. The system is governed AND operable AND recoverable.**
