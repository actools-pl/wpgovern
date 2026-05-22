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
