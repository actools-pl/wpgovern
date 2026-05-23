# WPGovern Operational Runbook

> **Version:** 1.0 (H.7)  
> **Doctrine:** Governed. Operable. Recoverable.

---

## Quick Reference

| Task | Command |
|------|---------|
| Check governance | `wpgovern governance-check` |
| Full health audit | `wpgovern-install-audit --complete` |
| Backup status | `wpgovern-restore list` |
| Trigger manual backup | `systemctl start wpgovern-backup-full.service` |
| Verify backup integrity | `wpgovern-restore restore-test` |
| Full restore | `wpgovern-restore <backup_ts>` |
| Acknowledge key backup | `wpgovern-restore ack-key-backup --location-hint "your vault"` |

---

## Routine Operations

**Daily:** `wpgovern-install-audit --ci` — scan findings, act on FAILs.

**Weekly:** `wpgovern-restore restore-test` — verify most recent backup is restorable. install-audit will emit WPG-BKUP-002 WARN after 7 days without a passing restore-test, and FAIL after 30 days.

**Monthly:** Review `wpgovern-restore list` — confirm backup accumulation is as expected. Rotate old backups manually if disk pressure is approaching WPG-STACK-002 WARN threshold (80%).

---

## Failure Modes and Fix Commands

See `wpgovern-install-audit --complete` output for current findings. Each FAIL has a fix command in the output. Common findings:

- **WPG-BKUP-001 FAIL** — No backup in 48 hours. Check: `systemctl status wpgovern-backup-full.timer`
- **WPG-BKUP-002 FAIL** — No restore-test in 30 days. Run: `wpgovern-restore restore-test`
- **WPG-DR-01 WARN** — Key backup not acknowledged. See Key Backup Responsibilities below.
- **WPG-SEC-001 FAIL** — TLS cert expiring. Check: `docker compose logs caddy | grep renew`
- **WPG-SEC-009 FAIL** — Docker images not digest-pinned. Re-run installer to update digests.

---

## Disaster Recovery

### Scenario 1 — Data loss (accidental deletion, corruption)

1. `wpgovern-restore list` — identify the backup timestamp to restore from
2. `wpgovern-restore <backup_ts>` — runs all five phases automatically
3. Review exit code: 0 = complete; non-zero = see exit code table in `wpgovern-restore --help`
4. Run `wpgovern-install-audit --complete` to verify post-restore state

### Scenario 2 — Host loss (box dead, disk failed, ransomware)

1. Provision a new Ubuntu 24.04 box
2. Copy your backup files from your backup storage to `${WPGOVERN_BACKUP_DIR}/`
3. Restore your age private key from your off-server backup to `/etc/wpgovern/age.key` (mode 0600)
4. Run `wpgovern-install.sh` with your env file
5. Run `wpgovern-restore <latest_backup_ts>`
6. **RTO target: ≤ 30 minutes** (Hetzner CX22-class box; excludes data transfer time for large backup files)

### Scenario 3 — Key loss (age private key destroyed)

**This scenario is NOT RECOVERABLE by WPGovern.** All backup files are age-encrypted to your private key. Without the private key, the backup files cannot be decrypted.

**Prevention:** run `wpgovern-restore ack-key-backup --location-hint "your location"` after storing the key off-server. Review `WPG-DR-01` in install-audit output regularly.

---

## Backup Verification Cadence

| Frequency | Action |
|-----------|--------|
| Weekly | `wpgovern-restore restore-test` |
| After any major WordPress update | Manual restore-test |
| After host migration | Full restore-test to verify new box works |

---

## Key Backup Responsibilities

**The age private key at `/etc/wpgovern/age.key` (mode 0600) is YOUR responsibility.**

WPGovern generates the key but cannot back it up off-server — that would require an outbound network call that cannot be made safely by an automated system on a server you own.

Steps to acknowledge:
1. Copy `/etc/wpgovern/age.key` to a secure off-server location (password manager, encrypted USB, secure cloud vault)
2. Run: `wpgovern-restore ack-key-backup --location-hint "describe your storage"`
3. Verify: `wpgovern-install-audit --complete` shows WPG-DR-01 PASS

**WPG-DR-01 PASS means:** the operator has acknowledged having backed up the key. It does NOT mean WPGovern has verified the key is actually safe. The attestation is yours.

---

## Emergency Contacts

_Fill in your own:_
- Off-hours support: ___________
- Hetzner Cloud support: https://console.hetzner.cloud (support ticket)
- WPGovern project: https://github.com/your-org/wpgovern
