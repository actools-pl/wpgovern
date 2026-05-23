# WPGovern Backup and Disaster Recovery Manual

## Status

Institutional backup and disaster recovery manual for a single-tenant, single-user WPGovern installation.

This manual explains how WPGovern protects recoverability, what evidence it records, and what the operator must do to keep recovery possible.

---

## 1. Recovery doctrine

WPGovern’s recovery model has three goals:

| Goal | Meaning |
|---|---|
| RPO | How much recent data may be lost in a disaster. |
| RTO | How long recovery should take after a prepared restore host exists. |
| Evidence | Whether the operator can prove backups and restore-tests happened. |

WPGovern is designed around this doctrine:

```text
Encrypted full backups + encrypted binlogs + restore-test + operator-attested key custody.
```

The system is recoverable only if all parts remain true.

---

## 2. Backup model

WPGovern uses two backup layers.

### Full backup

A full backup captures:

- WordPress database dump,
- governance state,
- installer state and configuration evidence,
- required governed files, excluding the age private key.

The SQL backup is streamed directly through age encryption. Plaintext SQL must not be written to disk.

### Binlog rotation

Binlogs support point-in-time recovery between full backups. The expected sequence is:

```text
encrypt binlog -> verify encrypted output -> delete plaintext binlog
```

Plaintext binlogs must not be deleted before encrypted output is verified.

---

## 3. Encryption model

WPGovern uses age encryption.

The public key is used to encrypt backups. The private key is required to decrypt them.

Critical rule:

```text
If the age private key is lost, encrypted backups are not recoverable.
```

The age private key must be backed up off-server by the operator.

WPGovern can record that the operator acknowledged the key backup. WPGovern cannot independently verify that the off-server copy exists or is usable.

---

## 4. Operator-owned key responsibility

The operator must store the age private key somewhere outside the protected server.

Acceptable examples:

- encrypted password manager attachment,
- secure institutional key vault,
- offline encrypted storage,
- sealed operational escrow with access controls.

Unacceptable examples:

- only copy on the WPGovern server,
- only copy inside the encrypted backup directory,
- only copy in a screenshot or chat transcript,
- only copy in an unencrypted local file.

After the key is backed up, record acknowledgement:

```bash
wpgovern-restore ack-key-backup --location-hint "off-server key vault"
```

The wording is intentionally “acknowledged,” not “verified.”

---

## 5. Routine backup checks

### List backups

```bash
wpgovern-restore list
```

Confirm that a recent full backup exists.

### Run operational audit

```bash
wpgovern-install-audit --complete
```

Confirm backup-related fix-IDs are not failing.

### Run restore-test

```bash
wpgovern-restore restore-test
```

Restore-test proves that the latest backup can be decrypted and loaded into a test schema.

A system with backups but no recent restore-test should not be treated as fully proven.

---

## 6. Restore-test standard

A successful restore-test should establish:

- the age private key can decrypt the backup,
- the SQL stream can load into a test schema,
- expected WordPress tables are present,
- `wp_options` contains rows,
- the test schema is dropped after the test.

If restore-test fails:

1. Treat recoverability as degraded.
2. Do not delete existing backups.
3. Preserve logs.
4. Run audit.
5. Diagnose key, backup file, database, or schema failure.
6. Re-run restore-test after correction.

---

## 7. Disaster scenarios

### Scenario A — Row mistake or content corruption

Use point-in-time recovery if available.

Procedure:

1. Stop normal editing activity.
2. Identify approximate incident time.
3. List available backups.
4. Validate the intended restore point.
5. Restore from full backup plus applicable binlogs.
6. Run governance-check and install-audit.
7. Record incident notes.

### Scenario B — Full database corruption

Procedure:

1. Confirm age private key is present.
2. Confirm target backup exists.
3. Restore governance state before database.
4. Restore SQL backup.
5. Apply applicable binlogs.
6. Run verification.

### Scenario C — Server loss

Procedure:

1. Provision replacement server.
2. Reinstall WPGovern to the required phase baseline.
3. Restore age private key from off-server storage.
4. Copy encrypted backups to the expected backup directory.
5. Run restore.
6. Run audit and governance-check.

### Scenario D — age private key loss

If no off-server copy exists, encrypted backups are not recoverable.

WPGovern cannot bypass age encryption. This is intentional.

---

## 8. Restore command model

The restore command is destructive.

Use:

```bash
wpgovern-restore <backup_ts>
```

The timestamp format is:

```text
YYYYMMDDTHHMMSSZ
```

Example:

```bash
wpgovern-restore 20260523T000000Z
```

The restore process should follow this order:

```text
validate -> install-check -> governance state -> database -> verify
```

Governance state must be restored before database so that audit and governance evidence remain coherent.

---

## 9. Restore exit codes

| Exit code | Meaning |
|---|---|
| 0 | Restore complete and verification passed. |
| 10 | Validate phase failed. Backup files, key, decryptability, or database readiness may be broken. |
| 11 | Install check failed. The target box is not ready for restore. |
| 12 | Governance state restore failed. |
| 13 | Database restore failed. |
| 14 | Post-restore verification failed. |

Operators should preserve the exact exit code in incident notes.

---

## 10. Pre-restore checklist

Before running a destructive restore, confirm:

```text
[ ] Correct backup timestamp selected.
[ ] age private key exists and has correct permissions.
[ ] Encrypted SQL backup exists.
[ ] Encrypted governance backup exists.
[ ] Target system has completed required install phases.
[ ] Current incident reason is recorded.
[ ] Operator understands current data will be overwritten.
[ ] Recent audit/backup evidence has been saved if needed.
```

A future Local Console restore wizard must require explicit typed confirmation before running destructive restore.

---

## 11. Post-restore checklist

After restore:

```bash
wpgovern-install-audit --complete
```

Also run the governance check if available:

```bash
wpgovern governance-check
```

Confirm:

```text
[ ] WordPress site loads.
[ ] Admin login works.
[ ] Expected content exists.
[ ] Audit has no unexpected FAIL findings.
[ ] Governance check result is recorded.
[ ] Incident notes include command, timestamp, exit code, and result.
```

---

## 12. Evidence for institutional use

For institutional reporting, preserve:

- latest full backup timestamp,
- latest binlog rotation timestamp,
- latest restore-test result,
- WPG-DR-01 acknowledgement,
- audit output,
- governance-check result,
- operator incident notes.

A future DR Attestation Report should compile these into a human-readable evidence document.

Required wording:

```text
WPGovern verifies local encrypted backup and restore-test evidence.
WPGovern records operator acknowledgement of off-server key backup.
WPGovern does not independently verify off-server key custody.
```

---

## 13. Recovery readiness standard

WPGovern should be considered recovery-ready only when:

```text
Recent full backup exists.
Binlog rotation is current.
Restore-test has passed recently.
age private key backup is acknowledged.
No backup-related audit FAIL findings exist.
The operator knows where the private key is stored.
```

If any item is false, treat recovery readiness as degraded.