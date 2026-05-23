# Backup and Disaster Recovery Manual

## Status

This manual is for operators, sysadmins, and emergency recovery personnel responsible for WPGovern v1.0.0. It explains the backup model, restore model, restore-test process, and operator-owned age private key responsibility.

## 1. Recovery doctrine

WPGovern's recovery doctrine is:

```text
Recoverable means encrypted full backups, encrypted binlog rotation, restore-test evidence, and operator-attested key custody are all in place.
```

The doctrinal recovery goals are:

| Claim | Meaning |
|---|---|
| RPO <= 1 hour | Hourly binlog rotation is intended to limit data loss between full backups. |
| RTO <= 30 minutes | A prepared operator should be able to reinstall and restore a small WPGovern site within this target. |
| Encrypted at rest | Backup artifacts are age-encrypted. Plaintext SQL should not be written to disk during normal full backup. |
| Restore-test evidence | Backups are not considered proven until restore-test has passed. |
| Key custody acknowledgement | The operator must acknowledge off-server custody of the age private key. |

These claims depend on correct operation and operator custody of the private key.

## 2. Full backup model

The full backup captures two major artifacts:

- WordPress database backup as an age-encrypted SQL stream,
- governance state and configuration as an age-encrypted tar stream.

The database backup uses a stream pipeline:

```text
mariadb-dump -> age -> full-<timestamp>.sql.age
```

Plaintext SQL should not be written to disk.

The governance tarball intentionally excludes the age private key. The private key must never be stored inside the same encrypted backup set it is needed to decrypt.

## 3. Binlog rotation model

Binlog rotation supports point-in-time recovery after a full backup.

The intended order is:

```text
encrypt binlog -> verify encrypted file -> delete plaintext binlog
```

If encryption fails or produces an empty encrypted output, plaintext should be preserved rather than deleted.

Binlog rotation is intended to run hourly through systemd timers.

## 4. Restore-test process

The restore-test command is:

```bash
wpgovern-restore restore-test
```

Restore-test is non-destructive to the production WordPress database. It should:

1. find the most recent full backup,
2. decrypt it using the age private key,
3. load it into a temporary test schema,
4. check expected WordPress tables,
5. check that `wp_options` has rows,
6. record PASS or FAIL state,
7. drop the test schema.

Weekly restore-test is recommended.

A recent backup without a recent successful restore-test should not be treated as fully proven.

## 5. age keypair responsibility

WPGovern generates or manages an age keypair for backup encryption.

The public key encrypts backups.

The private key decrypts backups.

Critical rule:

```text
If the age private key is lost and no usable off-server copy exists, encrypted backups are not recoverable.
```

The operator must store the private key off-server.

WPGovern records acknowledgement with:

```bash
wpgovern-restore ack-key-backup --location-hint "off-server key location"
```

WPGovern records this as:

```text
WPG-DR-01: acknowledged (operator-attested)
```

WPGovern cannot independently verify that the off-server key copy exists or is usable. See SECURITY_TRUST_MODEL.md Section 7 for the key custody boundary.

## 6. Restore command syntax

The restore command is:

```bash
wpgovern-restore <backup_ts>
```

The backup timestamp format is:

```text
YYYYMMDDTHHMMSSZ
```

Example:

```bash
wpgovern-restore 20260524T030000Z
```

Other supported subcommands are:

```bash
wpgovern-restore restore-test
wpgovern-restore list
wpgovern-restore ack-key-backup --location-hint "off-server key location"
wpgovern-restore --help
wpgovern-restore --version
```

There is no `wpgovern-restore --dry-run` command in v1.0.0.

## 7. Restore phase sequence

A full restore runs five phases:

| Phase | Purpose |
|---|---|
| validate | Confirm backup files, age key, decryptability, and MariaDB readiness. |
| install-check | Confirm required WPGovern install phases completed on the target box. |
| governance state | Restore governance state before the database. |
| database | Restore SQL backup and apply applicable binlogs. |
| verify | Run post-restore verification through governance and audit checks. |

The order matters. Governance state is restored before database so the restored system retains coherent governance context.

## 8. Restore exit codes

Full restore exit codes are:

| Code | Meaning |
|---|---|
| 0 | Restore complete and checks passed. |
| 10 | Validate phase failed. |
| 11 | Install check failed. |
| 12 | Governance state restore failed. |
| 13 | Database restore failed. |
| 14 | Post-restore verification failed. |

Preserve the exact exit code in incident notes.

## 9. Pre-restore checklist

Before a destructive restore, confirm:

```text
[ ] Correct backup timestamp selected.
[ ] Current data loss implications are understood.
[ ] age private key exists and has the expected permissions.
[ ] SQL backup file exists.
[ ] Governance backup file exists.
[ ] Target server completed required WPGovern install phases.
[ ] Current audit evidence has been saved if needed.
[ ] Operator has authority to overwrite the current database and governance state.
```

Do not run restore casually. Restore overwrites current state.

## 10. Post-restore verification

After restore, run:

```bash
wpgovern-install-audit --complete
```

Also run the governance check if available in the environment:

```bash
wpgovern governance-check
```

Confirm:

```text
[ ] WordPress loads.
[ ] Expected content exists.
[ ] Audit has no unexpected FAIL findings.
[ ] Governance check result is acceptable.
[ ] Restore command, timestamp, exit code, and findings are recorded.
```

See AUDIT_MANUAL.md Section 6 for audit exit-code semantics.

## 11. Disaster scenario: data corruption

For mistaken content edits or database corruption:

1. Stop normal editing activity.
2. Identify the approximate incident time.
3. List available backups.
4. Select the safest restore timestamp.
5. Confirm age private key availability.
6. Run restore.
7. Run post-restore verification.
8. Preserve incident notes.

## 12. Disaster scenario: full server loss

For server loss:

1. Provision a replacement Ubuntu 24.04 LTS server.
2. Restore or recreate required DNS pointing.
3. Install WPGovern to the required phase baseline.
4. Restore the age private key from off-server custody.
5. Copy encrypted backups to the expected backup directory.
6. Run `wpgovern-restore <backup_ts>`.
7. Run audit and governance checks.

The RTO claim assumes a prepared operator, available backups, available key material, and a small-to-moderate site size.

## 13. Disaster scenario: age key loss

If the age private key is lost and no usable off-server copy exists, encrypted backups cannot be decrypted.

WPGovern cannot bypass age encryption.

This is intentional. The system makes key responsibility explicit through WPG-DR-01. It does not remove that responsibility.

## 14. Recovery readiness standard

Treat the system as recovery-ready only when:

```text
[ ] Full backup is current.
[ ] Binlog rotation is current.
[ ] Restore-test has passed within the required window.
[ ] WPG-DR-01 is acknowledged (operator-attested).
[ ] No backup-related audit FAIL findings exist.
[ ] The operator knows where the off-server age private key copy is stored.
```

See AUDIT_MANUAL.md Section 12 for backup and DR audit findings.

## 15. Closure / Summary

WPGovern v1.0.0 makes recoverability observable through encrypted backups, binlog rotation, restore-test evidence, and operator-attested key custody. Recovery is only as strong as the complete chain: backup files, private key custody, restore procedure, and operator discipline.