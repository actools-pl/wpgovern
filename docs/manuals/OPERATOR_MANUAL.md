# Operator Manual

## Status

This manual is for the daily operator of a WPGovern v1.0.0 installation. It explains how to monitor the system, read operational evidence, respond to warnings and failures, and preserve the single-tenant governance model.

## 1. Operating principle

WPGovern is operated through explicit commands and recorded evidence.

The command line is the authority in v1.0.0. There is no Local Console and no `wpgovern-status --json` command in v1.0.0. Machine-readable status output is planned for a future release.

Daily operation should use:

```bash
wpgovern-install-audit --complete
```

and backup/restore commands through:

```bash
wpgovern-restore
```

## 2. Four operational states

The operator should think in four states:

| State | Meaning |
|---|---|
| Governed | Governance baseline and checks remain acceptable. |
| Operable | The stack, WordPress layer, audit probes, and runtime health are acceptable. |
| Recoverable | Backups, binlogs, restore-test, and key acknowledgement are current. |
| Evidence-backed | Important checks and actions have recorded evidence. |

A WPGovern system is not merely installed. It must remain governed, operable, recoverable, and evidence-backed.

## 3. Daily routine

Run:

```bash
wpgovern-install-audit --complete
```

Expected daily condition:

```text
No unexpected FAIL findings.
WARN findings are reviewed and understood.
```

Also check available backups:

```bash
wpgovern-restore list
```

If the audit reports backup or restore-test findings, read BACKUP_AND_DR_MANUAL.md Section 14.

## 4. Weekly routine

Run restore-test:

```bash
wpgovern-restore restore-test
```

Expected condition:

```text
Restore-test passes.
```

If restore-test fails, treat the system as not fully recoverable until corrected.

## 5. Monthly routine

Review disaster-recovery key acknowledgement:

```bash
wpgovern-install-audit --complete
```

Confirm that `WPG-DR-01` is PASS and that the operator still knows where the off-server age private key copy is stored.

`WPG-DR-01` is acknowledged or operator-attested. It is not independently verified by WPGovern.

## 6. After major changes

After DNS, credentials, WordPress configuration, backup location, systemd timer, firewall, Docker, or restore procedure changes, run:

```bash
wpgovern-install-audit --complete
wpgovern-restore restore-test
```

Preserve output if the change matters for institutional evidence.

## 7. Reading PASS, WARN, and FAIL

Use AUDIT_MANUAL.md Section 5 as the authority for audit semantics.

Short form:

| Status | Meaning |
|---|---|
| PASS | Condition is acceptable. |
| WARN | Operator attention is required or recommended. |
| FAIL | Required condition is broken. |

Do not ignore FAIL findings. Do not dismiss WARN findings without understanding them.

## 8. Core commands

### Complete audit

```bash
wpgovern-install-audit --complete
```

### Security-focused audit

```bash
wpgovern-install-audit --security
```

### Machine-readable audit JSON

```bash
wpgovern-install-audit --json
```

### List backups

```bash
wpgovern-restore list
```

### Run restore-test

```bash
wpgovern-restore restore-test
```

### Acknowledge off-server age private key backup

```bash
wpgovern-restore ack-key-backup --location-hint "off-server key location"
```

### Full restore

```bash
wpgovern-restore <backup_ts>
```

Example:

```bash
wpgovern-restore 20260524T030000Z
```

Full restore is destructive. Read BACKUP_AND_DR_MANUAL.md Section 9 before running it.

## 9. Incident handling: audit shows FAIL

If audit shows FAIL:

1. Save the audit output.
2. Identify the fix-ID and message.
3. Read the suggested fix command if present.
4. Apply the correction carefully.
5. Re-run the same audit command.
6. Preserve before/after evidence if the incident matters.

If the FAIL relates to backups, restore-test, or key acknowledgement, also read BACKUP_AND_DR_MANUAL.md Section 14.

## 10. Incident handling: backup is stale

If `WPG-BKUP-001` reports WARN or FAIL:

1. Check backup timers and service status.
2. Confirm backup directory exists.
3. Trigger or repair the full backup path as indicated by the audit finding.
4. Re-run audit.
5. Run restore-test after backup health is restored.

Do not delete existing encrypted backups during diagnosis unless a retention procedure explicitly requires it.

## 11. Incident handling: restore-test fails

If restore-test fails:

1. Treat recoverability as degraded.
2. Preserve the command output.
3. Confirm age private key is present.
4. Confirm recent encrypted backup exists.
5. Confirm MariaDB is available.
6. Re-run after correcting the cause.

Do not claim disaster-recovery readiness until restore-test passes again.

## 12. What not to touch manually

Do not manually edit or delete these unless following a documented repair procedure:

- installer state file,
- governance state,
- generated Docker Compose files,
- generated WordPress configuration,
- age private key,
- encrypted backup files,
- systemd backup units,
- backup metadata facts.

Manual edits can make audit and governance evidence inconsistent.

## 13. Operator handover checklist

Before handing WPGovern to another operator, provide:

```text
[ ] Server access procedure.
[ ] DNS and domain details.
[ ] WPGovern install directory.
[ ] Path to wpgovern.env.
[ ] Backup directory.
[ ] Off-server age private key custody location.
[ ] Latest wpgovern-install-audit --complete output.
[ ] Latest wpgovern-restore restore-test result.
[ ] Known WARN findings and reasons.
[ ] Recent incidents and resolutions.
[ ] SECURITY_TRUST_MODEL.md and BACKUP_AND_DR_MANUAL.md.
```

Do not hand over a system without explaining the private key custody boundary.

## 14. What WPGovern does not do for the operator

WPGovern does not:

- protect against a compromised root operator,
- verify off-server key custody,
- replace WordPress security plugins,
- eliminate the need for DNS and server administration,
- make restore safe without operator judgement,
- operate as a SaaS fleet dashboard.

See SECURITY_TRUST_MODEL.md Section 10 for known limitations.

## 15. Closure / Summary

Daily WPGovern operation is disciplined, not complicated: run audit, watch backup and restore-test evidence, keep age private key custody clear, and preserve evidence when something changes. The system is trustworthy only when the operator keeps its governed, operable, recoverable, and evidence-backed states current.