# WPGovern Operator Manual

## Status

Institutional operations manual for a single-tenant, single-user WPGovern installation.

This manual is written for the person responsible for running an installed WPGovern system. It assumes the system has already been installed and that the operator has shell access to the server.

WPGovern is not a fleet SaaS. It is a governed single-site WordPress appliance. The operator’s job is to keep the one protected installation governed, operable, recoverable, and evidence-backed.

---

## 1. Operating principle

WPGovern is operated through explicit commands and recorded evidence.

The operator should think in four states:

| State | Meaning |
|---|---|
| Governed | The baseline, signatures, and governance checks agree with the expected system state. |
| Operable | The live stack, audit probes, WordPress layer, and infrastructure health are acceptable. |
| Recoverable | Backups, binlogs, restore-test, and DR key acknowledgement are current. |
| Evidence-backed | The system can show when checks, backups, restore-tests, and acknowledgements occurred. |

The command line remains the authority. Any future local console must explain and present this evidence; it must not invent a second source of truth.

---

## 2. Operator responsibilities

The operator is responsible for:

- running periodic checks,
- reading WARN and FAIL results,
- keeping the age private key backed up off-server,
- confirming backups are recent,
- running restore-tests,
- preserving logs and state evidence,
- avoiding manual edits to governed files unless a repair procedure explicitly allows it.

The operator is not expected to inspect raw Bash logs every day. The normal operating pattern is to run the audit/status commands and act on the resulting PASS, WARN, or FAIL signals.

---

## 3. Routine operating cadence

### Daily

Run the operational audit:

```bash
wpgovern-install-audit --complete
```

Expected result:

```text
No FAIL findings.
WARN findings are allowed only when understood and intentionally deferred.
```

Check recent backup state:

```bash
wpgovern-restore list
```

Confirm that at least one recent full backup exists and that binlog rotation is not stale.

### Weekly

Run a restore-test:

```bash
wpgovern-restore restore-test
```

Expected result:

```text
Restore-test PASSED
```

If restore-test fails, treat the system as not fully recoverable until the failure is corrected.

### Monthly

Review the DR key acknowledgement:

```bash
wpgovern-install-audit --complete
```

Confirm that WPG-DR-01 is PASS. The wording is important: WPGovern records that the key backup was acknowledged by the operator. It does not independently verify off-server key custody.

### After any major change

After changing DNS, WordPress configuration, backup storage, credentials, firewall rules, or restore procedures, run:

```bash
wpgovern-install-audit --complete
wpgovern-restore restore-test
```

---

## 4. Reading audit results

WPGovern audit results use three operational states:

| Result | Operator meaning |
|---|---|
| PASS | The check is currently acceptable. |
| WARN | The system is still usable, but action is recommended. |
| FAIL | A required condition is broken. Treat as an operational incident. |

A WARN is not decorative. It means the operator should either fix the condition or consciously defer it and record why.

A FAIL should not be ignored before a production claim, restore operation, client evidence report, or handover.

---

## 5. Core commands

### Full audit

```bash
wpgovern-install-audit --complete
```

Use this for routine operator checks.

### Security-focused audit

```bash
wpgovern-install-audit --security
```

Use this when reviewing security posture.

### Machine-readable audit

```bash
wpgovern-install-audit --json
```

Use this for a future local console or evidence export.

### List backups

```bash
wpgovern-restore list
```

Use this before restore planning.

### Run restore-test

```bash
wpgovern-restore restore-test
```

Use this weekly and after backup-related changes.

### Acknowledge age key backup

```bash
wpgovern-restore ack-key-backup --location-hint "off-server location description"
```

Use this only after the operator has actually backed up the age private key off-server.

---

## 6. Evidence discipline

Evidence matters because WPGovern is a governance system, not just an installer.

Preserve:

- audit results,
- restore-test results,
- backup timestamps,
- age key acknowledgement timestamp,
- governance-check results,
- relevant state-file facts,
- incident notes.

For future UX work, these should feed a DR Attestation Report. The report should explain what WPGovern verified and what the operator attested.

---

## 7. What not to do

Do not manually delete backup files because they look old unless a retention policy says so.

Do not edit governed configuration files without understanding that the next governance check may fail.

Do not run destructive restore commands casually.

Do not store the only copy of the age private key on the same server as the encrypted backups.

Do not treat WPG-DR-01 PASS as off-server verification. It is an operator acknowledgement.

Do not expose any future local console publicly without authentication and a clear threat model.

---

## 8. Incident handling

### If audit shows FAIL

1. Record the exact command and output.
2. Identify the fix-ID.
3. Read the relevant manual section or runbook entry.
4. Fix the cause.
5. Re-run the audit.
6. Keep the before/after evidence.

### If backup is stale

1. Run a manual full backup if available.
2. Confirm the backup appears in `wpgovern-restore list`.
3. Run restore-test.
4. Re-run audit.

### If restore-test fails

Treat recoverability as degraded.

Do not claim disaster recovery readiness until restore-test passes again.

### If age private key is missing

Encrypted backups cannot be restored without the private key. Recoverability depends on an off-server copy. If no copy exists, WPGovern cannot recover the encrypted backups.

---

## 9. Operator handover checklist

Before transferring responsibility to another operator, provide:

- server access procedure,
- DNS and domain information,
- location of WPGovern install directory,
- location of encrypted backups,
- location of off-server age private key backup,
- latest audit output,
- latest restore-test output,
- known WARN findings,
- incident history,
- this manual and the Backup & DR Manual.

---

## 10. Closure rule for routine operation

The system is in acceptable daily operating condition when:

```text
wpgovern-install-audit --complete has no FAIL findings.
Backups are recent.
Restore-test is within the required window.
WPG-DR-01 is acknowledged.
No unresolved restore or governance incident is open.
```

If any of these are false, the operator should treat the system as needing attention.