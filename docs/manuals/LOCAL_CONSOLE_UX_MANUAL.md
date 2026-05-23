# WPGovern Local Console UX Manual

## Status

Institutional UX manual for the future WPGovern Local Console.

This manual defines the correct user-experience direction for WPGovern without changing the product into a fleet SaaS or agency dashboard.

---

## 1. Product identity

WPGovern is a single-tenant, single-user, single-node governance appliance for one protected WordPress installation.

The correct UX is therefore:

```text
Local evidence console for one governed site.
```

The incorrect UX is:

```text
Fleet dashboard for many client sites.
```

The Local Console must preserve WPGovern's identity.

---

## 2. UX principle

```text
The CLI remains the authority.
The console explains, summarizes, and safely wraps evidence.
```

The console must not become a second control plane. It should read the same evidence the operator can inspect by command line.

---

## 3. Non-goals

Do not build these for the initial console:

- fleet view,
- agency owner portal,
- multi-tenant SaaS,
- remote agents,
- Redis/Celery/BullMQ task queue,
- arbitrary command runner,
- one-click destructive restore,
- public unauthenticated web dashboard.

These may be different products later. They are not WPGovern v1 console scope.

---

## 4. Console screens

### 4.1 System State

The main screen should show four cards:

| Card | Meaning |
|---|---|
| Governed | Governance baseline and checks are acceptable. |
| Operable | Stack, audit, and runtime health are acceptable. |
| Recoverable | Backup, binlog, and restore-test posture is acceptable. |
| Key Safety | age private key backup acknowledgement state. |

Example:

```text
Recoverable: WARN
Last full backup: 31 hours ago
Last restore-test: passed 5 days ago
Recommended action: run a full backup.
```

### 4.2 Evidence Timeline

The timeline should show important operational events:

```text
Today 02:00    Binlog rotation completed
Today 00:12    Full backup completed
Yesterday      Restore-test passed
May 21         age key backup acknowledged
```

Each event should expose:

- timestamp,
- event type,
- result,
- source command,
- exit code if available,
- expandable raw evidence.

### 4.3 Backup and DR

This screen answers:

- Do I have a recent full backup?
- Do I have recent binlogs?
- Has restore-test passed recently?
- Has the age private key backup been acknowledged?

The wording must remain accurate:

```text
age key backup: acknowledged, operator-attested
```

Do not say “verified” for off-server key custody.

### 4.4 Restore Wizard

The restore wizard must be guarded.

Steps:

1. Choose restore point.
2. Validate restore point.
3. Show consequence summary.
4. Require typed confirmation.
5. Execute controlled restore job.
6. Show exact result and exit code.

Typed confirmation should be explicit:

```text
RESTORE THIS SITE
```

### 4.5 DR Attestation Export

The console should eventually generate a DR Attestation Report.

Sections:

- site identity,
- governance status,
- audit status,
- backup currency,
- restore-test history,
- binlog rotation status,
- age key acknowledgement,
- last 30 days of backup events,
- operator attestation statement,
- raw evidence appendix.

---

## 5. WPGovern Advisor

The console may include a constrained assistant panel called:

```text
WPGovern Advisor
```

It should answer evidence-grounded questions such as:

- Am I recoverable right now?
- Why is the system warning?
- What should I do next?
- Can I safely restore from this backup?
- What evidence can I give to a client or institution?

The Advisor may explain and recommend. It must not silently execute destructive commands.

Example answer:

```text
Recoverability is currently WARN.

Reason:
- Last full backup is 31 hours old.
- Restore-test passed 5 days ago.
- age key backup is acknowledged.

Recommended action:
Run a manual full backup, then run restore-test.

Evidence:
- WPG-BKUP-001: WARN
- WPG-BKUP-002: PASS
- WPG-DR-01: PASS, operator-attested
```

---

## 6. First implementation: UX-0

The first implementation should not be a web app.

The first implementation should be a stable status contract:

```bash
wpgovern-status --json
```

The command must be read-only.

It should aggregate:

- installer state,
- audit result,
- backup status,
- restore-test status,
- DR key acknowledgement,
- governance-check result if available.

---

## 7. Status JSON contract

Example:

```json
{
  "site": {
    "domain": "example.com",
    "mode": "single_tenant",
    "tenant_count": 1
  },
  "overall": {
    "status": "WARN",
    "summary": "System is governed and operable, but full backup is aging."
  },
  "governance": {
    "status": "PASS",
    "last_check_at": "2026-05-23T02:15:00Z",
    "source": "governance-check"
  },
  "operations": {
    "status": "PASS",
    "audit_fail_count": 0,
    "audit_warn_count": 2,
    "source": "wpgovern-install-audit"
  },
  "recoverability": {
    "status": "WARN",
    "last_full_backup_at": "2026-05-22T00:00:00Z",
    "last_binlog_rotation_at": "2026-05-23T02:00:00Z",
    "last_restore_test_at": "2026-05-18T02:00:00Z",
    "last_restore_test_result": "PASS",
    "age_key_backup": "ACKNOWLEDGED_OPERATOR_ATTESTED"
  },
  "next_action": {
    "label": "Run full backup",
    "risk": "safe",
    "command": "wpgovern-backup-full"
  },
  "evidence": {
    "state_file": "/opt/wpgovern-install/.wpgovern-installer-state.json",
    "generated_at": "2026-05-23T10:00:00Z"
  }
}
```

The JSON must not contain secrets.

---

## 8. Status mapping

Recommended deterministic mapping:

```text
overall = FAIL if any major category is FAIL
overall = WARN if no FAIL but at least one WARN
overall = PASS only if all core categories PASS
```

Governed:

```text
governance-check exit 0 -> PASS
non-zero -> WARN or FAIL depending available evidence
```

Operable:

```text
install-audit FAIL -> FAIL
install-audit WARN only -> WARN
no FAIL/WARN -> PASS
```

Recoverable:

```text
backup FAIL -> FAIL
restore-test FAIL -> FAIL
backup WARN or restore-test WARN -> WARN
otherwise PASS
```

Key Safety:

```text
WPG-DR-01 PASS -> ACKNOWLEDGED_OPERATOR_ATTESTED
WPG-DR-01 WARN -> NOT_ACKNOWLEDGED
```

---

## 9. Action safety

UX-0 and UX-1 should be read-only.

Later controlled actions must follow these rules:

- no long-running command directly inside HTTP request path,
- no arbitrary command execution,
- strict allowlist of supported actions,
- exact exit code preserved,
- logs and evidence preserved,
- destructive actions require typed confirmation,
- restore requires attestation.

Acceptable future action mechanisms:

- `systemd-run` controlled oneshot,
- local root-owned wrapper,
- job state file under WPGovern state directory.

---

## 10. Security requirements

A local console must not be publicly exposed without authentication.

Initial safe options:

- localhost-only UI,
- static report generation,
- protected admin-only local endpoint,
- SSH tunnel access.

The console must not display secrets:

- database passwords,
- WordPress admin password,
- AUTH_KEY/SALT values,
- age private key contents.

---

## 11. Repository implementation plan

Add UX-0 files:

```text
modules/console/status.sh
modules/console/status_entry.sh
modules/console/install_shim.sh
installer_tests/test_console_status.bats
docs/manuals/LOCAL_CONSOLE_UX_MANUAL.md
PHASE_UX0_README.md
```

Do not add a web app until `wpgovern-status --json` is stable.

---

## 12. UX acceptance criteria

A first UX foundation is acceptable when:

```text
wpgovern-status --json emits valid JSON.
The command is read-only.
The command does not leak secrets.
The output summarizes governed, operable, recoverable, and key-safety state.
Missing inputs degrade to UNKNOWN or WARN, not a crash.
Tests cover PASS/WARN/FAIL mapping.
Documentation states that CLI remains authority.
```

---

## 13. Institutional UX tone

The console should speak calmly and precisely.

Good:

```text
Recoverability is WARN because the latest full backup is older than the recommended window.
```

Avoid:

```text
Backup broken!!!
```

Good:

```text
age key backup is acknowledged by the operator. WPGovern cannot independently verify off-server key custody.
```

Avoid:

```text
Private key backup verified.
```

---

## 14. Final UX rule

The WPGovern Local Console must make the system easier to operate without weakening governance discipline.

If a UX feature hides evidence, bypasses confirmation, weakens exit-code semantics, or turns a single-tenant appliance into a fleet SaaS, it does not belong in the first console.