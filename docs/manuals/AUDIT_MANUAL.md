# Audit Manual

## Status

This manual is for operators, auditors, and evaluators using `wpgovern-install-audit` in WPGovern v1.0.0. It explains audit modes, output formats, fix-ID semantics, and exit codes.

## 1. Audit doctrine

WPGovern audit output follows this doctrine:

```text
boringly predictable, brutally honest, immediately useful
```

Predictable means the same checks run in the same mode each time.

Honest means WPGovern should not hide known failures or short-circuit after the first problem.

Useful means every finding should have a fix-ID, a status, a priority, and where possible a suggested operator action.

## 2. Command

The audit command is:

```bash
wpgovern-install-audit
```

Default mode is complete audit.

Common usage:

```bash
wpgovern-install-audit --complete
wpgovern-install-audit --security
wpgovern-install-audit --ci
wpgovern-install-audit --json
wpgovern-install-audit --env-file /path/to/wpgovern.env --complete
```

The command supports `--version` and `--help`.

## 3. Audit modes

The v1.0.0 audit entry script supports these modes:

| Flag | Meaning |
|---|---|
| `--complete` | Runs all audit layers. This is the default routine operator mode. |
| `--security` | Runs security layer and security-relevant WordPress checks. |
| `--ci` | Emits machine-stable text output sorted by fix-ID with no colors. |
| `--json` | Emits structured JSON output. |
| `--env-file <path>` | Loads a specific environment file using read-only env discovery. |

Unknown flags exit with code `2`.

## 4. Audit layers

The audit system groups probes by layer:

| Layer | Purpose |
|---|---|
| 1 | WordPress truth via wp-cli. |
| 1.5 | Behavioral checks such as login form, cache headers, Redis writeback, and trusted-host behavior. |
| 2 | Infrastructure health such as containers, disk, memory, TLS, backups, restore-test, and database reachability. |
| 3 | Security posture such as HTTPS, headers, ports, pinned images, and DR key acknowledgement. |

The operator does not normally need to choose layers manually. Use `--complete` for routine operation.

## 5. PASS, WARN, and FAIL

| Status | Meaning | Operator action |
|---|---|---|
| PASS | The condition is currently acceptable. | Record or continue. |
| WARN | The condition needs attention or acknowledgement, but is not necessarily broken. | Review and decide whether to fix or consciously defer. |
| FAIL | A required condition is broken. | Treat as an operational issue. Fix and re-run audit. |

WARN is not decorative. It exists so the operator can see risks before they become failures.

FAIL should not be ignored before a production claim, restore operation, or institutional handover.

## 6. Exit codes

The audit exit-code contract is:

| Exit code | Meaning |
|---|---|
| 0 | No FAIL findings. WARN findings may exist. |
| 1 | One or more FAIL findings are present. |
| 2 | Internal error or probe crash. |

Exit code `2` has precedence over exit code `1`. If a probe crashes unexpectedly, the audit should still print findings but return `2`.

## 7. Fix-ID namespaces

WPGovern v1.0.0 uses these fix-ID namespaces:

| Namespace | Area |
|---|---|
| `WPG-WP-*` | WordPress operational findings. |
| `WPG-STACK-*` | Stack and infrastructure findings. |
| `WPG-SEC-*` | Security posture findings. |
| `WPG-CFG-*` | Configuration findings. |
| `WPG-BKUP-*` | Backup and restore-test findings. |
| `WPG-DR-*` | Disaster-recovery responsibility findings. |

Some namespace placeholders may appear only as internal probe-error IDs. Operator-facing output should be read by exact finding text, not namespace alone.

## 8. Common fix-IDs

Common operator-visible findings include:

| Fix-ID | Meaning |
|---|---|
| `WPG-WP-001` | WordPress core version was checked. |
| `WPG-WP-002` | WordPress plugin update status. |
| `WPG-WP-003` | WordPress cron status. |
| `WPG-WP-004` | WordPress site URL/configuration drift. |
| `WPG-WP-007` | WordPress security plugin delegation signal. |
| `WPG-WP-008` | WordPress login form behavior. |
| `WPG-STACK-001` | Expected containers are healthy or unhealthy. |
| `WPG-STACK-002` | Disk pressure. |
| `WPG-STACK-003` | Memory pressure. |
| `WPG-STACK-004` | MariaDB reachability from PHP. |
| `WPG-STACK-005` | Redis writeback behavior, if Redis is configured. |
| `WPG-SEC-001` | TLS certificate expiry. |
| `WPG-SEC-002` | HTTPS enforcement. |
| `WPG-SEC-003` | HSTS header. |
| `WPG-SEC-004` | X-Content-Type-Options header. |
| `WPG-SEC-005` | Server header exposure. |
| `WPG-SEC-006` | X-Frame-Options header. |
| `WPG-SEC-007` | Content-Security-Policy header. |
| `WPG-SEC-008` | Unexpected listening ports. |
| `WPG-SEC-009` | Docker image digest pinning. |
| `WPG-SEC-010` | Cache-control behavior on `wp-login.php`. |
| `WPG-SEC-011` | Trusted-host spoof rejection. |
| `WPG-BKUP-001` | Full backup currency. |
| `WPG-BKUP-002` | Restore-test integrity and age. |
| `WPG-DR-01` | age private key backup acknowledgement. |

`WPG-DR-01` is operator-attested. PASS means WPGovern recorded that the operator acknowledged off-server key backup. It does not mean WPGovern independently verified off-server custody.

## 9. JSON output

Use:

```bash
wpgovern-install-audit --json
```

The JSON output has this shape:

```json
{
  "wpgovern_install_audit_version": "1.0",
  "timestamp": "2026-05-23T00:00:00Z",
  "domain": "example.com",
  "exit_code": 0,
  "summary": {
    "pass": 10,
    "warn": 2,
    "fail": 0
  },
  "findings": [
    {
      "fix_id": "WPG-BKUP-001",
      "priority": "HIGH",
      "status": "PASS",
      "layer": 2,
      "message": "Full backup current: last backup 4h ago",
      "fix": null
    }
  ]
}
```

JSON mode is intended for automation and future status surfaces. In v1.0.0 there is no separate `wpgovern-status --json` command.

## 10. How audit output drives action

When a finding appears:

1. Read the fix-ID and message.
2. Note PASS, WARN, or FAIL.
3. Read the suggested fix command if present.
4. Decide whether the issue is immediate or can be scheduled.
5. Apply the fix.
6. Re-run the same audit mode.
7. Preserve before/after evidence if the result matters institutionally.

Do not fix from memory when the audit gives a specific command. Read the finding text first.

## 11. Security plugin delegation signal

`WPG-WP-007` is a visible architectural delegation signal. WPGovern does not replace a WordPress content-layer security plugin. If no recognized security plugin is active, the audit emits a warning.

This does not mean WPGovern failed to install. It means the operator still owns the content-layer security decision.

See SECURITY_TRUST_MODEL.md Section 10 for known limitations.

## 12. Backup and DR findings

`WPG-BKUP-001` checks full backup currency.

`WPG-BKUP-002` checks restore-test evidence.

`WPG-DR-01` checks whether the operator has acknowledged off-server age private key backup.

These findings are central to the recoverable doctrine. See BACKUP_AND_DR_MANUAL.md Section 13 for recovery readiness.

## 13. Closure / Summary

`wpgovern-install-audit` is the operator's routine truth surface for WPGovern v1.0.0. It does not silently make the system safe. It tells the operator, in repeatable terms, whether the installation is governed, operable, and recoverable enough to trust.