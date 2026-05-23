# WPGovern Security and Trust Model Manual

## Status

Institutional security and trust model manual for a single-tenant, single-user WPGovern installation.

This document explains what WPGovern is designed to protect, what assumptions it makes, and what remains the operator's responsibility.

---

## 1. Security posture in one sentence

WPGovern is a single-node governance appliance for one WordPress installation. It hardens installation, records governance evidence, audits operational posture, and supports encrypted recovery; it does not remove the need for operator key custody, server access control, or careful incident response.

---

## 2. Trust model

WPGovern assumes:

- one protected WordPress installation,
- one administrative operator or tightly controlled operator group,
- root-level server access is trusted,
- the host is a dedicated single-tenant environment,
- the operator controls DNS and server provisioning,
- the operator is responsible for off-server key backup.

WPGovern does not assume:

- hostile tenants on the same WPGovern instance,
- a SaaS control plane,
- central fleet management,
- untrusted operators with shell access,
- automatic recovery if the age private key is lost.

---

## 3. Boundary map

| Boundary | WPGovern role | Operator responsibility |
|---|---|---|
| Host operating system | installs and checks expected host foundation | keep server access secure |
| Docker stack | generates and governs deterministic stack files | avoid manual drift unless planned |
| WordPress files | governs critical configuration and provisioning | manage content-layer policy/plugins |
| Database | creates users, backup user, and backup paths | protect database credentials |
| Backups | stream-encrypted backup and restore-test | preserve backup files and private key |
| Governance state | records phase facts, audit facts, backup facts | avoid tampering with state files |
| Off-server key custody | records acknowledgement | actually store the private key safely |

---

## 4. What WPGovern protects

WPGovern protects against:

- unmanaged installation drift,
- missing operational audit evidence,
- stale backup visibility,
- missing restore-test evidence,
- accidental plaintext SQL backup files,
- silent backup timer setup failure,
- configuration mismatch between declared governance and runtime state,
- unacknowledged DR key custody responsibility.

WPGovern improves the system by making important conditions visible and testable.

---

## 5. What WPGovern does not protect

WPGovern does not protect against:

- a lost age private key with no off-server backup,
- a fully compromised root operator,
- malicious physical access to the server,
- vulnerabilities in WordPress plugins or themes unless separately governed,
- all possible supply-chain attacks,
- careless public exposure of a future local console,
- unsupported manual edits that bypass governance workflow.

These are not failures of WPGovern; they are boundaries of the model.

---

## 6. Credential handling

Credentials must not appear in routine stdout, stderr, or logs.

Credential-sensitive functions should disable xtrace before reading or using secrets. This protects against accidental `bash -x` leakage.

Sensitive values include:

- database root password,
- WordPress database password,
- backup database password,
- WordPress admin password,
- AUTH_KEY and SALT values,
- age private key contents.

The age private key should be handled as one of the most important secrets in the system.

---

## 7. Encryption-at-rest model

Backups are encrypted with age.

The intended backup discipline is:

```text
plaintext SQL exists only in process pipes, not as a disk file.
```

The governance backup is also encrypted.

The age private key is intentionally excluded from the governance backup. If the private key were included, anyone with the backup set could decrypt the backup set.

---

## 8. Key custody model

The private key must be backed up off-server.

WPGovern can record:

```text
The operator acknowledged that key backup was completed.
```

WPGovern cannot prove:

```text
The key exists in off-server storage.
The key can be retrieved by the right person.
The storage system remains available.
```

Therefore WPG-DR-01 must always use “acknowledged” or “operator-attested,” not “verified.”

---

## 9. Audit model

The audit command should be:

```text
boringly predictable, brutally honest, immediately useful.
```

Audit output must distinguish:

| Result | Meaning |
|---|---|
| PASS | currently acceptable |
| WARN | attention recommended |
| FAIL | required condition broken |

Audit output should never silently hide a known failure. If a probe cannot run, the audit should make that visible according to its exit-code contract.

---

## 10. Restore trust model

Restore is destructive.

The restore procedure assumes:

- the operator has selected the correct backup timestamp,
- the private key is available,
- the target host has completed required install phases,
- the operator understands current data may be overwritten.

Future UX must treat restore as a guarded workflow, not a casual button.

At minimum, restore UX must include:

- validation step,
- consequence summary,
- explicit typed confirmation,
- recorded attestation,
- raw command and exit-code evidence.

---

## 11. Local Console security model

A future WPGovern Local Console must remain local and single-tenant.

It must not become a fleet SaaS or a public remote control plane.

Initial console work should be read-only:

```text
status, evidence, audit summary, backup health, DR acknowledgement.
```

Destructive actions must not run directly inside HTTP request handlers. If action execution is added later, it must use controlled local job execution and preserve exact exit codes and evidence.

A public unauthenticated console is forbidden.

---

## 12. Evidence trust model

WPGovern evidence is useful because it is explicit.

Evidence should answer:

```text
What was checked?
When was it checked?
What was the result?
What command produced the result?
What action is recommended?
What remains operator-attested rather than machine-verified?
```

Evidence must not overclaim. This is especially important for off-server key custody.

---

## 13. Security review checklist

Before making a security claim, confirm:

```text
[ ] No known audit FAIL findings remain.
[ ] Backup and restore-test status are current.
[ ] age key backup is acknowledged.
[ ] Secrets are not printed by normal commands.
[ ] Restore procedures are documented.
[ ] Local console, if present, is not publicly exposed without protection.
[ ] Documentation uses “acknowledged” rather than “verified” for key custody.
```

---

## 14. Institutional trust statement

WPGovern should be presented honestly:

```text
WPGovern provides governed installation, operational audit, encrypted recovery, and evidence discipline for a single WordPress installation.
It reduces operational ambiguity.
It does not eliminate operator responsibility.
```

That honesty is part of the trust model.