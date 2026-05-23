# Security and Trust Model Manual

## Status

This manual is for auditors, sysadmins, and technical evaluators reviewing WPGovern v1.0.0. It describes what WPGovern protects, what it assumes, and what remains the operator's responsibility.

## 1. Trust model

WPGovern v1.0.0 is a single-tenant, single-user, single-node governance system for one WordPress installation.

It assumes:

- one protected WordPress site,
- one server under the operator's control,
- trusted root access for the operator,
- no hostile co-tenants on the WPGovern instance,
- no fleet or SaaS control plane,
- operator custody of off-server recovery material.

WPGovern does not defend against a compromised root operator. Root can change files, read process memory, stop services, delete backups, or bypass controls. WPGovern records, governs, audits, and supports recovery; it does not make root untrusted.

## 2. Governance boundary

WPGovern's load-bearing doctrines are:

| Doctrine | Meaning |
|---|---|
| Governed | Critical configuration and baseline state are created deterministically and checked by the governance control plane. |
| Operable | The live installation can be audited with repeatable PASS, WARN, and FAIL findings. |
| Recoverable | Encrypted backups, binlog rotation, restore-test evidence, and key-custody acknowledgement support disaster recovery. |

Each doctrine has limits. WPGovern makes important evidence visible; it does not remove operator responsibility.

## 3. Root privilege boundary

The installer and operational scripts perform privileged system work. They configure host packages, Docker, firewall rules, systemd units, filesystem permissions, governance state, and backup paths.

The root operator is trusted.

WPGovern protects against unmanaged drift and missing evidence. It does not protect against a malicious or careless root operator who intentionally deletes files, changes keys, edits state, or disables services.

## 4. Docker boundary

WPGovern v1 uses a four-service Docker stack:

```text
caddy
mariadb
php
wordpress
```

The stack is generated and governed by installer modules. Docker isolation is treated as an operational boundary, not a complete security sandbox against root or daemon compromise.

The operator remains responsible for host-level Docker access. Anyone with Docker daemon control can usually escalate to host-level control.

## 5. Filesystem and credential handling

WPGovern uses filesystem ownership, modes, and deterministic generated files to reduce accidental drift.

Sensitive files include:

- `wpgovern.env`,
- generated WordPress configuration,
- database credentials,
- WordPress admin credentials,
- WordPress salts and keys,
- age private key,
- installer state,
- encrypted backups.

Credential-sensitive functions should disable Bash xtrace before handling secrets. WPGovern includes xtrace guards in credential-touching flows, including audit database reachability and backup/restore paths. This protects against accidental `bash -x` disclosure; it is not a substitute for protecting the server and logs.

## 6. Encryption-at-rest model

Backups are encrypted with age.

The SQL backup model is stream-oriented:

```text
mariadb-dump -> age-encrypted .sql.age file
```

Plaintext SQL should not be written to disk during normal full backup operation.

Governance state is also backed up through an encrypted tar stream. The age private key is excluded from the governance tarball. Including it would defeat the encryption-at-rest model.

## 7. Off-server key custody

The age public key can encrypt backups. The age private key is required to decrypt them.

If the age private key is lost and no usable off-server copy exists, encrypted backups are not recoverable.

WPGovern can record that the operator acknowledged off-server key backup:

```text
WPG-DR-01: acknowledged (operator-attested)
```

WPGovern cannot prove that the off-server private key exists, is retrievable, or is usable. Manuals, audit output, and reports must use “acknowledged” or “operator-attested,” never “verified,” for off-server key custody.

## 8. What WPGovern protects

WPGovern helps protect against:

- undocumented installer state,
- unmanaged configuration drift,
- missing audit evidence,
- stale backup visibility,
- missing restore-test evidence,
- accidental plaintext SQL backup files,
- silent backup timer setup failure,
- unacknowledged disaster-recovery key responsibility.

It does this through deterministic generation, state facts, audit probes, encrypted backups, restore-test evidence, and explicit operator acknowledgement.

## 9. What remains operator responsibility

The operator remains responsible for:

- server access control,
- SSH key custody,
- DNS correctness,
- off-server age private key backup,
- off-server backup policy if required,
- WordPress content-layer security choices,
- plugin and theme risk decisions,
- incident response,
- safe handling of restore operations,
- preserving evidence when needed.

WPGovern can warn about some of these conditions. It cannot fully automate judgement or institutional accountability.

## 10. Known limitations

WPGovern v1.0.0 is not:

- a multi-tenant platform,
- a fleet manager,
- a SaaS control plane,
- a Web Application Firewall,
- a malware scanner,
- a replacement for WordPress security plugins,
- a substitute for off-server key custody,
- a guarantee against supply-chain compromise,
- a defense against compromised root.

The audit includes an architectural delegation signal for WordPress security plugin presence. That signal does not mean WPGovern itself performs all content-layer protection.

## 11. Security review checklist

Before making a security or recovery claim, confirm:

```text
[ ] wpgovern-install-audit --complete has no unexpected FAIL findings.
[ ] Backup currency is acceptable.
[ ] Restore-test has passed within the required window.
[ ] WPG-DR-01 is acknowledged (operator-attested).
[ ] The operator knows where the off-server age private key copy is stored.
[ ] The local server remains under trusted administrative control.
[ ] Documentation does not claim off-server key custody is verified.
```

## 12. Closure / Summary

WPGovern v1.0.0 provides disciplined governance, auditability, and encrypted recoverability for a single WordPress installation. Its trust model is strongest when the operator understands the boundary: WPGovern records and checks what it can observe; the operator remains responsible for root control, key custody, and institutional decisions outside the machine.