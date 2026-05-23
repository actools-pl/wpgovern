# Executive Overview

## Status

This manual is for school owners, small institutions, and non-technical decision-makers considering or evaluating WPGovern v1.0.0. It explains what WPGovern is, what problem it solves, and where its responsibilities end.

## 1. What WPGovern is

WPGovern is a single-tenant governance system for one WordPress installation on one server.

It combines a disciplined installer, deterministic configuration, operational audit, encrypted backup, restore-test, and governance checks so that a WordPress site is not merely installed, but governed, operable, and recoverable.

WPGovern is not a fleet platform or SaaS dashboard. It is a single-site governance appliance.

## 2. The problem WPGovern solves

Many WordPress sites depend on informal operations:

- configuration changes are not clearly recorded,
- backups exist but are not regularly tested,
- recovery depends on memory or luck,
- security warnings are scattered across tools,
- operators cannot easily prove what was checked and when.

WPGovern addresses this by creating a structured operating layer around one WordPress installation.

It gives the operator repeatable commands, audit findings, backup evidence, restore-test evidence, and explicit responsibility boundaries.

## 3. Single-tenant and single-user model

Single-tenant means WPGovern is designed for one protected WordPress installation, not many unrelated customer sites sharing one control plane.

Single-user means the system assumes one trusted operator or one tightly controlled operator group.

Single-node means the installation runs on one server-class machine, such as a Hetzner CX22-class Ubuntu host or equivalent.

This model keeps the trust boundary clear. It avoids the complexity and additional risk of multi-tenant SaaS control systems.

## 4. Governed WordPress

In WPGovern, “governed WordPress” means the site is installed and operated through a controlled process.

The system creates known configuration, records state, installs a governance control plane, and checks whether the live system still matches expected conditions.

The governance idea is simple:

```text
Important operational facts should be explicit, checkable, and recoverable.
```

Governance does not mean nothing can go wrong. It means the system is built to reveal important drift, missing evidence, and recovery gaps.

## 5. Operable WordPress

WPGovern includes `wpgovern-install-audit`, an operational health command.

The audit is designed to be:

```text
boringly predictable, brutally honest, immediately useful
```

It reports PASS, WARN, and FAIL findings across WordPress, stack, security, configuration, backup, and disaster-recovery responsibility areas.

The operator can run:

```bash
wpgovern-install-audit --complete
```

and see whether the installation has conditions needing attention.

## 6. Recoverable WordPress

WPGovern v1.0.0 includes encrypted backup and restore tooling.

The recovery model includes:

- daily age-encrypted full backups,
- hourly age-encrypted binlog rotation,
- restore-test procedure,
- governance-aware restore sequence,
- operator acknowledgement of off-server age private key backup.

The doctrinal targets are:

```text
RPO <= 1 hour
RTO <= 30 minutes for a prepared operator and suitable site size
```

These targets depend on backups running, restore-test passing, the private key being available, and the operator following the recovery procedure.

## 7. What WPGovern protects

WPGovern helps protect against:

- unmanaged installation drift,
- missing audit evidence,
- stale or untested backups,
- unclear recovery readiness,
- accidental plaintext SQL backup files,
- unacknowledged private-key custody risk,
- unclear operator handover.

It does this through installer phases, audit fix-IDs, encrypted backup artifacts, restore-test records, and governance checks.

## 8. What WPGovern does not protect

WPGovern does not protect against everything.

It does not replace:

- careful server administration,
- DNS management,
- WordPress content-layer security plugins,
- supply-chain review,
- operator judgement,
- off-server key custody,
- incident response planning.

It does not defend against a malicious or compromised root operator.

It cannot recover encrypted backups if the age private key is lost and no usable off-server copy exists.

## 9. Private key responsibility

The age private key is essential for recovery.

WPGovern can record that the operator acknowledged backing it up off-server.

The correct wording is:

```text
acknowledged
operator-attested
```

The incorrect wording is:

```text
verified
```

WPGovern cannot independently verify that an off-server key copy exists or is usable. It can only record the operator's acknowledgement.

This distinction is important because it is part of the trust model.

## 10. Evidence value

WPGovern's value is not only technical. It is evidentiary.

A responsible operator can show:

- when audit was run,
- which findings passed or failed,
- when the latest full backup occurred,
- when restore-test last passed,
- whether the age key backup was acknowledged,
- whether governance checks passed.

This evidence helps institutions move from informal WordPress operation to disciplined WordPress governance.

## 11. Who WPGovern is for

WPGovern is appropriate for:

- small institutions,
- schools,
- independent organizations,
- single-site operators,
- technical maintainers who want a governed WordPress appliance rather than ad hoc hosting.

It is not designed as a central agency dashboard for hundreds of sites. That would be a different product with a different trust model.

## 12. Closure / Summary

WPGovern v1.0.0 provides a disciplined operating foundation for one WordPress installation. It is valuable because it is honest about its boundaries: it governs what it can observe, audits what it can check, encrypts and tests recovery paths, and records operator responsibility where human custody is required. Its trust signal is not marketing language; it is explicit evidence and clear limits.