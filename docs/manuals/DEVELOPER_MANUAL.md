# Developer Manual

## Status

This manual is for future maintainers and coding agents extending WPGovern v1.0.0. It explains repository structure, phase architecture, Bash rules, state discipline, fix-ID discipline, and documentation expectations.

## 1. Project shape

WPGovern has two major parts:

- Bash installer and operations arc, H.1 through H.7,
- Python governance control plane, locked separately and invoked by the ceremony phase.

The Bash arc installs and operates the single-node WordPress governance appliance. The Python control plane provides governance semantics after the byte-one ceremony.

WPGovern v1.0.0 is single-tenant, single-user, and single-node. Do not introduce fleet, SaaS, or multi-tenant assumptions into v1 maintenance work.

## 2. Top-level repository layout

Typical top-level areas include:

```text
core/                  shared Bash helpers
modules/host/          host foundation
modules/stack/         Docker Compose stack generation
modules/db/            database readiness and users
modules/wp/            WordPress preparation and secure config
modules/ceremony/      Python installation and byte-one ceremony
modules/audit/         wpgovern-install-audit
modules/backup/        backup, restore, systemd, runbook
installer_tests/       Bats test suite
wpgovern/              Python governance control plane, when present
wpgovern-install.sh    main installer entry point
wpgovern.env.example   env-file template
docs/                  manuals and project documentation
CHANGELOG.md           release and phase notes
```

Keep module boundaries clear. Do not leak one phase's private helper into another phase unless it has been promoted into `core/`.

## 3. Phase architecture

### H.1 host

Installs host dependencies, tunes host settings, configures swap, firewall, Docker, and logrotate.

### H.2 stack

Generates digest-pinned Docker Compose stack, Caddyfile, and MariaDB configuration.

### H.3 db

Waits for MariaDB readiness, manages credentials, encrypts state, verifies application DB user, and creates backup user.

### H.4 wp

Prepares WordPress filesystem, provisions WordPress, generates secure configuration, and ensures auth keys/salts.

### H.5 ceremony

Installs the Python control plane and crosses the byte-one governance threshold.

### H.6 audit

Installs `wpgovern-install-audit` and defines operational PASS, WARN, FAIL evidence.

### H.7 backup

Installs backup and restore tooling, age keypair handling, systemd timers, restore-test, and recovery runbook.

## 4. Bash coding rules

All Bash modules should use:

```bash
set -euo pipefail
```

Rules:

- no top-level `local`,
- explicit error handling around pipelines that may legitimately return non-zero,
- no silent masking of critical failures with `|| true`,
- cleanup temp files on failure,
- preserve exact exit codes where the contract requires them,
- use arrays for argv when arguments may contain spaces,
- never rely on unquoted word splitting for operator-provided text,
- keep destructive actions explicit.

## 5. Credential handling rules

Credential-sensitive functions must protect against xtrace leaks.

Use a local guard pattern at function entry when a function reads or substitutes secrets:

```bash
case "$-" in *x*) set +x; local _restore_xtrace=1 ;; esac
```

Credential-sensitive values include:

- database passwords,
- WordPress admin password,
- WordPress salts and keys,
- age private key material or paths when used for decryption,
- backup database password.

Do not print secrets to stdout, stderr, logs, JSON, or test output.

## 6. Pipeline and PIPESTATUS rules

Pipelines require special care under `set -euo pipefail`.

If a command's non-zero status is expected and must be classified, do not run the pipeline bare. Guard it so `PIPESTATUS` can be inspected before Bash exits.

Example pattern:

```bash
set +e
producer | consumer
producer_rc="${PIPESTATUS[0]}"
consumer_rc="${PIPESTATUS[1]}"
set -e
```

Then decide whether each status is acceptable.

Use this discipline for backup streams, tar streams, decryptability checks, and any stream where early pipe close may cause SIGPIPE.

## 7. State file rules

State mutations must go through `core/state.sh` helpers.

Use:

```bash
wpgovern::state::set_fact
wpgovern::state::mark_phase_complete
wpgovern::state::mark_phase_failed
```

Do not manually edit the state JSON from phase modules unless the operation is deliberately implemented in `core/state.sh`.

Concurrent writes are protected with flock in `core/state.sh`. Reads are normally unflocked. If future work introduces read-modify-write behaviour outside the helpers, move that behaviour into `core/state.sh` rather than duplicating it.

## 8. Module boundary rules

Phase modules should not depend on private functions from later or sibling phases.

If a helper is needed across phases, promote it to `core/`.

Examples of shared concerns:

- state mutation,
- credential persistence,
- xtrace protection,
- env-file loading,
- state-file path resolution.

Do not source a sibling module only to access one private helper. That creates resumability failures when a previous phase is skipped.

## 9. Adding a new Bash module

When adding a module:

1. Place it under the correct `modules/<area>/` directory.
2. Start with `#!/usr/bin/env bash` and `set -euo pipefail`.
3. Use a namespace-like function name, for example `wpgovern::area::action`.
4. Keep side effects explicit.
5. Add a Bats test file under `installer_tests/`.
6. Add syntax checks.
7. Update documentation and changelog.
8. Confirm no top-level `local` appears.

## 10. Adding a new fix-ID

When adding an audit finding:

1. Choose the correct namespace:
   - `WPG-WP-*`,
   - `WPG-STACK-*`,
   - `WPG-SEC-*`,
   - `WPG-CFG-*`,
   - `WPG-BKUP-*`,
   - `WPG-DR-*`.
2. Emit through `_audit_finding`.
3. Include priority, status, layer, message, and fix command where appropriate.
4. Confirm JSON output remains valid.
5. Add or update tests.
6. Update AUDIT_MANUAL.md if the fix-ID is operator-facing.

Do not create undocumented operator-facing fix-IDs.

## 11. Test discipline

WPGovern uses Bats for installer and Bash behaviour.

The Python governance control plane uses pytest.

Test rules:

- test names must describe what the test actually exercises,
- do not mock the function named in the test unless the test explicitly says it is a wiring test,
- add regression tests for every discovered defect class,
- keep environment-specific skips explicit,
- preserve deterministic counts in phase notes when claiming closure,
- include syntax checks for shell files.

## 12. Documentation and changelog discipline

When shipping changes, update relevant documentation.

For operator-facing behaviour, update manuals if commands, flags, fix-IDs, exit codes, or safety wording change.

For phase or release work, update `CHANGELOG.md` with honest counts and scope.

Do not document future features as if they exist. For example, `wpgovern-status --json`, Local Console, DR Attestation Report export, WPGovern Advisor, and restore dry-run are future concepts unless implemented.

## 13. Safety language discipline

Use exact language for key custody:

```text
acknowledged
operator-attested
```

Do not write:

```text
verified off-server key backup
```

WPGovern records acknowledgement. It cannot prove off-server custody.

## 14. Closure / Summary

Future WPGovern maintenance should preserve the same discipline that made v1 possible: clear module boundaries, explicit state mutation, careful Bash semantics, credential-safe output, evidence-grounded audit findings, and honest documentation. Every extension should strengthen the governed, operable, and recoverable doctrines without turning WPGovern into a different product.