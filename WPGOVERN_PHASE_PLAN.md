# WPGovern Clean-Room Reconstruction — Phase Plan

**Reference artifact:** `wpgovern_clean_v21.zip` (frozen, never modified)  
**Target:** Same behavior, same invariants, no historical sediment  
**Status:** APPROVED — Phase 0 may begin immediately

---

## Decisions recorded (not open questions)

**Q1 — `models/` directory:** Rejected. No Pydantic. Runtime has zero external dependencies; adding Pydantic is a new architectural decision, not a reconstruction of existing behavior. `ApprovalRecord`, `AuditRecord`, `TrustKeyRecord`, `TrustStore`, `ReconciliationRecord` remain as stdlib dataclasses living in their owning modules (`policy/approval.py`, `audit/logger.py`, `core/trust.py`). They are authored in those modules in their respective phases.

**Q2 — CLI submodule split:** Confirmed. Phase 11 replaces the monolithic 2,371-line `cli/cli.py` with a clean `cli/commands/` layout grouped by domain. Command parity with v21 is the acceptance criterion: every command must appear.

**Q3 — Test count reduction:** Confirmed. Target ~287 tests vs. v21's 462. Reduction comes from merging v-versioned test files with subject-named equivalents and deduplicating redundant scenario variants. Behavioral coverage is equivalent; test volume is tighter. If a behavior in v21 has no corresponding test in the reconstruction, that is a bug in the phase plan — not an accepted gap.

---

## Ground rules (governing every phase)

1. Phase N is zipped and verified before Phase N+1 starts. No exceptions.
2. No v-version comments in source. Explanations live in the phase README.
3. Tests named by subject: `test_signing_verify_rejects_preactive_key`, never `test_v17_finding_2`.
4. Each phase delivers: **phase zip** + **phase README** (invariants stated, design decisions recorded, test coverage enumerated).
5. Clean-room discipline: no additions outside phase scope. Surfaced issues are noted and deferred to their proper phase.
6. Implementing veto is the assistant's. No discussion required to defer.

---

## Dependency chain (read before reviewing phases)

```
Phase 0  errors.py, scaffold
   │
Phase 1  config.py, paths.py
   │
Phase 2  utils/ (locking, transaction, fs, jsonio, time)
   │
Phase 3  audit/logger, audit/fs_hardening
   │
Phase 4  utils/journal, utils/recovery
   │
Phase 5  core/trust, core/signing, core/actor
   │
Phase 6  core/baseline, policy/approval
   │
Phase 7  policy/rollback, policy/breakglass, policy/reconciliation
   │
Phase 8  core/key_compromise, core/trust_backup
   │
Phase 9  audit/verifier, audit/alerter
   │
Phase 10 status/checker, status/reporter
   │
Phase 11 cli/ (split into command-group submodules)
   │
Phase 12 utils/invariants + property-based + adversarial + cross-cutting tests
```

Every arrow is a hard dependency. No phase imports from a phase below it in this chain.

---

## Phase 0 — Scaffold & Errors

**Scope**

- `pyproject.toml` (clean, no v-version comments; all subpackages enumerated)
- `requirements.txt` (pytest + hypothesis; no inline version comments)
- Package skeleton: `wpgovern/__init__.py` (version string only), one `__init__.py` per sub-package, all other modules as empty stubs (`pass` body or `raise NotImplementedError`)
- `errors.py` **fully authored** — the complete error hierarchy including `B4Error` and all subclasses

**Why errors.py here:**  
`errors.py` imports nothing from this project. Every subsequent phase imports from it. It must be complete and stable before Phase 1 begins.

**Structural decision recorded here:**  
The CLI will be split across sub-modules in Phase 11. Stub layout: `cli/__init__.py` + `cli/commands/` (empty). This is declared now so the scaffold is correct from the start. No `models/` directory exists at any point in the reconstruction.

**Deliverable tests**

- `pip install -e .` succeeds
- `wpgovern --help` runs without `ImportError` or `AttributeError`
- `pytest` collects 0 tests and exits 0
- Import smoke: `python -c "from wpgovern.errors import WPGovernError, B4Error, _classify_oserror"` exits 0

**Test files authored in this phase:** none (no behaviors to test yet)

---

## Phase 1 — Config & Paths

**Scope**

- `config.py` — `WPGovernConfig` dataclass, `DEFAULT_CONFIG`; all fields present with clean docstrings, zero v-version inline comments
- `paths.py` — `Paths` dataclass, `build_paths()`; all path properties; alias properties retained for CLI/shell compatibility; `WPGovernPaths` alias retained

**No `models/` directory.** The data records (`ApprovalRecord`, `AuditRecord`, `TrustKeyRecord`, `TrustStore`, `ReconciliationRecord`) are stdlib dataclasses authored in their owning modules during their respective phases. They are not centralised here.

**Design decisions**

- All config fields grouped by logical domain (core paths / journal / alerting / review) with a single clean block comment per group. No "vN:" prefixes.
- `build_paths()` accepts: `None` (uses `DEFAULT_CONFIG`), an existing `Paths` instance (returned as-is), a `str` or `Path` (treated as root), or a `WPGovernConfig` instance (uses `config.root_dir`).
- `WPGovernPaths` alias for `Paths` is retained for CLI/shell compatibility. It is documented as an alias in the phase README; no separate class exists.

**Deliverable tests** (`tests/test_config.py`, `tests/test_paths.py`)

- `WPGovernConfig()` instantiates with all defaults
- Field types are correct (`Path`, `int | None`, `tuple | None`)
- `Paths()` produces expected paths for default root
- `build_paths()` handles: `None`, existing `Paths`, `str`, `Path`, config with `root_dir`
- Path aliases (`approvals`, `audit_log`, etc.) return the same object as their canonical property
- `WPGovernPaths` is identical to `Paths`

**Estimated test count:** ~12

---

## Phase 2 — Utility Layer

**Scope**

- `utils/locking.py` — `FileLock` (fcntl.flock, advisory, single-node); `LockManager` (multi-lock `acquire_many` with dedup + deterministic sort)
- `utils/transaction.py` — `AtomicTransaction` (stage → replace, kill-point safe)
- `utils/fs.py` — atomic file write helpers
- `utils/jsonio.py` — safe JSON read/write wrappers
- `utils/time.py` — `utcnow_iso()` and timestamp helpers

**Design decisions**

- `LockManager.acquire_many()` acquires in sorted order (deadlock avoidance). Sort order is documented in the phase README, not inline.
- `AtomicTransaction` stages to `.tmp` in the same directory as the target (same-filesystem guarantee for atomic rename).
- KNOWN_LIMITS entry preserved: `FileLock` uses `fcntl.flock` which is advisory and not NFS-safe.

**Deliverable tests** (`tests/test_locking.py`, `tests/test_transaction.py`, `tests/test_fs_utils.py`)

- `FileLock` is re-entrant within the same process
- `LockManager` rejects empty name, path-traversal names (`/`, `..`, `\`)
- `LockManager.acquire_many()` deduplicates, holds all locks inside block, releases after
- `AtomicTransaction` leaves target unchanged on failure; succeeds on clean path
- `AtomicTransaction` is kill-point safe (staged file abandoned, target intact)
- JSON round-trip through `jsonio`; malformed input raises `ValidationError`
- `utcnow_iso()` returns an ISO-8601 string parseable by `datetime.fromisoformat`

**Estimated test count:** ~22

---

## Phase 3 — Audit Logger & FS Hardening

**Scope**

- `audit/logger.py` — `AuditLogger`, `AUDIT_ALLOWED_FIELDS` (complete allowlist), `sanitise_details()`
- `audit/fs_hardening.py` — `AuditFSHardener` (chattr append-only, lsattr verification)

**Design decisions**

- `AUDIT_ALLOWED_FIELDS` is defined as a single frozenset at module level. The allowlist is the authoritative list; any field not on it is stripped by `sanitise_details()`. No "vN additions" partitioning.
- Audit records are written as newline-delimited JSON. Each record includes `seq`, `timestamp`, `event_type`, `actor`, `outcome`, `details`, `prev_hash`, `self_hash`.
- `sanitise_details()` applies exactly two security checks — no more:
  1. **Field-name check:** if the field key is in `_SECRET_FIELD_NAMES` (`password`, `secret`, `token`, `credential`, `api_key`, `private_key`, `secret_key`), raise `AuditError` regardless of the value. This check runs before the allowlist filter so that a field named `password` raises rather than being silently stripped.
  2. **PEM-marker check:** if any string value contains a PEM header (`begin private key`, `begin rsa private key`, `begin ec private key`, `begin encrypted private key`), raise `AuditError`. PEM content is structurally unambiguous key material.
  - Operator reason text (e.g. `"Per password rotation policy"`, `"Rotating the secret sharing key"`) is **never** rejected on content. Substring matching on reason values caused legitimate operations to fail after state mutation — that failure mode is explicitly prevented here.
  - Non-printable characters in values raise `AuditError`.
  - Non-JSON-serializable types raise `AuditError`.
  - Unknown fields are stripped silently (no warning, no error).
- `AuditFSHardener` degrades gracefully when `chattr`/`lsattr` are absent (test environments).

**Deliverable tests** (`tests/test_audit_logger.py`, `tests/test_audit_fs_hardening.py`)

- Hash chain: each record's `prev_hash` equals the `self_hash` of its predecessor
- `self_hash` is recomputable from the record without `self_hash`
- `sanitise_details()` preserves all allowed fields
- `sanitise_details()` strips unknown fields silently (no error)
- `sanitise_details()` rejects a field literally named `password` regardless of its value
- `sanitise_details()` rejects a field literally named `secret` regardless of its value
- `sanitise_details()` rejects PEM key material (`-----BEGIN PRIVATE KEY-----`) in any field value
- `sanitise_details()` accepts operator reason text containing the words "password" or "secret"
- `sanitise_details()` accepts `"Per password rotation policy"` as a reason value (regression for external review B-6)
- `sanitise_details()` rejects non-printable characters in values
- `sanitise_details()` rejects non-JSON-serializable types (tuple, object)
- Audit emit with malformed details does not corrupt the chain
- `AuditFSHardener` does not raise when chattr is absent
- Actor ID validation: max length accepted, one-over rejected, control characters rejected

**Estimated test count:** ~25

---

## Phase 4 — Journal & Recovery

**Scope**

- `utils/journal.py` — `IntentRecord`, `CompleteRecord`, `JournalWriter`, `verify_intent_signature`; `schema_version=2` signed journal
- `utils/recovery.py` — `RecoveryService`, `_run_startup_recovery()`; fatal-on-refused contract

**Design decisions**

- Journal records have `schema_version` field. `schema_version=1` (unsigned) and `schema_version=2` (signed) are both readable. Unknown schema versions reject.
- Intent → targets → complete ordering is the atomicity contract. Recovery replays from the last unmatched intent. Kill-anywhere is safe.
- Fatal-on-refused: a `recovery.refused` event permanently halts the system until the operator manually acknowledges. `RecoveryService` raises `WPGovernError` on startup if a refused record is present without acknowledgement.
- `JournalWriter` emits to `AuditLogger` on intent, complete, refused, and stuck events.
- `verify_intent_signature` uses `VALID_VERIFY_STATUSES` — but `journal.py` does not import `signing.py` directly; the verifier function is injected as a parameter. This keeps the dependency graph acyclic: Phase 4 does not import Phase 5.

**Deliverable tests** (`tests/test_journal.py`, `tests/test_recovery.py`)

- Intent record written before any target file
- Complete record written after all target files
- Recovery correctly replays an incomplete intent (kills after intent, before complete)
- Recovery correctly skips a completed intent
- `recovery.refused` blocks startup; explicit acknowledgement allows restart
- Schema v1 and v2 records both readable
- Unknown schema version raises on read
- Tampered intent signature blocks replay
- `verify_intent_signature` with an invalid key status rejects
- Journal staleness warn/enforce thresholds surface correct behavior

**Estimated test count:** ~32

---

## Phase 5 — Trust Domain & Signing

**Scope**

- `core/trust.py` — `TrustService`; key lifecycle (generate, activate, revoke, retire); `active_private_key_path`; desync detection; trust store content validation
- `core/signing.py` — `SigningService`; `sign_file`, `verify_file`; `VALID_VERIFY_STATUSES = {"active", "retired_verify_only"}`
- `core/actor.py` — `resolve_actor_context()`; actor ID validation and normalization

**Design decisions**

- `VALID_VERIFY_STATUSES` is the fail-closed allow-list. Any status not in the set → verification fails. No exceptions, no fallback.
- `active_private_key_path` checks that the symlink target stem matches the `active_key_id` in the trust store. Desync → `TrustError`. This prevents signing with the wrong key when activation partially fails (JSON written, symlink not updated).
- Trust store content validation: on load, every key record is validated for required fields; missing or malformed records raise `IntegrityError`.
- Passphrase newline rejection: passphrases containing `\n`, `\r`, or `\x00` are rejected. `openssl enc -pass stdin` reads up to the first newline — a passphrase containing `\n` silently truncates, producing a weaker key. The check lives in the API function, not only in the CLI.
- `TrustService` covers three domains (runtime, release, journal) using the same logic; domain is a parameter, not a subclass.
- `resolve_actor_context()` rejects actor IDs with embedded null bytes and whitespace-only strings; tab is accepted.

**Deliverable tests** (`tests/test_trust.py`, `tests/test_signing.py`, `tests/test_actor_identity.py`, `tests/test_staged_signing.py`)

- Key lifecycle: generate → preactive; activate → active; revoke → revoked; retire → retired_verify_only
- `active_private_key_path` raises `TrustError` on symlink/store desync
- Trust store with malformed key record raises `IntegrityError` on load
- Passphrase with `\n` rejected at API level (not just CLI)
- `verify_file` with `preactive` key status rejects
- `verify_file` with `revoked` key status rejects
- `verify_file` with `active` status accepts
- `verify_file` with `retired_verify_only` accepts
- Unknown key status rejects (fail-closed)
- `resolve_actor_context()` rejects empty/whitespace-only actor_id
- `resolve_actor_context()` accepts tab in actor_id
- `resolve_actor_context()` rejects control characters (not tab)

**Estimated test count:** ~28

---

## Phase 6 — Baseline & Approval

**Scope**

- `core/baseline.py` — `BaselineService`; create, submit, approve, activate; approval consumption on activation
- `policy/approval.py` — `ApprovalService`; self-verifying load; no-reuse enforcement; revoke

**`ApprovalRecord` is a stdlib dataclass authored here** in `policy/approval.py`. It is not a Pydantic model and does not live in a `models/` directory.

**Design decisions**

- `ApprovalService.load()` verifies the approval signature internally. A caller cannot obtain an `ApprovalRecord` without the signature having been checked. An explicit `load_untrusted_for_inspection_only()` method exists for forensic/diagnostic use; its name is the warning.
- Approvals are consumed on use. Consumed approval IDs are recorded; re-presenting a consumed approval raises `PolicyError`.
- Baseline activation verifies the baseline signature before writing the active pointer.
- `BaselineService` emits audit events at each lifecycle stage.

**Deliverable tests** (`tests/test_baseline.py`, `tests/test_approval.py`)

- Baseline create → submit → approve → activate happy path
- Activation with missing signature raises
- Activation with tampered signature raises
- Approval consumed on activation; reuse raises `PolicyError`
- Revoked approval cannot be used
- `ApprovalService.load()` with tampered signature raises on load
- `ApprovalService.load()` with unknown key_id raises
- `load_untrusted_for_inspection_only()` returns record without raising on tampered content
- Audit events emitted at each stage

**Estimated test count:** ~19

---

## Phase 7 — Policy: Rollback, Break-glass, Reconciliation

**Scope**

- `policy/rollback.py` — `RollbackService`; approve, activate
- `policy/breakglass.py` — `BreakglassService`; approve, activate, review
- `policy/reconciliation.py` — `ReconciliationService`; complete; enforcement

**Design decisions**

- Rollback activation verifies the rollback approval, then atomically writes the active pointer to the target baseline.
- Break-glass activate uses a journaled transaction (intent/complete). Break-glass review signature is verified before completing reconciliation.
- Reconciliation enforce: if reconciliation is required and not completed within the configured window, subsequent activations are blocked.
- All three services emit audit events at each stage.

**Deliverable tests** (`tests/test_rollback.py`, `tests/test_breakglass.py`, `tests/test_reconciliation.py`, `tests/test_reconciliation_enforcement.py`)

- Rollback happy path; tampered approval blocks rollback
- Break-glass happy path; tampered review signature blocks reconciliation completion
- Reconciliation enforcement: activation blocked when reconciliation required and overdue
- Reconciliation enforcement: activation proceeds when reconciliation complete
- Audit events emitted for breakglass, rollback, reconciliation
- Path-traversal IDs rejected across all three services

**Estimated test count:** ~34

---

## Phase 8 — Key Compromise & Trust Backup

**Scope**

- `core/key_compromise.py` — `KeyCompromiseService`; runtime, release, and journal key compromise response
- `core/trust_backup.py` — `create_trust_backup`, `restore_trust_backup`; AES-256-CBC PBKDF2; atomic quarantine-replace; path-traversal guard; content validation

**Design decisions**

- Key compromise: revokes the compromised key, rotates to a new active key, emits a `key-compromise-*` audit event. KNOWN_LIMITS entry preserved: partial failure can leave the key in an inconsistent state (deferred to post-reconstruction hardening pass).
- `create_trust_backup`: produces an encrypted archive of all trust-domain directories. Passphrase newline rejection enforced at API level (same rule as Phase 5 — `\n`, `\r`, `\x00` rejected).
- `restore_trust_backup`: decrypts to a staging directory, validates content (see below), then atomically quarantine-swaps the live trust directories. Force-restore is atomic: existing `trust/` is moved to quarantine before staging is moved into place; on failure, quarantine is restored.
- Content validation (`_validate_restored_trust`): after extraction, all three required trust stores must exist, parse as valid JSON, have non-empty `keys` lists, have a valid `active_key_id`, and have their referenced `.pem` files present on disk. An encrypted archive that decrypts to empty or contains `{}` raises `TrustBackupError`.

**Deliverable tests** (`tests/test_key_compromise.py`, `tests/test_trust_backup.py`)

- Key compromise happy path for each domain (runtime, release, journal)
- Backup create round-trips through restore
- Backup with wrong passphrase raises `TrustBackupError` with clear message
- Passphrase containing `\n` rejected at API level
- Empty backup (encrypted `{}`) raises `TrustBackupError`
- Backup with empty `keys` list raises `TrustBackupError`
- Path traversal in backup archive raises `TrustBackupError`
- `restore_trust_backup` atomic: partial failure (wrong passphrase on force-restore) leaves original trust material intact
- Stale/attacker-added files do not survive a force-restore
- Audit events emitted for compromise and backup/restore

**Estimated test count:** ~18

---

## Phase 9 — Audit Verifier & Alerter

**Scope**

- `audit/verifier.py` — `AuditVerifier`; hash-chain verification; `review_window()`; `last_checkpoint()`
- `audit/alerter.py` — `AuditAlerter`; 4 sink types (webhook, file, syslog, stderr); built-in trigger set; `alert-test` support

**Design decisions**

- `AuditVerifier.verify()` re-derives each record's `self_hash` and checks `prev_hash` linkage. Detects all broken links, not just the first — returns a list of violations.
- `review_window()` verifies the full chain (not just the window) before returning results. A tampered upstream record causes `chain_ok=False`. Used by `governance-check` and `audit-review` — both must call `verify()` before trusting a checkpoint.
- **Checkpoint attestation model (updated — Step 3 shipped):** The `audit-review` checkpoint is hash-chained AND now cryptographically signed with the runtime key via a companion `audit.checkpoint.signature` record. The signature covers the checkpoint's `self_hash`, binding the checkpoint to a specific runtime key. An attacker who can rewrite the chain cannot forge a valid signature without the runtime private key. The word "attested" now means what operators read it to mean.
- `AuditAlerter` built-in trigger set (minimum safe set — cannot be reduced via config): `recovery.refused`, `recovery.stuck`, `breakglass.*`, `key-compromise-*`, `journal.key.revoked`, `baseline.activate`, `reconciliation.refused`, `b4.*`, `trust.backup.restored`. Operators may add to this set via `alert_extra_triggers`.
- Alert sinks: `none` silences (tests); `stderr` is the default when no sinks are configured; `webhook` has configurable timeout. Alert delivery failures are absorbed — alerting must never block governance operations.

**Deliverable tests** (`tests/test_audit_verifier.py`, `tests/test_audit_review.py`, `tests/test_alerting.py`)

- Chain verify passes on intact chain
- Chain verify detects single broken link and reports it
- Chain verify detects multiple broken links and reports all of them
- `review_window()` reports `chain_ok=False` when any record in the full chain is tampered (not just the window)
- `review_window()` reports `chain_ok=True` on clean chain
- Tampered checkpoint record is detected by chain verify (not by a signature check — chain detects the hash mismatch)
- `last_checkpoint()` returns the most recent checkpoint record; returns `None` when none exist
- `governance-check` exits 50 when review age exceeds `review_max_age_days`
- `governance-check` exits 51 unconditionally when chain broken, regardless of config
- Built-in alert triggers cannot be suppressed by config
- `alert_extra_triggers` adds to the built-in set; cannot reduce it
- `none` sink produces no output
- `webhook` sink fires on trigger event; webhook failure does not raise

**Estimated test count:** ~26

---

## Phase 10 — Status & Governance Check

**Scope**

- `status/checker.py` — `GovernanceChecker`; all exit codes: 0 (healthy), 10–14 (specific failure modes), 33 (stuck recovery), 50 (review overdue), 51 (chain broken)
- `status/reporter.py` — `GovernanceReporter`; human-readable and JSON status output

**Exit code contract (stated once, authoritatively)**

| Code | Meaning |
|------|---------|
| 0    | All checks pass |
| 10   | No active baseline |
| 11   | Active baseline signature invalid |
| 12   | Trust store missing or unreadable |
| 13   | Active key desync |
| 14   | Journal stuck |
| 33   | Recovery stuck (B4 condition during recovery) |
| 50   | Audit review overdue |
| 51   | Audit chain broken |

**Design decisions**

- Exit 51 is **unconditional**: `_evaluate_audit_chain_integrity()` runs at the very top of `check()`, before any other check, regardless of any configuration flag. If the chain is broken, `check()` returns exit 51 and stops. No bypass exists.
- Exit 50 fires only when `review_max_age_days` is configured. Default config (`review_max_age_days=None`) never produces exit 50.
- Exit 51 overrides exit 50: a broken chain with an overdue review reports 51, not 50.
- `GovernanceReporter` outputs JSON by default; `--human` flag produces operator-readable lines.

**Deliverable tests** (`tests/test_status.py`, `tests/test_governance_check.py`)

- Exit 0 on a fully healthy runtime
- Exit 10–14 for each specific failure mode
- Exit 33 on stuck recovery
- Exit 50 when review overdue; no exit 50 when review not configured
- Exit 51 when chain broken; exit 51 overrides exit 50
- Exit 51 check is unconditional: fires even when `review_max_age_days=None` (default config)
- Exit 51 fires on a tampered chain in default-config deployment (regression for external review S-2)
- `GovernanceReporter` JSON output is valid JSON
- Staleness warn/enforce thresholds surface correctly

**Estimated test count:** ~18

---

## Phase 11 — CLI

**Scope**

The single 2,371-line `cli/cli.py` is replaced with a clean submodule layout:

```
cli/
├── __init__.py          (app assembly: imports all command groups, registers main())
├── _common.py           (shared helpers: _config, _actor_context, _echo_json,
│                         ActorIdOption, ReasonOption, ChangeTicketOption,
│                         _run_with_error_handling, _should_skip_startup_recovery)
└── commands/
    ├── baseline.py      (baseline-create, baseline-submit, baseline-approve,
    │                     baseline-activate)
    ├── trust.py         (trust-key-generate, trust-key-activate, trust-key-revoke,
    │                     trust-key-status, release-key-*, journal-key-*)
    ├── policy.py        (rollback-approve, rollback-activate, breakglass-approve,
    │                     breakglass-activate, breakglass-review,
    │                     reconciliation-complete, approval-revoke)
    ├── audit.py         (audit-verify, audit-review, audit-checkpoints,
    │                     audit-fs-harden, audit-fs-status,
    │                     alert-test, alert-triggers)
    ├── status.py        (governance-check, governance-report, b4-status, b4-clear,
    │                     invariants-check, transaction-status)
    ├── journal.py       (bootstrap-journal-key, journal-key-status,
    │                     prune-journal-key, migrate-journal-v1-to-v2,
    │                     recovery-replay)
    ├── keys.py          (key-compromise-runtime, key-compromise-release,
    │                     key-compromise-journal, trust-backup, trust-restore,
    │                     trust-verify, active-verify, release-trust-verify,
    │                     release-sign, release-verify, journal-trust-verify)
    └── misc.py          (version, fresh, update, repair, status, logs,
                          restart, backup)
```

**Design decisions**

- All commands use the same `_config()`, `_actor_context()`, and `_echo_json()` from `_common.py`. No per-command duplication.
- The Typer `app` is assembled in `cli/__init__.py` by calling `app.add_typer()` for each command group. No global mutable state per command file.
- `cli/commands/misc.py` contains the platform-delegation commands (fresh, update, repair, restart, backup) that shell out to the Bash installer. Delegation logic is unchanged from v21.
- `_should_skip_startup_recovery()` lives in `_common.py`. Startup recovery is skipped for `--help`, `-h`, `--version`, `version`, `fresh`, no-args, and typer completion machinery. All governance commands still run recovery.
- `main()` entry point in `cli/__init__.py`. Human-readable display output goes to stderr; machine-readable JSON goes to stdout. This split is enforced consistently across all commands.

**Deliverable tests** (`tests/test_cli_wiring.py`, `tests/test_cli_integration.py`)

- `wpgovern --help` exits 0 and lists all expected command groups
- Every command appears in `--help` output (command parity matrix verified against v21)
- CLI integration: `baseline-create` end-to-end through the Typer runner
- CLI integration: `governance-check` exit code flows correctly through runner
- Actor context wired: `--actor-id` flag propagates to audit event
- `--reason` and `--change-ticket` propagate correctly
- `version` command outputs version string
- Startup recovery skipped for `--help`, `version`, `fresh`, no-args
- Startup recovery runs for governance commands

**Estimated test count:** ~15

---

## Phase 12 — Invariants, Property-Based & Cross-Cutting Tests

**Scope**

- `utils/invariants.py` — the 14-invariant behavioral catalog; `check_all_invariants()`
- Hypothesis property test suite (cross-cutting, needs full system)
- Adversarial tests (tampered artifacts, forged signatures, path traversal)
- Kill-point harness tests (atomicity under synthetic process kill)
- Concurrency tests (two concurrent operations under file locking)
- Hardening tests (audit field allowlist, sanitise coverage)

**Invariant catalog (stated authoritatively — 14 invariants)**

| # | Invariant |
|---|-----------|
| 1  | Active pointer always references an existing baseline |
| 2  | Active baseline signature is always verifiable with an active/retired key |
| 3  | Audit chain is unbroken from genesis to current record |
| 4  | Every approval is consumed at most once |
| 5  | No approval can be used after revocation |
| 6  | Trust store always has exactly one active key per domain |
| 7  | Active private key symlink resolves to the key identified in the trust store |
| 8  | Journal intent records always precede their targets |
| 9  | Completed recovery leaves no pending intents |
| 10 | Break-glass events always produce a reconciliation requirement |
| 11 | Reconciliation completion requires a valid review signature |
| 12 | Key compromise always rotates to a new active key |
| 13 | Audit field values pass `sanitise_details` without truncation |
| 14 | Exit codes from `governance-check` are deterministic given the same filesystem state |

**Design decisions**

- `utils/invariants.py` exposes `check_all_invariants(paths, config)` returning a list of `InvariantResult(id, name, passed, detail)`. It does not raise; callers decide severity.
- Hypothesis tests use `@given` with `st.text()`, `st.binary()`, `st.integers()` strategies. Properties: signing + verify is identity for valid inputs; `sanitise_details` is idempotent; audit chain is monotone.
- Kill-point harness: for each journaled operation, a simulated kill (exception injected at each write point) is followed by recovery, and the result is verified to be consistent.
- Adversarial tests: all surfaces from v21 `test_adversarial.py`, `test_gaps.py`, `test_gaps_v2.py`, `test_hardening.py` are reorganized by subject here.

**Deliverable tests**

- `tests/test_invariants.py` — `check_all_invariants` reports pass for healthy state; reports correct failure for each individual violation
- `tests/test_property_audit.py` — Hypothesis: audit chain monotone; `sanitise_details` idempotent
- `tests/test_property_signing.py` — Hypothesis: sign/verify round-trip; tampered payload fails
- `tests/test_kill_points.py` — every journaled operation survives synthetic kill at each write point
- `tests/test_adversarial.py` — tampered signatures, forged key_ids, path-traversal IDs, consumed approval reuse
- `tests/test_concurrency.py` — two concurrent baseline activations; one wins, one blocks
- `tests/test_hardening.py` — audit allowlist completeness; sanitise coverage; actor validation coverage

**Estimated test count:** ~50

---

## Summary table

| Phase | Name | Primary modules | Est. tests |
|-------|------|----------------|------------|
| 0 | Scaffold & Errors | errors.py, pyproject.toml, stubs | 0 (smoke only) |
| 1 | Config & Paths | config.py, paths.py | ~12 |
| 2 | Utility Layer | utils/locking, transaction, fs, jsonio, time | ~22 |
| 3 | Audit Logger & FS Hardening | audit/logger, audit/fs_hardening | ~25 |
| 4 | Journal & Recovery | utils/journal, utils/recovery | ~32 |
| 5 | Trust Domain & Signing | core/trust, core/signing, core/actor | ~28 |
| 6 | Baseline & Approval | core/baseline, policy/approval | ~19 |
| 7 | Policy: Rollback, Break-glass, Reconciliation | policy/rollback, breakglass, reconciliation | ~34 |
| 8 | Key Compromise & Trust Backup | core/key_compromise, core/trust_backup | ~18 |
| 9 | Audit Verifier & Alerter | audit/verifier, audit/alerter | ~26 |
| 10 | Status & Governance Check | status/checker, status/reporter | ~18 |
| 11 | CLI | cli/ (split by command group) | ~15 |
| 12 | Invariants, Property-Based & Cross-Cutting | utils/invariants, Hypothesis, adversarial, kill-points | ~50 |
| | **Total** | | **~299** |

**Note on test count:** v21 has 462 tests across 25+ files. The reconstructed count is lower because: (a) v-versioned test files covering the same behavior as subject-named tests are merged, (b) redundant scenario variants are consolidated. Behavioral coverage is equivalent; test volume is tighter. If a behavior in v21 has no corresponding test in the reconstruction, that is a bug in the phase plan — not an accepted gap.

---

## KNOWN_LIMITS carried forward (stated once, not inline)

These limitations are real, acknowledged, and not in scope for the reconstruction. Each phase README references this list rather than restating in source comments.

| Item | Scope |
|------|-------|
| Audit chain consistent-rewrite undetectable | `verify()` catches blind tampering only. An attacker with write access can recompute all hashes. Mitigation: runtime-key checkpoint signing + external anchoring (future pass: "audit transparency"). |
| Checkpoint signed with runtime key | **SHIPPED in Step 3.** Each checkpoint record has a companion `audit.checkpoint.signature` record signed with the active runtime key. External anchoring (WORM, RFC 3161) remains future work. |
| Trust-store root anchoring absent | No offline root key, no signed snapshots. Future pass: "trust-store root anchoring". |
| Release manifest schema enforced | **SHIPPED in v23.** Both `sign_release()` and `verify_release()` now enforce the full manifest contract via a shared `_validate_release_manifest_contract()` validator. Artifact existence, sha256 format, path traversal, and hash matching are all checked on both sign and verify paths. |
| Single-node locking | `fcntl.flock` is advisory and not NFS-safe. Documented. |
| Key compromise partial failure | Partial failure can leave a compromised key in `retired_verify_only`. Deferred. |
| Bash wrapper INSTALL_DIR | `scripts/wpgovern.sh` derives install dir from script location. Documented. |
| Actor identity environment-driven | Not cryptographically bound. Hardening pass deferred. |

---

*Phase plan approved. Phase 0 may begin immediately.*
