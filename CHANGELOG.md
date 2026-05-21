# WPGovern — Changelog

All notable changes to this project are documented here.  
Format: version / phase / date / summary / test count.

---

## H.2 — Docker Compose Stack Module (May 2026)

**144 bats tests · 776 Python tests (unchanged)**

Brings up the four-container stack with digest-pinned images, deterministic
governance-critical file generation, and automated credential management.

### Five new stack modules
- `modules/stack/images.sh` — Pull + pin image digests. Three failure paths each
  call `mark_phase_failed`. Idempotent: persisted digests win on re-run.
- `modules/stack/credentials.sh` — Generate DB passwords if blank; persist to
  env file; enforce `chmod 600`.
- `modules/stack/compose.sh` — Generate `docker-compose.yml`. Deterministic.
  No `:latest` tags. All bind-mounts explicit. All services restart + healthcheck.
- `modules/stack/caddyfile.sh` — Generate `Caddyfile`. HTTPS via Let's Encrypt.
  Security headers, gzip+zstd, JSON log, port-80 health endpoint.
- `modules/stack/mycnf.sh` — Generate `my.cnf`. Binary logging, TLS required,
  InnoDB 2G, utf8mb4, max_connections=50.

### Entry script: stack phase dispatch added
Runs after host phase: credentials.ensure → images.pin → compose.generate →
caddyfile.generate → mycnf.generate → `docker compose up -d` → 120s healthcheck
wait → `mark_phase_complete "stack"`.

### Three coordinated env-var sites (H.2-6)
WPGOVERN_DOMAIN, WPGOVERN_LE_EMAIL, WPGOVERN_DB_ROOT_PASSWORD, WPGOVERN_DB_WP_PASSWORD
added to: whitelist parser (bootstrap.sh), env.example, entry-script validation.

### 40 new bats tests across 6 files
Determinism tests verify byte-identical generation (10/10 repeated invocations).
Images tests cover 3 failure paths behaviorally. CI guards enforce no-latest,
all-services, restart+healthcheck on generated output.

---

 — Second bash hardening pass

**104 bats tests · 776 Python tests (unchanged)**

Closes three blockers and three non-blocking items. All three blockers are the
SAME defect class as items supposedly closed in v53.1 — partial call-site coverage.

### H.1.2-1 — WPGOVERN_FORCE_FIREWALL truly CLI-only (High, three sites)
Removed from whitelist (bootstrap.sh), removed from env.example, entry script
unconditionally defaults to false after env load before CLI override.

### H.1.2-2 — UFW idempotency exact-field matching (Medium-High)
`_wpgovern_ufw_rule_present()` awk helper. Three rule-check sites all use it.
`2222/tcp` no longer satisfies a required `22/tcp` rule.

### H.1.2-3 — Docker GPG parse guard (Medium-High, three failure paths)
`if ! actual_fpr="$(gpg ... | awk ...)"` guards parse failure. Empty fingerprint
guarded separately. All three failure paths call `mark_phase_failed` before `return 1`.

### H.1.2-4 — sh guard POSIX syntax
`[ -z "${BASH_VERSION:-}" ]` replaces `[[ ]]`.

### H.1.2-5 — flock before state::init
Lock acquired before `source core/state.sh`.

### H.1.2-6 — Behavioral tests: 4 new + 1 replaced
Real entry-script witness-file test for force-firewall. Negative test for env
rejection. Behavioral UFW exact-match test. Behavioral Docker malformed-key test.

---

 — Bash installer hardening

**100 bats tests · 776 Python tests (unchanged)**

Closes five blockers and six non-blocking items identified by three-window
external review of H.1. All five blockers verified by direct PoC against v53.

### H.1.1-1 — State write atomicity (High blocker)
`mktemp` generates unique temp paths per invocation. Every write function uses
`if ! jq ... > "$tmp"; then rm -f "$tmp"; return 1; fi` — explicit checked writes
that return non-zero regardless of the caller's errexit context.

### H.1.1-2 — CLI/env precedence for --force-firewall (High blocker)
Entry script now loads env FIRST, then applies `--force-firewall` CLI override
after. `--force-firewall` is CLI-only (removed from env file allowlist).

### H.1.1-3 — Firewall SSH-port handling (High blocker)
`ufw allow "${ssh_port}/tcp"` replaces `ufw allow OpenSSH`. Listener check uses
`ss -H -ltn "sport = :${ssh_port}"` for exact-port matching. SSH port recorded
in state as `host.firewall.ssh_port`.

### H.1.1-4 — Docker GPG fingerprint verification (Medium-High blocker)
Downloads to temp file, verifies fingerprint via `gpg --show-keys --with-colons`,
fails closed on mismatch with `mark_phase_failed`. Verified fingerprint recorded
in state as `host.docker.gpg_fingerprint`.

### H.1.1-5 — jq bootstrap preflight (Medium-High blocker)
jq preflight runs before `state::init`. Auto-installs jq if missing (root) or
errors clearly (non-root).

### H.1.1-6 — logrotate fail-closed (Medium)
Checks `command -v logrotate` and validates config before marking success.
`mark_phase_failed` + `return 1` on failure. Adds `host.logrotate.config_path` fact.

### H.1.1-7 — UFW idempotency rule verification (Medium)
Active UFW → checks that SSH-port/80/443 ALLOW rules and default deny incoming
are all present. Falls through to reconfigure if any rule is missing.

### H.1.1-8 — Ubuntu 24.04 host preflight (Medium)
Reads `/etc/os-release` before any state writes. Records OS facts in state.

### H.1.1-9 — Concurrent-run safety (Medium)
`flock -n` on `${WPGOVERN_INSTALL_DIR}/.wpgovern-installer.lock`. Clear error
if another run is active.

### H.1.1-10 — Env file whitelist parser (Medium)
Replaces `set -a; source` with a line-by-line parser. Rejects: unknown keys,
shell metacharacters in values, malformed lines. Accepts: commented lines,
blank lines, quoted values.

### H.1.1-11 — sh invocation guard (Low)
`if [[ -z "${BASH_VERSION:-}" ]]` before `set -euo pipefail`. Clear error when
invoked via sh or dash.

### Tests
19 new bats tests, 2 manual-orchestration tests replaced with real integration
tests. Total: 100 bats (was 81).

---

 — Field-membership discrimination + I-CFG-1 path safety

**760 non-Hypothesis tests · 29 invariants · 10 CI guards**

Closes two High blockers found by external review of v51.1 at call sites that
v51 did not audit.

### H.0.4-1 — Field-absent vs field-present-null (High × 3 call sites)

`dict.get("config_file_hashes")` cannot distinguish "field absent" (legacy v47
baseline, acceptable) from "field present with null value" (malformed H.0-era
manifest, must be rejected). A signed baseline with `config_file_hashes: null`
returned exit 0 ok under v51.1. Fixed at three call sites with `"key" in dict`
membership checks: `checker.py::_evaluate_config_file_hashes`,
`invariants.py::_i_cfg_2`, `baseline.py::_parse_baseline`.

### H.0.4-2 — I-CFG-1 schema-validates before iterating (High)

I-CFG-1 iterated `config_file_hashes` directly. For a signed absolute-path
manifest (`{"/etc/hostname": "sha256:..."}`), `install_dir / "/etc/hostname"`
resolves to `Path("/etc/hostname")` — Python discards `install_dir` for absolute
paths. I-CFG-1 then read `/etc/hostname` and reported its real hash. Fixed by
calling `_validate_config_file_hashes()` before iteration. Malformed manifests
return empty violations (I-CFG-2 owns structural reporting).

### H.0.4-3 — I-CFG-2 null manifest reported as NoneType

After H.0.4-1, I-CFG-2 passes `None` to the non-dict check which reports
`actual_type: NoneType`. Confirmed automatic — no additional code needed.

### Tests

3 new tests. Full suite: 776. Fast suite: 760. CI guards: 10 (unchanged).

---



**757 non-Hypothesis tests · 29 invariants · 10 CI guards**

Closes three integrity gaps (one Medium-High, two High) found by adversarial
review of v50's H.0 schema-validation path.

### H.0.3-1 — Missing sidecar no longer crashes governance-check (Medium-High)

`_read_active_baseline_record_payload()` now catches `NotFoundError` alongside
`IntegrityError`. Missing `.sig.json` sidecar produces deterministic exit 21
(invariant catalog) instead of an uncaught exception crash.

### H.0.3-2 — Schema validation before hash evaluation (High)

`_evaluate_config_file_hashes()` now calls `_validate_config_file_hashes()` before
iterating the manifest. Catches non-dict, empty, partial, extra-keys, and
absolute-path manifests — all route to exit 21 via I-CFG-2 instead of exit 52
(config drift misclassification) or exit 0 (silent bypass).

### H.0.3-3 — Exact-set membership enforced at load time and check time (High)

`_validate_config_file_hashes()` now enforces that the key set is exactly
`set(CONFIG_FILE_PATHS)` — no missing, no extra entries. Empty and partial
manifests are schema violations. Applied at both load time (baseline.py) and
check time (checker.py) as defense in depth.

### H.0.3-4 — I-CFG-2 reports structural violations explicitly

I-CFG-2 strengthened to report: non-dict manifest, completeness violations
(missing/extra keys), per-entry type errors, invalid digest values. Each as
a separate `InvariantViolation`. The invariant now acts as the structural
enforcement layer that the dedicated checker refuses to process.

### H.0.3-5 — Tamper test strengthened + README corrected

`test_check_does_not_return_0_when_active_baseline_tampered` renamed to
`test_check_returns_21_when_active_baseline_tampered_without_resigning` with
assertion strengthened from `!= 52` to `== 21` with I-B-1/I-B-2 in reason.
PHASE_H0_2_README.md corrected: I-B-1 and I-B-2 are root-aware and DO catch
the tamper-without-resigning case.

### Tests

5 new tests. Full suite: 773. Fast suite: 757. CI guards: 10 (unchanged).

---



**752 non-Hypothesis tests · 29 invariants · 10 CI guards**

Closes two interlocking integrity gaps surfaced by external review of v49.

### H.0.2-1 — Invariant catalog gate path mismatch (High)

`GovernanceChecker.check()` invariant gate now uses `self.paths.active_pointer`
and `self.paths.root / "trust"` (derived from `root_dir`) instead of
`self.config.active_pointer` (hardcoded `/opt/wpgovern/state/active.json`).
Under `root_dir` override — the standard pattern for testing and non-default
installations — these diverged and the entire invariant catalog was silently
skipped, returning exit 0 for any state including tampered baselines.

Same fix applied to I-CFG-1 and I-CFG-2 in `wpgovern/utils/invariants.py`:
both now use `build_paths(config).active_pointer` (derived path).

### H.0.2-2 — Active baseline signature not verified (Medium-High)

`_read_active_baseline_record_payload()` now calls
`self.signing.verify_file(baseline_path, domain="runtime")` before returning
the record. If signature verification fails (`IntegrityError`), returns None —
causing the dedicated config-file hash check to skip and the invariant catalog
to run next with the appropriate exit code class. Prevents integrity failures
from being misclassified as config drift (exit 52).

### H.0.2-3 — Strengthen integration test + add regression tests

`test_check_returns_52_not_21_when_config_hash_mismatch` strengthened with
explicit gate-reachability assertions (trust_dir and active_ptr must exist
before the ordering claim is tested). Two new tests added:
`test_check_does_not_return_0_when_active_baseline_tampered` (tamper without
resigning must not produce exit 52) and
`test_invariant_gate_uses_derived_paths_not_config_default` (regression for
the path source-of-truth).

### H.0.2-4 — CI guard subprocess failure detection

`test_readme_test_counts_consistent` now checks `returncode` of both
subprocess calls and calls `pytest.fail()` with a clear diagnostic on failure,
instead of misreporting the error as stale README counts.

### Tests

2 new tests. Full suite: 768. Fast suite: 752. CI guards: 10 (unchanged).

---



**750 non-Hypothesis tests · 29 invariants · 10 CI guards**

Closes the deployment-blocking defect surfaced by external review of v48: config-file hash checks did not fire end-to-end.

### H.0.1-1 — Fix `_read_active_baseline_record_payload`
Added new helper that follows the active pointer to the actual baseline record (which contains `config_file_hashes`). The v48 code passed the pointer payload (which only contains `{baseline_id, activated_at, …}`) to `_evaluate_config_file_hashes`, which always saw `hashes=None` and silently skipped.

### H.0.1-2 — Fix Step 8.5 / Step 8.6 ordering
Moved dedicated config-file hash check (→ exit 52/53) to fire BEFORE the generic invariant catalog (→ exit 21). Without this, I-CFG-1 in the catalog would absorb config-file violations and return generic exit 21 instead of dedicated 52/53.

### H.0.1-3 — Refuse symlinks at compute and check time
`_compute_config_file_hashes` now rejects symlinks before the existence check. `_evaluate_config_file_hashes` returns exit 53 when a governed file has been replaced by a symlink post-baseline.

### H.0.1-4 — Closed-set validator replaces regex
`_validate_relative_path` now enforces closed-set membership in `CONFIG_FILE_PATHS`. Automatically refuses absolute paths, traversal sequences, Windows backslashes, NUL bytes, empty strings. `_TRAVERSAL_PATTERN` regex removed. I-CFG-2 description updated to reflect closed-set semantics.

### H.0.1-5 — Clearer install_dir-missing diagnostic
`_compute_config_file_hashes` pre-checks `install_dir` existence and is-dir before iterating config files. Operator gets "install_dir does not exist" rather than "config file missing" when the root problem is a missing install directory.

### Integration tests added
New `TestGovernanceCheckConfigHashIntegration` class (6 tests) exercises the full create → submit → approve → activate → check flow end-to-end. New CI guard `test_h0_has_integration_tests_for_governance_check` prevents regression.

### Tests
17 new tests. Full suite: 766. Fast suite: 750. CI guards: 10.

---



**733 non-Hypothesis tests · 29 invariants · 9 CI guards**

### H.0-A — Config-file hashing

- **`BaselineRecord` schema:** New optional field `config_file_hashes: dict[str, str] | None = None`. Optional-field discipline: legacy v47 baselines load with `config_file_hashes=None`; no existing test needs modification.
- **`CONFIG_FILE_PATHS` constant:** `("docker-compose.yml", "Caddyfile", "my.cnf", "wp-config.php")` — the four config files governed per strategic plan v1.1.
- **`create_draft()` extended:** Computes SHA-256 hashes for all four config files before entering `AtomicTransaction`. Fail-closed on missing file. Hash manifest included in signed JSON payload.
- **`governance-check` extended:** New step 8.6 verifies `config_file_hashes` against live filesystem. Exit code 52 (hash mismatch); exit code 53 (file missing or unreadable).
- **New invariants:** `I-CFG-1` (runtime: hashes match filesystem) and `I-CFG-2` (structural: relative paths, valid format). Total: 29 invariants.
- **New CI guards:** `test_baseline_record_has_optional_config_field` and `test_no_wp_content_hashing_in_baseline_service`. Total: 9 CI guards.

### H.0-B — CLI profile alignment

- **`BaselineService._docker_wp`:** `docker compose exec -T php wp` → `docker compose run --rm -T cli wp`. wp-cli binary is in the `wordpress:cli` image (cli profile service), not in the `wordpress:fpm` image.

### Tests

- 39 new tests (37 + 2 CI guards). Full suite: 749. Fast suite: 733.
- `tests/conftest.py` — autouse fixture patches `_compute_config_file_hashes` for pre-H.0 tests.

---

## v47 — Phase η (May 2026) — Final hardening sweep

**694 non-Hypothesis tests · 27 invariants · 7 CI guards**

Security findings from independent production-readiness review (external review, May 2026):

### High findings closed
- **η-1 (H1):** Added `I-T-7` invariant — detects `.keygen-*` staging residue (unregistered private key material) under any trust domain. `governance-check` now returns exit 21 when residue is present.
- **η-2 (H2):** Strengthened `I-T-6` — flags unregistered symlinks. Only `<domain>-active.pem` is the managed active pointer in `private/`; no symlinks are permitted in `public/`. All other symlinks are exfiltration vectors and are now violations.
- **η-3 (H3):** Removed `if domain == "runtime"` conditional from `KeyCompromiseService._atomic_write_and_sign`. All compromise reports (runtime and release domain) are now signed with the runtime key. Release key compromise forensic evidence was previously tamper-able.

### Medium-High findings closed
- **η-4 (M-H1):** Moved `sign_bytes`, `verify_bytes` (`signing.py`) and `_openssl_sign_bytes`, `_openssl_verify_bytes` (`journal.py`) from `NamedTemporaryFile + with_suffix` pattern to `TemporaryDirectory`. Eliminates predictable adjacent temp file paths.
- **η-5 (M-H2):** Algorithm field enforcement. `verify_file` and `verify_bytes` now reject any signature with `algorithm != "ed25519"`. Missing field and wrong values both raise `IntegrityError`.

### CI guard added
- `test_no_unsigned_compromise_reports` — structural check that `key_compromise.py` has no path writing a JSON report without `stage_signed_json`.

---

## v46 — Phase ζ (May 2026) — Governance-check integration

**679 non-Hypothesis tests**

- **ζ-1:** `governance-check` now calls `check_all_invariants()`. New exit code 21 for invariant violations. governance-check and the invariant catalog now agree on "healthy."
- **ζ-2:** Bootstrap recovery marker (`state/.bootstrap_recovery_required.json`). Written when `_rollback_writes_from_prior` itself fails (double-failure). `governance-check` returns exit 34. Priority: marker before invariants.

---

## v45 — Phase ε.2 (May 2026) — Duplicate invariant + revoke_key journaling

**672 non-Hypothesis tests**

- **ε.2-1:** Removed duplicate `I-T-6` definition (copy-paste accident). Invariant count: 27 → 26 (correct).
- **ε.2-2:** CI guard `test_no_duplicate_invariant_ids` — catches copy-paste accidents that produce 4 violations where 1 exists.
- **ε.2-3:** `revoke_key` journaled through `AtomicTransaction`. Trust lifecycle atomicity now complete: generate (staging pattern), activate (journaled), revoke (journaled).

---

## v44 — Phase ε.1 (May 2026) — generate_key staging + I-T-6 + I-T-7

**665 non-Hypothesis tests**

- **ε-1:** `generate_key` now uses staging-directory pattern. Keys generated into `.keygen-{key_id}-{token}` sibling directory. On any failure, staging is cleaned up before raising — no orphan key material in governed directories.
- **ε-2:** Added `I-T-6` invariant — every `.pem` in `private/` and every `.pub` in `public/` must be registered in the trust store. Orphan key files detected.

---

## v43 — Phase δ (May 2026) — JSON-then-sign defect class eliminated

**657 non-Hypothesis tests**

- **δ-1:** `BreakglassService.approve` replaced two-step JSON-then-sign with `stage_signed_json`.
- **δ-2:** `RollbackService.approve` same fix.
- Also fixed `KeyCompromiseService` third split site found during grep sweep.
- CI guard `test_no_json_then_sign_split_anywhere` — structural enforcement.

---

## v42 — Phase γ (May 2026) — Final cleanup

**652 non-Hypothesis tests**

- **γ-1:** `_b4_preflight` extended to cover staged deletes and symlink parents (previously only covered write target parents).
- **γ-2:** Dead `_update_active_private_link` method removed from `TrustService`.
- **γ-3:** `_record_b4_event` now fsyncs the evidence directory after file write — durability on power loss.
- **γ-4:** `_rollback_writes_from_prior` handles symlink write targets correctly (restores symlink topology, not file bytes).
- **γ-5:** Dead snapshot call removed from `_write_journal_intent`. Recovery uses file existence, not snapshots.

---

## v41 — Phase β (May 2026) — Invariant and schema hardening

**645 non-Hypothesis tests**

- **β-1:** `I-FS-5` extended to cover all three trust private domains (previously only journal domain).
- **β-2:** `I-T-5` now verifies symlink target is a regular file (previously only checked name and path-inside-tree).
- **β-3:** `JournalSchemaError` added. `read_intent_record` and `read_complete_record` reject missing or wrong `schema_version` explicitly.
- **β-4:** README CI guard upgraded from `re.search` (first match) to `re.findall` (all numeric references). Catches stale counts anywhere in the document.
- **β-5:** `.gitignore` added.

---

## v40 — Phase α.5-fix (May 2026) — I-AUD-2 contract correction

**638 non-Hypothesis tests**

- **α-5-fix:** `I-AUD-2` corrected. Previously fired on ANY chain without a checkpoint (including 1-record test chains). Now fires only when chain exceeds `MAX_TAIL_WINDOW = 100` records without a checkpoint. Small chains without checkpoints are normal startup state.

---

## v39 — Phase α (May 2026) — Final code-side hardening

**637 non-Hypothesis tests**

- **α-1:** Public key precondition in `activate_key` (mirrors private key check).
- **α-2:** Pre-commit checks use `is_file()` not `exists()` — directories at `.pem` or `.pub` paths are refused.
- **α-3:** `validate_store` enforces cryptographic keypair match via shared `_verify_keypair_cryptographic_match` helper. Same contract as `I-T-4`.
- **α-4:** Journaled commit failure now invokes in-process recovery synchronously.
- **α-5:** `I-AUD-2` chain-tail invariant — fires when uncovered tail exceeds `MAX_TAIL_WINDOW`.
- **α-6:** Reviewer-name leakage CI guard added. All remaining reviewer-name references removed from source.

---

## v38 — Phase F (April 2026) — Approval and signing hardening

**626 non-Hypothesis tests**

- **F1:** `verify_active_pointer` checks referenced baseline has `status == "active"`.
- **F2:** `ApprovalService.consume/revoke/check_expiry` use `stage_signed_json` (atomic JSON + signature).
- **F3:** `consume` and `revoke` acquire `["approvals"]` lock before check-then-mutate.
- **F4:** `BaselineService.create_draft` uses `stage_signed_json`.
- **F5:** `sign_file`, `sign_staged`, `verify_file` use `TemporaryDirectory` for raw temp files.

---

## v37 — Phase internal (April 2026) — I-T-4 private key existence + CI guards

**616 non-Hypothesis tests**

- `I-T-4` now reports missing active/preactive private keys as violations (previously silently skipped).
- `activate_key` pre-commit check: verifies private key exists before any transaction mutation.
- `tests/test_ci_guards.py` added — four initial CI guards.

---

## v36 — Phase internal (April 2026) — Bootstrap atomicity + non-journal B4

**607 non-Hypothesis tests**

- Non-journaled transactions capture prior state before writes. `_rollback_writes_from_prior` restores on post-write failure.
- `state_root` decoupled from `journal_root`. `_record_b4_event` uses `state_root` — B4 evidence written even before journal key exists.

---

## v35 — Phase internal (April 2026) — Symlink as first-class journal artifact

**602 non-Hypothesis tests**

- `IntentSymlink` dataclass + `IntentRecord.symlinks` field.
- Recovery handles pending symlinks, verifies post-conditions before `recovery.completed`.
- Symlink B4 persistence.
- Active symlink escape detection (I-T-5 + `validate_store`).

---

## v34 — Phase internal (April 2026) — Trust activation atomicity + invariants

**596 non-Hypothesis tests**

- `activate_key`: JSON and active symlink staged in same `AtomicTransaction`.
- `validate_store`: path-inside-tree enforcement.
- `I-T-3`, `I-T-4`, `I-T-5` invariants added.
- Reviewer-reference cleanup throughout codebase.

---

## v33 — Phase internal (March 2026) — Trust backup full contract

**588 non-Hypothesis tests**

- Trust backup: empty/directory key paths refused.
- `validate_store` uses `is_file()` not `exists()`.
- Preactive keypair validation during restore.
- `I-T-3`, `I-T-4` invariants (precursors).

---

## v32 — Phase internal (March 2026) — Multi-key keypair validation

**579 non-Hypothesis tests**

- Trust backup keypair validation: uses `staging_public_by_key_id` map (not leaked loop variable `key_file`).
- All four key-position shapes tested: active-first, active-middle, active-last, single-key.
- PEM detection regex generalized to catch DSA and PGP private keys.

---

## v31 — Phase internal (March 2026) — Active keypair validation + audit chain

**571 non-Hypothesis tests**

- Trust backup: active keypair cryptographically validated against staging path (not rewritten final path).
- `I-AUD-0` audit chain self_hash recomputation invariant.
- Authorization/Cookie/OpenSSH secret detection in nested audit fields.

---

## v30 — Phase internal (February 2026) — Recovery pending-delete B4

**562 non-Hypothesis tests**

- Recovery pending-delete B4 → `recovery.stuck`.
- Audit token detection in list elements.
- `I-REL-1` catches traversal before file-existence checks.
- `I-AUD-1` checkpoint signature companion invariant.

---

## v22–v29 — Foundation arc (January–February 2026)

Core system built across phases 0–12:

- Clean-room reconstruction: `AtomicTransaction`, `JournalWriter`, `RecoveryService`, `TrustService`, `SigningService`, `BaselineService`, `ApprovalService`, `BreakglassService`, `RollbackService`, `KeyCompromiseService`, `AuditLogger`, `AuditVerifier`, `GovernanceChecker`
- Baseline tamper-laundering closed (v22/v23)
- Timestamped IDs with UUID4 suffix
- Reconciliation atomicity: `AtomicTransaction` with `stage_delete()`
- Release artifact hash verification: `_validate_release_manifest_contract` shared by sign and verify
- Baseline submit/approve journaled via `AtomicTransaction`
- Symlink journaling (`IntentSymlink`, `stage_symlink_replace`)
- B4 evidence B4 preflight + intent + complete-write paths
- Journal delete recovery (`IntentRecord.deletes` field)
- Trust backup: absolute path rewriting, staging-vs-final path separation
- Audit sanitization: recursive dict/list, Unicode normalization, token patterns

---

*See `WPGOVERN_PHASE_PLAN.md` for the original phase-by-phase build specification.*  
*See `docs/CODING_AGENT_REFERENCE.md` for methodology lessons and reconstruction guidance.*  
*See `docs/STRATEGIC_DEPLOYMENT_REPORT.md` for the Phase H deployment arc plan.*
