# Phase H.5 — WPGovern Python Control Plane Integration (Byte-One Ceremony)

**Status:** Complete  
**Bats tests:** 251 (was 229; +22 new)  
**Python tests:** 776 (unchanged — Python control plane at v52.1, untouched)  
**New bash files:** 2 (`modules/ceremony/install_python.sh`, `modules/ceremony/byte_one.sh`)  
**New Python file:** `installer_tests/h5_integration_runner.py`  
**Vendored sdist:** `installer/vendor/wpgovern-0.1.0.tar.gz`

---

## Purpose

H.5 is the bash arc's transition point. H.0–H.4 built the substrate: hardened host, deterministic four-container stack, governed WordPress installation, four file-hash-governable artifacts at install-dir root. H.5 connects the substrate to the Python control plane that has been waiting since v52.1 closure.

**After H.5, the system has crossed the governance threshold.** The four governed artifacts have a signed baseline. Any future drift triggers `governance-check` exit non-zero. Operator changes must go through the create → submit → approve → activate flow.

---

## The byte-one ceremony — nine steps

The bash module orchestrates; the Python CLI (`wpgovern`) is the authority. Each step:

| Step | Command | What it does |
|------|---------|-------------|
| 1 | `wpgovern trust-key-generate runtime-1` | Generate runtime trust key |
| 2 | `wpgovern trust-key-activate runtime-1` | Activate runtime key |
| 3 | `wpgovern journal-key-generate journal-1` | Generate journal trust key |
| 4 | `wpgovern journal-key-activate journal-1` | Activate journal key |
| 5 | `wpgovern baseline-create` | Hash the four governed files, produce signed draft |
| 6 | `wpgovern baseline-submit <id>` | Transition draft → submitted |
| 7 | `wpgovern baseline-approve <id>` | Self-approve (documented bootstrap exception) |
| 8 | `wpgovern baseline-activate <id> <approval_id>` | Activate → write active.json |
| 9 | `wpgovern governance-check` | Verify system is governance-coherent |

Each step is idempotent: reads a state fact on entry, skips if already recorded. Partial failures recover on re-run from the failed step.

---

## Architectural decisions

**Decision 1 — Vendored sdist (not PyPI).** The installer ships `installer/vendor/wpgovern-0.1.0.tar.gz`. The bash arc and Python control plane are versioned together. PyPI installs are correct when versions are independently released; at v1 they ship together.

**Decision 2 — `WPGOVERN_ACTOR_ID` env var (default: `installer`).** Single-operator v1 default. Future multi-operator scope: set to an identifiable actor (e.g., `alice@example.com`). Recorded in every governance audit event.

**Decision 3 — Per-step resumption from state facts.** Nine state facts, one per step. Re-running the installer on partial failure skips completed steps and retries from the first uncompleted step.

---

## Hard requirement: `WPGOVERN_INSTALL_DIR=/opt/wpgovern-install`

The Python control plane's `WPGovernConfig.install_dir` defaults to `/opt/wpgovern-install` (hardcoded). The bash installer's `WPGOVERN_INSTALL_DIR` must match exactly, or `baseline-create` will fail to find the governed config files.

`wpgovern::ceremony::byte_one` validates this at function entry and fails closed with a clear error if the paths disagree. This is a deployment convention, not a future-scope item to relax.

---

## Self-approval bootstrap exception

Step 7 (`baseline-approve`) is a self-approval: the same actor that creates the baseline also approves it. This is the canonical initial exception for v1 single-operator deployments.

**Why it's acceptable here:** H.5 installs the governance system itself. Before H.5 runs, there is no governance trust store — there is no approved approver to ask. The bootstrap exception establishes the first trusted state from which future governance operations (including future approvals by a different actor) can occur.

**Documentation discipline:** the exception is explicitly documented here, in CHANGELOG.md, and in the audit trail recorded by `baseline-approve`. It is not hidden.

**When separation of duties matters:** future multi-operator deployments set `WPGOVERN_ACTOR_ID` differently for the approver vs the installer and run `baseline-approve` under a separate actor's credential. The Python control plane already supports this; the bash module just doesn't enforce it in v1.

---

## Bash → Python interface contract

| Command | Stdout captured? | Stderr | Exit 0 means |
|---------|-----------------|--------|-------------|
| `wpgovern version` | yes (version string) | unused | install OK |
| `wpgovern trust-key-generate <id>` | no (fire-and-forget) | unused | key generated as preactive |
| `wpgovern trust-key-activate <id>` | no | unused | key transitioned to active |
| `wpgovern journal-key-generate <id>` | no | unused | journal key generated |
| `wpgovern journal-key-activate <id>` | no | unused | journal key active |
| `wpgovern baseline-create` | **yes** (baseline_id) | discarded (`2>/dev/null`) | draft baseline signed |
| `wpgovern baseline-submit <id>` | no | unused | draft → submitted |
| `wpgovern baseline-approve <id>` | **yes** (approval_id) | discarded | submitted → approved |
| `wpgovern baseline-activate <id> <aid>` | no | unused | approved → active, active.json written |
| `wpgovern governance-check` | no | summary lines | system is governance-coherent |

**Stream discipline enforced:** captured-stdout invocations use `2>/dev/null` (stderr discarded, stdout captured cleanly). Fire-and-forget invocations use `>/dev/null 2>&1` (both discarded). Never `2>&1` on a captured invocation — that conflates streams and corrupts the captured ID.

---

## Trust model after H.5

```
/opt/wpgovern/
├── .venv/               # Python package venv
├── trust/
│   ├── runtime/         # runtime trust keys
│   └── journal/         # journal trust keys
└── state/
    ├── baselines/        # signed baseline JSON + signature sidecars
    ├── approvals/        # approval records
    └── active.json       # → points to currently active baseline

/opt/wpgovern-install/    # WPGOVERN_INSTALL_DIR
├── docker-compose.yml    # governed artifact #1
├── Caddyfile             # governed artifact #2
├── my.cnf                # governed artifact #3
└── wp-config.php         # governed artifact #4
```

---

## Vendored sdist integrity

`installer/vendor/wpgovern-0.1.0.tar.gz`  
SHA-256: `30b4583c0b7574e774b95eab184371f29366f38443a2f1f4f6b90e405e2f67a6`

Verify on any system:
```bash
sha256sum installer/vendor/wpgovern-0.1.0.tar.gz
```

---

## `wpgovern governance-check` semantics

| Exit code | Meaning |
|-----------|---------|
| 0 | System is governance-coherent |
| 52 | `config_file_hash_mismatch` — a governed file was modified outside the installer |
| Other non-zero | Other governance violations (see governance-report for details) |

---

## New env vars (three coordinated sites each)

`WPGOVERN_ACTOR_ID` — governance actor identity. Default: `installer`. Regex: `^[a-zA-Z][a-zA-Z0-9_.@-]{0,63}$`. Added to env.example, whitelist, validation.

`WPGOVERN_CEREMONY_REASON` — governance reason for the bootstrap approval. Default: `byte-one bootstrap`. ≤200 printable chars. Added to env.example, whitelist, validation.

---

## New state facts

| Fact | Value |
|------|-------|
| `ceremony.python_installed_at` | ISO timestamp (first install) |
| `ceremony.python_installed_skipped_at` | ISO timestamp (idempotent skip) |
| `ceremony.python_version` | String returned by `wpgovern version` |
| `ceremony.runtime_key_id` | `"runtime-1"` |
| `ceremony.step_1_completed_at` through `ceremony.step_9_completed_at` | ISO timestamps |
| `ceremony.journal_key_id` | `"journal-1"` |
| `ceremony.baseline_id` | ID string (e.g. `baseline-20260521T...`) |
| `ceremony.approval_id` | ID string |
| `ceremony.activated_at` | ISO timestamp |
| `ceremony.governance_check_passed_at` | ISO timestamp |

---

## What H.5 does NOT do

- No operational audit command — that's H.6 (`install-audit`)
- No backup or restore — that's H.7
- No systemd services for the ceremony (it's a one-time install-time operation)
- No multi-operator separation of duties enforcement (deferred per strategic plan)
- No credential rotation for AUTH_KEYs or DB passwords

---

## What H.6 begins next

`wpgovern install-audit` — the three-layer operational health command: governance layer (governance-check), container layer (all four services healthy), WordPress layer (HTTP 200 on the configured domain). Returns structured exit codes for automation.

---

## Test count

| Suite | H.4.1 | H.5 |
|-------|-------|-----|
| Bats | 229 | 251 |
| Python | 776 | 776 |
| Bash files | 21 | 23 |
| File-hash governed | 4 | 4 |

---

## H.5.1 hardening note

**H.5 Python control plane verified correct by external review.** Baseline creation, signature, tamper detection at exit_code=52 all confirmed empirically. Five blockers at the bash↔Python integration boundary closed.

### Five blockers closed

**H.5.1-1 (High) — Wheelhouse replaces sdist.** `pip install --no-index <sdist>` failed on fresh box due to unfulfilled build deps (setuptools≥68, typer≥0.12 and its transitive chain). Fixed by vendoring 9 `.whl` files; production install uses `--no-index --find-links installer/vendor/ wpgovern==0.1.0`. Offline PoC verified: fresh venv + no network access → `wpgovern version` = 0.1.0.

**H.5.1-2 (High) — Array argv at all 9 ceremony call sites.** `_wpgovern_ceremony_actor_args` returned a string; `$(...)` word-split `"byte-one bootstrap"` into `byte-one` and `bootstrap` (dangling positional). Real CLI rejected: `Got unexpected extra argument (bootstrap)`. Fixed via `_WPGOVERN_CEREMONY_ARGS=(--actor-id ... --reason ...)` global array; callers expand `"${_WPGOVERN_CEREMONY_ARGS[@]}"`.

**H.5.1-3 (High) — CEREMONY_REASON whitespace exception.** `load_env` rejected `WPGOVERN_CEREMONY_REASON="byte-one bootstrap"` (space in value). Exception extended from `WPGOVERN_WP_SITE_TITLE` to also cover `WPGOVERN_CEREMONY_REASON`. Metacharacter rejection still applies.

**H.5.1-4 (Med-High) — Default-path consistency.** `bootstrap.sh:122` defaulted to `/opt/wpgovern` (H.1 legacy); `byte_one()` requires `/opt/wpgovern-install`. Now: `${WPGOVERN_INSTALL_DIR:-/opt/wpgovern-install}`. Audit: `/opt/wpgovern` (without `-install`) remains only in venv path (`/opt/wpgovern/.venv`) and shim exec path — correct.

**H.5.1-5 (Med-High) — Capture-then-test in step_9.** `if ! cmd; then local ec=$?` evaluated the negated pipeline's status (always 0 in the then-branch), masking real exit code (52 on tamper). Fixed with: `cmd; local exit_code=$?; if [[ $exit_code -ne 0 ]]; then ... exit ${exit_code}`.

### Four supporting items closed

**H.5.1-6** — Cat heredoc in install_python.sh now guarded: `if ! cat > "$shim_tmp" << 'SHIM'; then rm -f "$shim_tmp"; mark_phase_failed; return 1; fi`. H.4.1-3 discipline travels to all four operations.

**H.5.1-7** — Test count: 259 bats total. H.5.1-specific new tests: 2 (exit-code + array-argv regression in byte_one_steps) + 1 (wheelhouse offline in install_python) + 2 (production-path in test_h5_production_path) + 3 (bootstrap regressions for H.5.1-3+4). Prior README claimed 22; actual H.5-specific file tests: 20. With H.5.1 additions the total is correct at 259.

**H.5.1-8** — `test_h5_production_path.bats` + `h5_integration_runner_cli_wrapper.py`: exercises `byte_one.sh` invoking real wpgovern CLI (not Python services directly). Whitespace reason passed; tamper detection records exit 52 in state.

**H.5.1-9** — State-fact trust limitation documented below.

---

## Wheelhouse integrity (installer/vendor/)

| Wheel | SHA-256 |
|-------|---------|
| `wpgovern-0.1.0-py3-none-any.whl` | `f9d209f92189083eeb3d141a5478715fb629d8939a1df9d1ecd4a122405eb4f9` |
| `typer-0.25.1-py3-none-any.whl` | `75caa44ed46a03fb2dab8808753ffacdbfea88495e74c85a28c5eefcf5f39c89` |
| `click-8.4.1-py3-none-any.whl` | `482be17c6991b8c19c5429a1e995d9b0efdbb63172824c41f99965dc0ade8ec2` |
| `rich-15.0.0-py3-none-any.whl` | `33bd4ef74232fb73fe9279a257718407f169c09b78a87ad3d296f548e27de0bb` |
| `shellingham-1.5.4-py2.py3-none-any.whl` | `7ecfff8f2fd72616f7481040475a65b2bf8af90a56c89140852d1120324e8686` |
| `pygments-2.20.0-py3-none-any.whl` | `81a9e26dd42fd28a23a2d169d86d7ac03b46e2f8b59ed4698fb4785f946d0176` |
| `markdown_it_py-4.2.0-py3-none-any.whl` | `9f7ebbcd14fe59494226453aed97c1070d83f8d24b6fc3a3bcf9a38092641c4a` |
| `mdurl-0.1.2-py3-none-any.whl` | `84008a41e51615a49fc9966191ff91509e3c40b939176e643fd50a5c2196b8f8` |
| `annotated_doc-0.0.4-py3-none-any.whl` | `571ac1dc6991c450b25a9c2d84a3705e2ae7a53467b5d111c24fa8baabbed320` |

Verify: `sha256sum installer/vendor/*.whl`

## State-fact trust model (v1 limit, documented)

The bash module trusts its own state facts for idempotency. If `ceremony.baseline_id` exists, step 5 skips — assuming a baseline JSON exists in `/opt/wpgovern/state/baselines/`.

**Limitation:** if the baseline JSON is wiped while the installer state file is intact, step 5 skips but step 6 fails (baseline-submit cannot find the JSON).

**Recovery:**
```bash
jq 'del(.host_facts | with_entries(select(.key | startswith("ceremony."))))' \
    /var/lib/wpgovern/.state.json > /tmp/state-clean.json
mv /tmp/state-clean.json /var/lib/wpgovern/.state.json
```

**Future hardening:** before skipping step 5, verify the baseline JSON exists on disk. Deferred for v1 single-operator deployments.
