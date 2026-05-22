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
