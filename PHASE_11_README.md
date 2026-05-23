# Phase 11 — CLI Split

**Status:** Complete
**Tests:** 415 total (363 from Phases 0-10, 52 new), 0 failed
**Modules authored:** `cli/_common.py`, `cli/commands/{misc,baseline,trust,policy,audit,status,journal,keys}.py`, `cli/__init__.py` (assembler)

---

## What this phase delivers

The Phase 0 CLI stub is replaced by a fully functional CLI split across eight command modules. All 57 commands from v21 are implemented.

| File | Commands |
|------|----------|
| `cli/_common.py` | Shared helpers, type aliases, `_config()`, `_actor_context()`, `_run_with_error_handling()` |
| `cli/commands/misc.py` | `version`, `fresh`, `update`, `repair`, `status`, `logs`, `restart`, `backup` |
| `cli/commands/baseline.py` | `baseline-create`, `baseline-submit`, `baseline-approve`, `baseline-activate`, `active-verify` |
| `cli/commands/trust.py` | `trust-key-{generate,activate,revoke}`, `trust-verify`, `release-key-{generate,activate,revoke}`, `release-trust-verify`, `release-{sign,verify}` |
| `cli/commands/policy.py` | `rollback-{approve,activate}`, `breakglass-{approve,activate,review}`, `reconciliation-complete`, `approval-revoke` |
| `cli/commands/audit.py` | `audit-{verify,review,checkpoints,fs-harden,fs-status}`, `alert-{test,triggers}` |
| `cli/commands/status.py` | `governance-check`, `governance-report` |
| `cli/commands/journal.py` | `bootstrap-journal-key`, `journal-key-{generate,activate,revoke}`, `journal-trust-verify`, `journal-key-status`, `transaction-status`, `recovery-replay`, `key-compromise-journal`, `prune-journal-key`, `migrate-journal-v1-to-v2` |
| `cli/commands/keys.py` | `key-compromise-{runtime,release}`, `trust-{backup,restore}`, `b4-{status,clear}`, `invariants-check` |
| `cli/__init__.py` | Assembler + startup recovery hook |

---

## Design decisions

### Single `app` — not sub-apps
All commands are registered on a single flat Typer app. This matches v21's command model and avoids nested sub-command group complexity (`wpgovern trust key-generate` vs `wpgovern trust-key-generate`).

### Startup recovery hook
`main()` calls `_run_startup_recovery()` which runs `RecoveryService.recover()` before any governance command dispatches. Skip conditions:
- No args (help screen)
- `--help`, `-h`, `--version`
- `version` or `fresh` commands (bootstrap paths — state may not exist)

This preserves the v12 fatal-on-refused contract at the CLI entry point.

### `_config()` is a function, not a module-level constant
`_config()` is called at command execution time, not at import time. This allows tests to monkeypatch `_config` in individual command modules.

### Monkeypatching `_config` across modules
Each command module does `from wpgovern.cli._common import _config`. This creates a local binding in the importing module. To patch effectively in tests, patch the `_config` attribute in each command module where it's used (`monkeypatch.setattr(trust_cmd, "_config", lambda: config)`), not just in `_common.py`.

---

## Test coverage summary

**`tests/test_cli.py`** (52 tests) — `version` outputs package version, `--help` exits 0, all 45 key commands registered in help output (parametrized), `transaction-status` returns clean JSON without creating root, `governance-check` outputs JSON with `exit_code`, `governance-check` exits non-zero without trust store, `audit-verify --help` works, `trust-key-generate` outputs key_id via patched config.

---

## KNOWN_LIMITS

See `WPGOVERN_PHASE_PLAN.md` section "KNOWN_LIMITS carried forward." No changes.
