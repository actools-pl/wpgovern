# Phase 0 — Scaffold & Errors

**Status:** Complete  
**Reference:** `wpgovern_clean_v21.zip` (frozen)  
**Reconstruction artifact:** `wpgovern_phase0.zip`

---

## What this phase delivers

1. `pyproject.toml` — clean build config; no v-version comments; no Pydantic dependency
2. `requirements.txt` — test deps only (pytest, hypothesis); no inline version comments
3. Package skeleton — all sub-packages and modules present as importable stubs
4. `errors.py` — **fully authored** exception hierarchy
5. `cli/__init__.py` — minimal Typer stub (one `version` command) sufficient for `wpgovern --help`
6. `cli/commands/` — directory declared; all command-group stubs present for Phase 11

---

## Design decisions

### No `models/` directory
The `models/` directory from v21 is not reproduced. Data records (`ApprovalRecord`,
`AuditRecord`, `TrustKeyRecord`, `TrustStore`, `ReconciliationRecord`) are stdlib
dataclasses authored in their owning modules during their respective phases. There is
no centralised models package at any point in the reconstruction.

### No Pydantic runtime dependency
v21 listed `pydantic>=2.0` in runtime dependencies and used it for the `models/`
dataclasses. Since `models/` is eliminated and the governance engine uses only the
standard library, Pydantic is removed from `[project.dependencies]`. It does not
appear anywhere in the reconstruction.

### Entry point changed from `wpgovern.cli.cli:main` to `wpgovern.cli:main`
v21 used a shim in `cli/__init__.py` that replaced itself with `cli.cli` in
`sys.modules`. This was historical sediment from the original module layout.
The reconstruction uses `wpgovern.cli:main` (pointing to `cli/__init__.py`) and
Phase 11 will build the full assembly there. The shim is gone.

### CLI sub-module layout declared in Phase 0
The `cli/commands/` directory exists from Phase 0 so the import tree is stable from
the start. Each `cli/commands/*.py` stub is importable. Phase 11 fills them out.

### `pytest` exits 5 in Phase 0 (not 0)
pytest exit code 5 means "no tests were collected." This is the correct and expected
state for Phase 0 — there is nothing to test yet. The smoke-test check is:

```
pytest --co -q   # collect-only; exits 0 when nothing found
```

Or equivalently, verify that `pytest` exits 5 (not 1, 2, or 3, which indicate failures).

---

## Error hierarchy

```
WPGovernError (RuntimeError)
├── IntegrityError       — governance integrity check failed
├── NotFoundError        — required governance artifact missing
├── ValidationError      — supplied input or state is invalid
├── PolicyError          — governance policy rule violated
└── B4Error              — filesystem write failure mid-operation
    ├── DiskFullError                   (errno 28 ENOSPC)
    ├── ReadOnlyFilesystemError         (errno 30 EROFS / 5 EIO / 116 ESTALE / 110 ETIMEDOUT)
    ├── PermissionError_                (errno 13 EACCES)
    └── ReadOnlyDuringRecoveryError     (B4 during recovery — produces exit 33)
```

`_classify_oserror(exc, path, phase)` — converts an OSError at an I/O point into the
appropriate B4Error subclass. Returns `None` if the errno is not a B4 condition.

`_classify_during_recovery(exc, path, phase)` — same but produces
`ReadOnlyDuringRecoveryError`; use inside the recovery loop only.

Both helpers are in `errors.py` so they are available to every phase without
introducing inter-module dependencies.

---

## Invariants established in this phase

1. Every sub-package and module is importable without error.
2. `errors.py` is complete and stable; no subsequent phase modifies it.
3. The exception hierarchy is documented in this README and is the single
   authoritative source. Phase READMEs reference this hierarchy; they do not restate it.
4. No `models/` directory exists.
5. No Pydantic dependency anywhere in the package.

---

## Smoke tests (all pass)

```bash
pip install -e .                                    # exit 0
wpgovern --help                                     # exit 0, no ImportError
wpgovern version                                    # prints 0.1.0
python -c "from wpgovern.errors import WPGovernError, B4Error, _classify_oserror"  # exit 0
pytest --co -q                                      # exit 0, 0 items
```

Full import sweep: 43 modules imported without error (all stubs + errors.py).

---

## KNOWN_LIMITS (carried forward — not restated per phase)

See the approved phase plan `WPGOVERN_PHASE_PLAN.md`, section "KNOWN_LIMITS carried
forward." Eight items. None are in scope for this reconstruction.

---

## Files delivered

```
wpgovern/
├── __init__.py               version = "0.1.0"
├── errors.py                 FULLY AUTHORED — complete hierarchy
├── config.py                 stub (Phase 1)
├── paths.py                  stub (Phase 1)
├── audit/
│   ├── __init__.py
│   ├── alerter.py            stub (Phase 9)
│   ├── fs_hardening.py       stub (Phase 3)
│   ├── logger.py             stub (Phase 3)
│   └── verifier.py           stub (Phase 9)
├── cli/
│   ├── __init__.py           minimal stub — version command only
│   └── commands/
│       ├── __init__.py
│       ├── audit.py          stub (Phase 11)
│       ├── baseline.py       stub (Phase 11)
│       ├── journal.py        stub (Phase 11)
│       ├── keys.py           stub (Phase 11)
│       ├── misc.py           stub (Phase 11)
│       ├── policy.py         stub (Phase 11)
│       ├── status.py         stub (Phase 11)
│       └── trust.py          stub (Phase 11)
├── core/
│   ├── __init__.py
│   ├── actor.py              stub (Phase 5)
│   ├── baseline.py           stub (Phase 6)
│   ├── key_compromise.py     stub (Phase 8)
│   ├── signing.py            stub (Phase 5)
│   ├── trust.py              stub (Phase 5)
│   └── trust_backup.py       stub (Phase 8)
├── policy/
│   ├── __init__.py
│   ├── approval.py           stub (Phase 6)
│   ├── breakglass.py         stub (Phase 7)
│   ├── reconciliation.py     stub (Phase 7)
│   └── rollback.py           stub (Phase 7)
├── status/
│   ├── __init__.py
│   ├── checker.py            stub (Phase 10)
│   └── reporter.py           stub (Phase 10)
└── utils/
    ├── __init__.py
    ├── fs.py                 stub (Phase 2)
    ├── invariants.py         stub (Phase 12)
    ├── journal.py            stub (Phase 4)
    ├── jsonio.py             stub (Phase 2)
    ├── locking.py            stub (Phase 2)
    ├── recovery.py           stub (Phase 4)
    ├── time.py               stub (Phase 2)
    └── transaction.py        stub (Phase 2)
pyproject.toml
requirements.txt
README.md
tests/
└── __init__.py
```
