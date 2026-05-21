# WPGovern

Governance control plane for WordPress installations. Provides a
structured, auditable lifecycle for all operational changes: baseline
creation, approval, activation, rollback, break-glass, reconciliation,
and emergency key compromise response. Every governance action is recorded
in a tamper-evident hash-chained audit log. Review checkpoints are
additionally signed with the runtime key.

---

## Quick start

**Prerequisites:** Python 3.11+, `openssl` on PATH. Linux / macOS / WSL.
Not supported on native Windows.

```bash
pip install -e "[test]"   # installs typer + pytest + hypothesis
pytest tests/ -q          # 760 tests expected (fast non-Hypothesis suite;
                          # full suite with test extras installed: 776 tests)
wpgovern --help
```

`requirements.txt` lists test-only dependencies. Use `pip install -e "[test]"`
as the complete install path — `requirements.txt` alone is not sufficient.

---

## Expected test count

The fast suite (excluding Hypothesis-based tests) collects **760 tests**.
The Hypothesis test files (`tests/test_hypothesis.py` and `tests/test_kill_points.py`)
add 16 more for a total of **776 tests** with test extras installed.

Pass `--ignore=tests/test_hypothesis.py --ignore=tests/test_kill_points.py`
for a fast smoke run.

---

## Documentation

| Document | Location | Contents |
|---|---|---|
| Changelog | `CHANGELOG.md` | Complete arc v22→v47, every version, test counts, key changes |
| Coding Agent Reference | `docs/CODING_AGENT_REFERENCE.md` | Methodology lessons v2.0 — for Drupal-Govern, OpenEdX-Govern, future reconstructions |
| Strategic Deployment Report | `docs/STRATEGIC_DEPLOYMENT_REPORT.md` | Phase H.1–H.8 deployment arc plan, Hetzner architecture, operational decisions |
| Phase build specs | `PHASE_*_README.md` | Per-phase implementation specifications (phases 0–12) |

---

## Smoke tests

```bash
python -c "from wpgovern.errors import WPGovernError, B4Error"
python -c "from wpgovern.audit.logger import AuditLogger"
python -c "from wpgovern.cli import app"
wpgovern --help
```

---

## Key commands

```bash
wpgovern governance-check          # exit 0=healthy, non-zero=issue
wpgovern audit-verify              # verify audit chain integrity
wpgovern audit-review --auto-confirm --reason "monthly review"
wpgovern audit-checkpoints         # list signed review checkpoints
wpgovern trust-backup <output>     # encrypt trust material to backup
wpgovern trust-restore <input> --confirm --reason "restore after crash"
```

---

## Releasing

Before creating a release zip, prune build artifacts:

```bash
rm -rf .hypothesis/ .pytest_cache/ __pycache__/ */__pycache__/
find . -name "*.pyc" -delete
```

Then create the zip from the cleaned directory.

---

## Known limits

- **Audit chain consistent-rewrite:** `verify()` detects blind tampering
  only. A privileged writer with access to the log file can rewrite the
  chain and recompute all hashes. Checkpoint records are signed with the
  runtime key (Step 3), which raises the attack bar — the signature
  cannot be forged without the runtime private key — but external
  anchoring (WORM storage, remote syslog, RFC 3161) is the full mitigation.

- **Release manifest schema:** Both `sign_release()` and `verify_release()` now
  enforce the full manifest contract: non-empty manifest, non-empty artifacts list,
  valid sha256 format, no path traversal, artifact files exist, and hashes match.
  The same shared validator is used in both paths.

- **Trust-store root anchoring:** The trust store JSON has no offline
  root of trust. Tracked for a future "trust-store root anchoring" pass.

- **Single-node locking:** `fcntl.flock` is advisory and not NFS-safe.

- **Actor identity:** The operator's identity in audit records is
  environment-driven, not cryptographically bound.

---

## Platform

Linux and macOS (POSIX). Requires `openssl`, `chattr`/`lsattr` for
filesystem hardening (optional — degrades gracefully if absent).
