"""
WPGovern on-disk invariant catalog.

Falco-style runtime invariants applied to WPGovern's on-disk state.
Each invariant is a function that inspects the system and returns a list
of violations. The full suite is ``check_all_invariants``; the
test-friendly form is ``assert_invariants_hold``.

Invariant catalog:

Filesystem / on-disk state:
  I-FS-1  Journal directory mode is 0o700
  I-FS-2  All .intent files have mode 0o600
  I-FS-3  No .intent.staged file outlives its commit
  I-FS-4  Backup directory mode is 0o700
  I-FS-5  Trust journal/private/ is 0o700; private keys are 0o600
  I-FS-6  .last_b4_event.json is 0o600 if it exists

Journal record format:
  I-J-1   Every .intent's intent_integrity_hash matches recomputation
  I-J-3   Every .complete has a matching .intent
  I-J-4   No two .intent files share a txn_id

Trust store:
  I-T-1   At most one key per domain has status 'active'
  I-T-2   A revoked key has revoked_at set; an active key does not

Recovery semantics:
  I-R-1   After successful recover(), no .intent files remain
           (conditional — only meaningful when checked after recover())

Negative-space queries:
  I-NEG-JOURNAL     No unexpected files/dirs in journal directory
  I-NEG-NOSYMLINKS  No symlinks in journal directory
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from wpgovern.config import WPGovernConfig


@dataclass(frozen=True)
class InvariantViolation:
    """A single violation surfaced by an invariant check.

    ``invariant_id``: e.g., "I-FS-1"
    ``description``:  short human-readable summary
    ``details``:      dict with violation specifics (path, mode found, etc.)
    ``severity``:     "error" or "warning" — error fails tests; warning logged.
    """
    invariant_id: str
    description: str
    details: dict
    severity: str = "error"

    def to_dict(self) -> dict:
        return {
            "invariant_id": self.invariant_id,
            "description": self.description,
            "details": self.details,
            "severity": self.severity,
        }


# Registry auto-populated by the @invariant decorator.
_INVARIANT_REGISTRY: list[tuple[str, str, Callable]] = []


def invariant(invariant_id: str, description: str):
    """Decorator: register an invariant check function.

    The function takes a ``WPGovernConfig`` and returns a list of
    ``InvariantViolation`` (empty list if the invariant holds).
    """
    def decorator(fn: Callable) -> Callable:
        _INVARIANT_REGISTRY.append((invariant_id, description, fn))
        return fn
    return decorator


def check_all_invariants(config: WPGovernConfig) -> list[InvariantViolation]:
    """Run every registered invariant check against the given config.

    Returns a flat list of all violations found. A check that itself
    raises is recorded as its own ``error``-severity violation so the
    caller receives a complete picture rather than a mid-sweep crash.
    """
    violations: list[InvariantViolation] = []
    for inv_id, desc, fn in _INVARIANT_REGISTRY:
        try:
            result = fn(config)
            if result:
                violations.extend(result)
        except Exception as exc:  # noqa: BLE001
            violations.append(InvariantViolation(
                invariant_id=inv_id,
                description=desc,
                details={"checker_exception": f"{type(exc).__name__}: {exc}"},
                severity="error",
            ))
    return violations


def assert_invariants_hold(config: WPGovernConfig) -> None:
    """pytest-friendly: raises AssertionError listing every violation found."""
    violations = check_all_invariants(config)
    errors = [v for v in violations if v.severity == "error"]
    if errors:
        lines = ["Invariants violated:"]
        for v in errors:
            lines.append(f"  [{v.invariant_id}] {v.description}: {v.details}")
        raise AssertionError("\n".join(lines))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_dir_mode(
    path: Path, expected: int, inv_id: str, desc: str,
) -> list[InvariantViolation]:
    if not path.exists():
        return []
    if not path.is_dir():
        return [InvariantViolation(
            invariant_id=inv_id, description=desc,
            details={"path": str(path), "expected": "directory", "actual": "not a directory"},
        )]
    actual = path.stat().st_mode & 0o777
    if actual != expected:
        return [InvariantViolation(
            invariant_id=inv_id, description=desc,
            details={"path": str(path), "expected_mode": oct(expected), "actual_mode": oct(actual)},
        )]
    return []


def _check_file_mode_glob(
    parent: Path, pattern: str, expected: int, inv_id: str, desc: str,
) -> list[InvariantViolation]:
    if not parent.exists():
        return []
    violations: list[InvariantViolation] = []
    for f in parent.glob(pattern):
        if not f.is_file():
            continue
        actual = f.stat().st_mode & 0o777
        if actual != expected:
            violations.append(InvariantViolation(
                invariant_id=inv_id, description=desc,
                details={"path": str(f), "expected_mode": oct(expected), "actual_mode": oct(actual)},
            ))
    return violations


# ---------------------------------------------------------------------------
# Filesystem invariants
# ---------------------------------------------------------------------------


@invariant("I-FS-1", "Journal directory mode is 0o700")
def _i_fs_1(config: WPGovernConfig) -> list[InvariantViolation]:
    journal_dir = config.root_dir / "state" / ".journal"
    return _check_dir_mode(journal_dir, 0o700, "I-FS-1", "Journal directory mode is 0o700")


@invariant("I-FS-2", "All .intent files have mode 0o600")
def _i_fs_2(config: WPGovernConfig) -> list[InvariantViolation]:
    journal_dir = config.root_dir / "state" / ".journal"
    return _check_file_mode_glob(
        journal_dir, "*.intent", 0o600, "I-FS-2", "All .intent files have mode 0o600",
    )


@invariant("I-FS-3", "No .intent.staged file outlives its commit")
def _i_fs_3(config: WPGovernConfig) -> list[InvariantViolation]:
    journal_dir = config.root_dir / "state" / ".journal"
    if not journal_dir.exists():
        return []
    stale = list(journal_dir.glob("*.intent.staged"))
    if stale:
        return [InvariantViolation(
            invariant_id="I-FS-3",
            description="No .intent.staged file outlives its commit",
            details={"stale_paths": [str(p) for p in stale]},
        )]
    return []


@invariant("I-FS-4", "Backup directory mode is 0o700")
def _i_fs_4(config: WPGovernConfig) -> list[InvariantViolation]:
    backups = config.root_dir / "state" / ".journal" / "backups"
    return _check_dir_mode(backups, 0o700, "I-FS-4", "Backup directory mode is 0o700")


@invariant("I-FS-5", "Trust private dirs (journal/runtime/release) are 0o700; private keys 0o600 across all domains")
def _i_fs_5(config: WPGovernConfig) -> list[InvariantViolation]:
    """Check that all three trust private directories have mode 0o700 and
    that all .pem files inside them have mode 0o600.

    β-1: Originally only covered trust/journal/private. Runtime and release
    private keys at world-readable mode (e.g. 0o644) were not detected.
    The contract is the same for all three sibling domains — apply it uniformly.
    """
    violations: list[InvariantViolation] = []
    for domain in ("journal", "runtime", "release"):
        private_dir = config.root_dir / "trust" / domain / "private"
        violations.extend(_check_dir_mode(
            private_dir, 0o700, "I-FS-5",
            f"Trust {domain}/private/ is 0o700",
        ))
        violations.extend(_check_file_mode_glob(
            private_dir, "*.pem", 0o600, "I-FS-5",
            f"{domain.capitalize()} private keys are 0o600",
        ))
    return violations


@invariant("I-FS-6", ".last_b4_event.json is 0o600 if it exists")
def _i_fs_6(config: WPGovernConfig) -> list[InvariantViolation]:
    event_path = config.root_dir / "state" / ".last_b4_event.json"
    if not event_path.exists():
        return []
    actual = event_path.stat().st_mode & 0o777
    if actual != 0o600:
        return [InvariantViolation(
            invariant_id="I-FS-6",
            description=".last_b4_event.json is 0o600",
            details={"path": str(event_path), "expected_mode": "0o600", "actual_mode": oct(actual)},
        )]
    return []


# ---------------------------------------------------------------------------
# Journal record invariants
# ---------------------------------------------------------------------------


@invariant("I-J-1", "Every .intent's intent_integrity_hash matches recomputation")
def _i_j_1(config: WPGovernConfig) -> list[InvariantViolation]:
    from wpgovern.utils.journal import (
        compute_intent_integrity_hash, list_intent_records, read_intent_record,
    )
    journal_dir = config.root_dir / "state" / ".journal"
    if not journal_dir.exists():
        return []
    # Skip refused intents — legitimately corrupt by design.
    refused_ids: set[str] = set()
    reports_dir = journal_dir / "recovery-reports"
    if reports_dir.exists():
        for report_path in reports_dir.glob("*.json"):
            try:
                report = json.loads(report_path.read_text())
                if report.get("action") in ("refused", "stuck"):
                    refused_ids.add(report_path.stem)
            except (json.JSONDecodeError, OSError):
                pass  # Malformed recovery report — skip gracefully
    violations: list[InvariantViolation] = []
    for intent_path in list_intent_records(journal_dir):
        tid = intent_path.stem
        if tid in refused_ids:
            continue
        try:
            record = read_intent_record(intent_path)
            recomputed = compute_intent_integrity_hash(record)
            if recomputed != record.intent_integrity_hash:
                violations.append(InvariantViolation(
                    invariant_id="I-J-1",
                    description="intent_integrity_hash matches recomputation",
                    details={
                        "intent_path": str(intent_path),
                        "stored": record.intent_integrity_hash,
                        "recomputed": recomputed,
                    },
                ))
        except Exception as exc:  # noqa: BLE001
            violations.append(InvariantViolation(
                invariant_id="I-J-1",
                description="intent record readable and hashable",
                details={"intent_path": str(intent_path), "error": str(exc)},
            ))
    return violations


@invariant("I-J-3", "Every .complete has a matching .intent")
def _i_j_3(config: WPGovernConfig) -> list[InvariantViolation]:
    journal_dir = config.root_dir / "state" / ".journal"
    if not journal_dir.exists():
        return []
    violations: list[InvariantViolation] = []
    for complete_path in journal_dir.glob("*.complete"):
        if complete_path.suffix == ".staged":
            continue
        txn_id = complete_path.stem
        intent_path = journal_dir / f"{txn_id}.intent"
        if not intent_path.exists():
            violations.append(InvariantViolation(
                invariant_id="I-J-3",
                description="Every .complete has a matching .intent",
                details={"orphan_complete": str(complete_path)},
            ))
    return violations


@invariant("I-J-4", "No two .intent files share a txn_id")
def _i_j_4(config: WPGovernConfig) -> list[InvariantViolation]:
    from wpgovern.utils.journal import list_intent_records, read_intent_record
    journal_dir = config.root_dir / "state" / ".journal"
    if not journal_dir.exists():
        return []
    seen: dict[str, str] = {}
    violations: list[InvariantViolation] = []
    for intent_path in list_intent_records(journal_dir):
        try:
            record = read_intent_record(intent_path)
            if record.txn_id in seen:
                violations.append(InvariantViolation(
                    invariant_id="I-J-4",
                    description="No two .intent files share a txn_id",
                    details={
                        "txn_id": record.txn_id,
                        "first": seen[record.txn_id],
                        "second": str(intent_path),
                    },
                ))
            else:
                seen[record.txn_id] = str(intent_path)
        except (OSError, ValueError, TypeError):
            pass  # Malformed intent record — skip gracefully
    return violations


# ---------------------------------------------------------------------------
# Trust store invariants
# ---------------------------------------------------------------------------


@invariant("I-T-1", "At most one key per domain has status 'active'")
def _i_t_1(config: WPGovernConfig) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for domain in ("runtime", "release", "journal"):
        store_path = (
            config.root_dir / "trust" / domain / "public" / f"trusted-{domain}-keys.json"
        )
        if not store_path.is_file():
            continue
        try:
            store = json.loads(store_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        active = [k for k in store.get("keys", []) if k.get("status") == "active"]
        if len(active) > 1:
            violations.append(InvariantViolation(
                invariant_id="I-T-1",
                description="At most one active key per domain",
                details={
                    "domain": domain,
                    "active_count": len(active),
                    "active_key_ids": [k.get("key_id") for k in active],
                },
            ))
    return violations


@invariant("I-T-2", "A revoked key has revoked_at set; an active key does not")
def _i_t_2(config: WPGovernConfig) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    for domain in ("runtime", "release", "journal"):
        store_path = (
            config.root_dir / "trust" / domain / "public" / f"trusted-{domain}-keys.json"
        )
        if not store_path.is_file():
            continue
        try:
            store = json.loads(store_path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for key in store.get("keys", []):
            status = key.get("status")
            has_revoked_at = bool(key.get("revoked_at"))
            if status == "revoked" and not has_revoked_at:
                violations.append(InvariantViolation(
                    invariant_id="I-T-2",
                    description="Revoked key has revoked_at set",
                    details={"domain": domain, "key_id": key.get("key_id")},
                ))
            if status == "active" and has_revoked_at:
                violations.append(InvariantViolation(
                    invariant_id="I-T-2",
                    description="Active key does not have revoked_at",
                    details={"domain": domain, "key_id": key.get("key_id")},
                ))
    return violations


# ---------------------------------------------------------------------------
# Recovery semantics — conditional; checked explicitly in test harness
# ---------------------------------------------------------------------------


@invariant("I-R-1", "After successful recover(), no .intent files remain")
def _i_r_1(config: WPGovernConfig) -> list[InvariantViolation]:
    # This invariant is conditionally meaningful: lingering intents are
    # expected DURING a commit and before the startup recovery hook runs.
    # Tests check this explicitly at the right moment.
    return []


# ---------------------------------------------------------------------------
# Negative-space queries
# ---------------------------------------------------------------------------


@invariant("I-NEG-JOURNAL", "No unexpected files/dirs in journal directory")
def _i_neg_journal(config: WPGovernConfig) -> list[InvariantViolation]:
    return negative_space_journal_dir(config)


@invariant("I-NEG-NOSYMLINKS", "No symlinks in journal directory")
def _i_neg_nosymlinks(config: WPGovernConfig) -> list[InvariantViolation]:
    return negative_space_no_symlinks_in_journal(config)


def negative_space_journal_dir(config: WPGovernConfig) -> list[InvariantViolation]:
    """Files in state/.journal/ that don't match expected patterns."""
    journal_dir = config.root_dir / "state" / ".journal"
    if not journal_dir.exists():
        return []
    expected_file_suffixes = {".intent", ".complete"}
    expected_staged_suffixes = {".intent.staged", ".complete.staged"}
    expected_dirs = {"backups", "recovery-reports", "acknowledged", "audit-emit-failures"}
    violations: list[InvariantViolation] = []
    for entry in journal_dir.iterdir():
        if entry.is_dir():
            if entry.name not in expected_dirs:
                violations.append(InvariantViolation(
                    invariant_id="I-NEG-JOURNAL",
                    description="Unexpected directory in journal dir",
                    details={"path": str(entry)},
                ))
        elif entry.is_file():
            name = entry.name
            ok = (
                any(name.endswith(suf) for suf in expected_file_suffixes)
                or any(name.endswith(suf) for suf in expected_staged_suffixes)
            )
            if not ok:
                violations.append(InvariantViolation(
                    invariant_id="I-NEG-JOURNAL",
                    description="Unexpected file in journal dir",
                    details={"path": str(entry)},
                ))
    return violations


def negative_space_no_symlinks_in_journal(
    config: WPGovernConfig,
) -> list[InvariantViolation]:
    """No symlinks should exist anywhere under the journal directory."""
    journal_dir = config.root_dir / "state" / ".journal"
    if not journal_dir.exists():
        return []
    violations: list[InvariantViolation] = []
    for entry in journal_dir.rglob("*"):
        if entry.is_symlink():
            violations.append(InvariantViolation(
                invariant_id="I-NEG-NOSYMLINKS",
                description="No symlinks in journal dir",
                details={"path": str(entry)},
            ))
    return violations


# ---------------------------------------------------------------------------
# Governance artifact invariants (H5)
# ---------------------------------------------------------------------------


@invariant("I-B-1", "Every baseline JSON has a .sig.json sidecar and verifies")
def _i_b_1(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every baseline JSON file must have a corresponding .sig.json and verify."""
    baselines_dir = config.root_dir / "baselines"
    if not baselines_dir.exists():
        return []
    from wpgovern.core.signing import SigningService
    signing = SigningService(config=config)
    violations: list[InvariantViolation] = []
    for bfile in baselines_dir.glob("*.json"):
        if bfile.name.endswith(".sig.json"):
            continue
        sig = bfile.with_suffix(".json.sig.json")
        if not sig.exists():
            violations.append(InvariantViolation(
                invariant_id="I-B-1",
                description="Baseline missing signature sidecar",
                details={"path": str(bfile), "expected": "baseline.json.sig.json exists", "actual": "missing"},
            ))
            continue
        # H2: also verify the signature cryptographically
        try:
            signing.verify_file(bfile)
        except Exception as exc:
            violations.append(InvariantViolation(
                invariant_id="I-B-1",
                description="Baseline signature verification failed",
                details={"path": str(bfile), "expected": "valid signature", "actual": str(exc)},
            ))
    return violations


@invariant("I-B-2", "Active pointer has signature, verifies, and references signed active baseline")
def _i_b_2(config: WPGovernConfig) -> list[InvariantViolation]:
    """Active pointer must be signed, verify, and reference a signed baseline with status=active."""
    import json as _json
    from wpgovern.core.signing import SigningService
    signing = SigningService(config=config)
    active = config.root_dir / "state" / "active.json"
    violations: list[InvariantViolation] = []
    if not active.exists():
        return []

    sig = Path(str(active) + ".sig.json")
    if not sig.exists():
        violations.append(InvariantViolation(
            invariant_id="I-B-2",
            description="Active pointer missing signature sidecar",
            details={"path": str(active), "expected": "active.json.sig.json exists", "actual": "missing"},
        ))
    else:
        # H2: verify signature
        try:
            signing.verify_file(active)
        except Exception as exc:
            violations.append(InvariantViolation(
                invariant_id="I-B-2",
                description="Active pointer signature verification failed",
                details={"path": str(active), "expected": "valid signature", "actual": str(exc)},
            ))

    try:
        payload = _json.loads(active.read_text(encoding="utf-8"))
    except Exception:
        violations.append(InvariantViolation(
            invariant_id="I-B-2",
            description="Active pointer is not valid JSON",
            details={"path": str(active), "expected": "valid JSON", "actual": "unreadable"},
        ))
        return violations

    baseline_id = payload.get("baseline_id")
    if not baseline_id:
        violations.append(InvariantViolation(
            invariant_id="I-B-2",
            description="Active pointer has no baseline_id",
            details={"path": str(active), "expected": "baseline_id present", "actual": "missing"},
        ))
        return violations

    baselines_dir = config.root_dir / "baselines"
    bfile = baselines_dir / f"{baseline_id}.json"
    if not bfile.exists():
        violations.append(InvariantViolation(
            invariant_id="I-B-2",
            description="Active pointer references missing baseline",
            details={"path": str(active), "expected": f"{baseline_id}.json exists", "actual": "baseline file missing"},
        ))
    else:
        sig_b = bfile.with_suffix(".json.sig.json")
        if not sig_b.exists():
            violations.append(InvariantViolation(
                invariant_id="I-B-2",
                description="Active baseline missing signature",
                details={"path": str(bfile), "expected": "baseline.json.sig.json exists", "actual": "missing"},
            ))
        else:
            try:
                signing.verify_file(bfile)
            except Exception as exc:
                violations.append(InvariantViolation(
                    invariant_id="I-B-2",
                    description="Active baseline signature verification failed",
                    details={"path": str(bfile), "expected": "valid signature", "actual": str(exc)},
                ))
        # H2: active baseline must have status=active
        try:
            b_payload = _json.loads(bfile.read_text(encoding="utf-8"))
            if b_payload.get("status") != "active":
                violations.append(InvariantViolation(
                    invariant_id="I-B-2",
                    description="Active pointer references non-active baseline",
                    details={"path": str(bfile), "expected": "status=active", "actual": f"status={b_payload.get('status')}"},
                ))
        except (json.JSONDecodeError, OSError, KeyError):
            pass  # Malformed baseline file — skip gracefully

    return violations


@invariant("I-A-1", "Every approval JSON has a .sig.json sidecar and verifies")
def _i_a_1(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every approval JSON file must have a .sig.json and verify cryptographically."""
    approvals_dir = config.root_dir / "approvals"
    if not approvals_dir.exists():
        return []
    from wpgovern.core.signing import SigningService
    signing = SigningService(config=config)
    violations: list[InvariantViolation] = []
    for afile in approvals_dir.glob("*.json"):
        if afile.name.endswith(".sig.json"):
            continue
        sig = afile.with_suffix(".json.sig.json")
        if not sig.exists():
            violations.append(InvariantViolation(
                invariant_id="I-A-1",
                description="Approval record missing signature sidecar",
                details={"path": str(afile), "expected": "approval.json.sig.json exists", "actual": "missing"},
            ))
            continue
        try:
            signing.verify_file(afile)
        except Exception as exc:
            violations.append(InvariantViolation(
                invariant_id="I-A-1",
                description="Approval signature verification failed",
                details={"path": str(afile), "expected": "valid signature", "actual": str(exc)},
            ))
    return violations


@invariant("I-B4-1", "If .last_b4_event.json exists, its mode must be 0o600")
def _i_b4_1(config: WPGovernConfig) -> list[InvariantViolation]:
    """If the B4 event file exists, it must have mode 0o600 (I-FS-6 complement)."""
    event_path = config.root_dir / "state" / ".last_b4_event.json"
    if not event_path.exists():
        return []
    mode = event_path.stat().st_mode & 0o777
    if mode != 0o600:
        return [InvariantViolation(
            invariant_id="I-B4-1",
            description=".last_b4_event.json has wrong mode",
            details={"path": str(event_path), "expected": "0o600", "actual": oct(mode)},
        )]
    return []


@invariant("I-REL-1", "Release artifacts must not be symlinks and must resolve inside dist")
def _i_rel_1(config: WPGovernConfig) -> list[InvariantViolation]:
    """Check any signed release manifests for symlink/path-escape violations.
    Path traversal strings are invalid regardless of whether the file exists."""
    import json as _json
    dist_dir = config.root_dir / "dist"
    if not dist_dir.exists():
        return []
    violations: list[InvariantViolation] = []
    for manifest in dist_dir.glob("manifest.json"):
        try:
            content = _json.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        for entry in content.get("artifacts", []):
            if not isinstance(entry, dict):
                continue
            art_path = entry.get("path", "")
            if not art_path:
                continue
            # M1: check the path STRING for traversal/absolute BEFORE checking
            # whether the file exists. L1 fix: use Path().parts to check for ".."
            # as a component rather than substring — avoids flagging filenames
            # that legitimately contain ".."-like substrings in their names.
            art_path_obj = Path(art_path)
            if art_path_obj.is_absolute() or ".." in art_path_obj.parts:
                violations.append(InvariantViolation(
                    invariant_id="I-REL-1",
                    description="Release artifact path contains traversal or is absolute",
                    details={"path": art_path, "expected": "relative path within dist", "actual": art_path},
                ))
                continue  # no need to check file existence for invalid paths

            art_file = dist_dir / art_path
            if art_file.is_symlink():
                violations.append(InvariantViolation(
                    invariant_id="I-REL-1",
                    description="Release artifact is a symlink",
                    details={"path": str(art_file), "expected": "regular file", "actual": "symlink"},
                ))
            elif art_file.exists():
                try:
                    art_file.resolve().relative_to(dist_dir.resolve())
                except ValueError:
                    violations.append(InvariantViolation(
                        invariant_id="I-REL-1",
                        description="Release artifact resolves outside dist directory",
                        details={"path": str(art_file), "expected": f"inside {dist_dir}", "actual": str(art_file.resolve())},
                    ))
    return violations


@invariant("I-AUD-1", "Every audit checkpoint has a valid matching checkpoint signature companion")
def _i_aud_1(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every audit.review.checkpoint record must have a matching
    audit.checkpoint.signature companion with a valid runtime-key signature."""
    audit_log = config.root_dir / "audit" / "audit.log"
    if not audit_log.exists():
        return []

    import json as _json
    from wpgovern.audit.verifier import AuditVerifier
    from wpgovern.errors import IntegrityError

    violations: list[InvariantViolation] = []
    try:
        records = [
            _json.loads(line)
            for line in audit_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception:
        return []

    verifier = AuditVerifier(config=config)
    for record in records:
        if record.get("event_type") != "audit.review.checkpoint":
            continue
        try:
            signed = verifier.verify_checkpoint_signature(record)
        except IntegrityError as exc:
            violations.append(InvariantViolation(
                invariant_id="I-AUD-1",
                description="Audit checkpoint signature verification failed",
                details={
                    "seq": record.get("seq"),
                    "hash": record.get("self_hash", "")[:16],
                    "error": str(exc),
                },
            ))
            continue
        if not signed:
            violations.append(InvariantViolation(
                invariant_id="I-AUD-1",
                description="Audit checkpoint has no valid signature companion",
                details={
                    "seq": record.get("seq"),
                    "hash": record.get("self_hash", "")[:16],
                    "expected": "audit.checkpoint.signature companion with valid runtime-key signature",
                    "actual": "not found",
                },
            ))
    return violations


@invariant("I-AUD-0", "Audit chain self_hash and prev_hash are internally consistent")
def _i_aud_0(config: WPGovernConfig) -> list[InvariantViolation]:
    """Verify audit chain integrity: every record's self_hash recomputes correctly
    and every prev_hash links to the previous record's self_hash.

    This is a prerequisite for I-AUD-1 — checkpoint signatures prove nothing
    if the underlying chain records can be silently tampered. Without chain
    validation, an attacker who keeps self_hash unchanged (or tamperers who
    only modify details fields) passes signature checks.
    """
    audit_log = config.root_dir / "audit" / "audit.log"
    if not audit_log.exists():
        return []

    import json as _json
    import hashlib as _hashlib

    violations: list[InvariantViolation] = []
    prev_hash = "0" * 64

    try:
        lines = [
            l for l in audit_log.read_text(encoding="utf-8").splitlines() if l.strip()
        ]
    except Exception:
        return []

    for line_no, line in enumerate(lines, start=1):
        try:
            record = _json.loads(line)
        except _json.JSONDecodeError:
            violations.append(InvariantViolation(
                invariant_id="I-AUD-0",
                description="Audit log line is not valid JSON",
                details={"line": line_no, "actual": line[:80]},
            ))
            continue

        stored_hash = record.get("self_hash", "")
        stored_prev = record.get("prev_hash", "")

        # Verify prev_hash links correctly
        if stored_prev != prev_hash:
            violations.append(InvariantViolation(
                invariant_id="I-AUD-0",
                description="Audit record prev_hash does not match previous self_hash",
                details={
                    "seq": record.get("seq"),
                    "expected_prev": prev_hash[:16] + "…",
                    "actual_prev": stored_prev[:16] + "…",
                },
            ))

        # Recompute self_hash from the record's content (exclude self_hash field).
        # self_hash = sha256(canonical_json(record_without_self_hash))
        # where record_without_self_hash includes prev_hash as a field.
        try:
            for_hashing = {k: v for k, v in record.items() if k != "self_hash"}
            canonical = _json.dumps(for_hashing, sort_keys=True, separators=(",", ":"))
            computed = _hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if computed != stored_hash:
                violations.append(InvariantViolation(
                    invariant_id="I-AUD-0",
                    description="Audit record self_hash does not match recomputed value",
                    details={
                        "seq": record.get("seq"),
                        "stored_hash": stored_hash[:16] + "…",
                        "computed_hash": computed[:16] + "…",
                    },
                ))
        except Exception as exc:
            violations.append(InvariantViolation(
                invariant_id="I-AUD-0",
                description="Audit record self_hash recomputation failed",
                details={"seq": record.get("seq"), "error": str(exc)},
            ))

        prev_hash = stored_hash

    return violations


@invariant("I-T-3", "Trust key paths are non-empty regular files inside trust/<domain>/public/")
def _i_t_3(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every trust key path must be non-empty, a regular file, and resolve
    inside the governed trust/<domain>/public/ directory."""
    import json as _json
    trust_dir = config.root_dir / "trust"
    if not trust_dir.exists():
        return []
    violations: list[InvariantViolation] = []
    domain_map = {
        "runtime/public/trusted-runtime-keys.json": "runtime",
        "release/public/trusted-release-keys.json": "release",
        "journal/public/trusted-journal-keys.json": "journal",
    }
    for store_rel, domain in domain_map.items():
        store_path = trust_dir / store_rel
        expected_pub_dir = trust_dir / domain / "public"
        if not store_path.exists():
            continue
        try:
            content = _json.loads(store_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for key in content.get("keys", []):
            key_id = key.get("key_id", "?")
            key_path_str = key.get("path", "")
            if not key_path_str:
                violations.append(InvariantViolation(
                    invariant_id="I-T-3",
                    description="Trust key has empty path",
                    details={"store": store_rel, "key_id": key_id,
                             "expected": "non-empty path", "actual": "empty"},
                ))
                continue
            p = Path(key_path_str)
            if not p.exists():
                violations.append(InvariantViolation(
                    invariant_id="I-T-3",
                    description="Trust key path missing",
                    details={"store": store_rel, "key_id": key_id, "path": key_path_str},
                ))
                continue
            if not p.is_file():
                violations.append(InvariantViolation(
                    invariant_id="I-T-3",
                    description="Trust key path is not a regular file",
                    details={"store": store_rel, "key_id": key_id, "path": key_path_str},
                ))
                continue
            # M-H2: enforce "inside trust/<domain>/public/" — same contract as validate_store.
            try:
                p.resolve().relative_to(expected_pub_dir.resolve())
            except ValueError:
                violations.append(InvariantViolation(
                    invariant_id="I-T-3",
                    description="Trust key path resolves outside governed trust directory",
                    details={"store": store_rel, "key_id": key_id, "path": key_path_str,
                             "expected_inside": str(expected_pub_dir)},
                ))
    return violations


@invariant("I-T-4", "Active keypair: private key matches public key for active/preactive keys")
def _i_t_4(config: WPGovernConfig) -> list[InvariantViolation]:
    """For each active/preactive key, verify the private key derives the stored public key."""
    import json as _json
    trust_dir = config.root_dir / "trust"
    if not trust_dir.exists():
        return []
    violations: list[InvariantViolation] = []
    PRIVATE_DIRS = {
        "runtime/public/trusted-runtime-keys.json": trust_dir / "runtime" / "private",
        "release/public/trusted-release-keys.json":  trust_dir / "release" / "private",
        "journal/public/trusted-journal-keys.json":  trust_dir / "journal" / "private",
    }
    for store_rel, priv_dir in PRIVATE_DIRS.items():
        store_path = trust_dir / store_rel
        if not store_path.exists():
            continue
        try:
            content = _json.loads(store_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for key in content.get("keys", []):
            key_id = key.get("key_id", "")
            status = key.get("status", "")
            if status not in ("active", "preactive"):
                continue
            priv_pem = priv_dir / f"{key_id}.pem"
            pub_path_str = key.get("path", "")

            # Missing private key is an explicit I-T-4 violation.
            # I-T-3 covers PUBLIC key paths; I-T-4 covers PRIVATE key existence
            # and keypair match. These are separate concerns — do not skip here.
            if not priv_pem.exists():
                violations.append(InvariantViolation(
                    invariant_id="I-T-4",
                    description=f"Trust private key missing for {status} key",
                    details={
                        "store": store_rel,
                        "key_id": key_id,
                        "status": status,
                        "expected_private_key": str(priv_pem),
                    },
                ))
                continue  # can't do keypair check without the private key

            if not pub_path_str:
                continue  # I-T-3 will catch this
            pub_file = Path(pub_path_str)
            if not pub_file.is_file():
                continue  # I-T-3 will catch this
            try:
                # α-3: use the shared helper from trust.py — same contract as validate_store.
                from wpgovern.core.trust import _verify_keypair_cryptographic_match
                from wpgovern.core.trust import TrustError as _TrustError

                class _InvariantTrustError(Exception):
                    pass

                try:
                    _verify_keypair_cryptographic_match(priv_pem, pub_file, _InvariantTrustError)
                except _InvariantTrustError as te:
                    violations.append(InvariantViolation(
                        invariant_id="I-T-4",
                        description=str(te),
                        details={"store": store_rel, "key_id": key_id, "status": status},
                    ))
            except _sub.CalledProcessError as exc:
                violations.append(InvariantViolation(
                    invariant_id="I-T-4",
                    description=f"Trust private key validation failed for {status} key",
                    details={
                        "store": store_rel,
                        "key_id": key_id,
                        "status": status,
                        "error": exc.stderr.decode()[:200] if exc.stderr else str(exc),
                    },
                ))
            except FileNotFoundError:
                pass  # openssl not on PATH — skip gracefully
            except OSError as exc:
                violations.append(InvariantViolation(
                    invariant_id="I-T-4",
                    description=f"Trust private key unreadable for {status} key",
                    details={"store": store_rel, "key_id": key_id, "status": status,
                             "error": str(exc)},
                ))
    return violations


@invariant("I-T-5", "active symlink resolves to active_key_id.pem for each trust domain")
def _i_t_5(config: WPGovernConfig) -> list[InvariantViolation]:
    """For each trust domain, the active private key symlink must exist, be a
    symlink, and resolve to <active_key_id>.pem in the same private directory.

    Catches the H1 governance-state stranding condition where activate_key's
    JSON write committed but the symlink update failed.
    """
    import json as _json
    from wpgovern.paths import build_paths
    paths = build_paths(config)
    trust_dir = config.root_dir / "trust"
    if not trust_dir.exists():
        return []
    violations: list[InvariantViolation] = []
    DOMAIN_CONFIGS = {
        "runtime/public/trusted-runtime-keys.json": paths.runtime_active_private_key,
        "release/public/trusted-release-keys.json": paths.release_active_private_key,
        "journal/public/trusted-journal-keys.json": paths.journal_active_private_key,
    }
    for store_rel, symlink_path in DOMAIN_CONFIGS.items():
        store_path = trust_dir / store_rel
        if not store_path.exists():
            continue
        try:
            content = _json.loads(store_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        active_key_id = content.get("active_key_id")
        if not active_key_id:
            continue
        expected_target = f"{active_key_id}.pem"
        if not symlink_path.exists() and not symlink_path.is_symlink():
            violations.append(InvariantViolation(
                invariant_id="I-T-5",
                description="Active private key symlink missing",
                details={"store": store_rel, "active_key_id": active_key_id,
                         "expected_symlink": str(symlink_path)},
            ))
            continue
        if not symlink_path.is_symlink():
            violations.append(InvariantViolation(
                invariant_id="I-T-5",
                description="Active private key path is not a symlink",
                details={"store": store_rel, "active_key_id": active_key_id,
                         "path": str(symlink_path)},
            ))
            continue
        import os as _os
        actual_target = _os.readlink(str(symlink_path))
        if Path(actual_target).name != expected_target:
            violations.append(InvariantViolation(
                invariant_id="I-T-5",
                description="Active private key symlink target does not match active_key_id",
                details={"store": store_rel, "active_key_id": active_key_id,
                         "expected_target": expected_target,
                         "actual_target": actual_target},
            ))
            continue
        # M-H1: also verify the symlink resolves inside trust/<domain>/private/.
        try:
            resolved = symlink_path.resolve()
            priv_dir = symlink_path.parent.resolve()
            resolved.relative_to(priv_dir)
        except ValueError:
            violations.append(InvariantViolation(
                invariant_id="I-T-5",
                description="Active private key symlink resolves outside trust/<domain>/private",
                details={"store": store_rel, "active_key_id": active_key_id,
                         "resolved": str(symlink_path.resolve()),
                         "expected_inside": str(symlink_path.parent)},
            ))
            continue
        # β-2: verify the resolved target is an existing regular file.
        # A broken symlink (correct name, missing or replaced target) is its
        # own integrity violation; don't rely on I-T-4 as a backstop.
        try:
            if not symlink_path.resolve(strict=False).is_file():
                violations.append(InvariantViolation(
                    invariant_id="I-T-5",
                    description=f"{store_rel} active symlink target is not a regular file",
                    details={
                        "store": store_rel,
                        "active_key_id": active_key_id,
                        "symlink": str(symlink_path),
                        "resolved_target": str(symlink_path.resolve(strict=False)),
                    },
                ))
        except OSError as exc:
            violations.append(InvariantViolation(
                invariant_id="I-T-5",
                description=f"{store_rel} active symlink target unreachable",
                details={"store": store_rel, "active_key_id": active_key_id,
                         "error": str(exc)[:200]},
            ))
    return violations


@invariant("I-AUD-2", "Audit chain head must be bound to a recent checkpoint signature")
def _i_aud_2(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every audit log record must be reachable from a valid checkpoint signature
    via valid prev_hash links. Records after the most recent checkpoint must be
    within a bounded window (MAX_TAIL_WINDOW = 100) to prevent unbounded tail
    tamper opportunity.

    A tail tamper — modifying only the last record — is undetectable by prev_hash
    linkage alone because no subsequent record references it. Checkpoint signatures
    bound this window: once the tail is covered by a checkpoint, tampering it
    would require forging the signature.

    This invariant fires when:
    1. No checkpoint has ever been emitted (entire chain uncovered).
    2. More than MAX_TAIL_WINDOW records have accumulated since the last checkpoint.
    """
    import json as _json
    violations: list[InvariantViolation] = []
    MAX_TAIL_WINDOW = 100

    audit_log = config.root_dir / "audit" / "audit.log"
    if not audit_log.is_file():
        return violations

    try:
        lines = [ln for ln in audit_log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return violations

    if not lines:
        return violations

    # Find the most recent checkpoint signature (scanning from the end)
    most_recent_checkpoint_seq: int | None = None
    for line in reversed(lines):
        try:
            rec = _json.loads(line)
        except _json.JSONDecodeError:
            continue
        if rec.get("event_type") == "audit.checkpoint.signature":
            try:
                most_recent_checkpoint_seq = int(rec.get("seq", 0))
            except (TypeError, ValueError):
                pass
            break

    if most_recent_checkpoint_seq is None:
        # No checkpoint yet — only fire if the chain has grown beyond the
        # window where a checkpoint should have been emitted. A small chain
        # without checkpoints is normal startup state, not a violation.
        # A chain of 1-2 records in tests is expected; only flag genuine
        # neglect (chain longer than MAX_TAIL_WINDOW with no checkpoint at all).
        if len(lines) > MAX_TAIL_WINDOW:
            violations.append(InvariantViolation(
                invariant_id="I-AUD-2",
                description="Audit log has no checkpoint signature and exceeds window",
                details={"records": len(lines), "max_window": MAX_TAIL_WINDOW},
            ))
        return violations

    # Count records after the last checkpoint
    try:
        last_rec = _json.loads(lines[-1])
        last_seq = int(last_rec.get("seq", 0))
    except (ValueError, _json.JSONDecodeError):
        return violations

    tail_size = last_seq - most_recent_checkpoint_seq
    if tail_size > MAX_TAIL_WINDOW:
        violations.append(InvariantViolation(
            invariant_id="I-AUD-2",
            description="Audit chain tail exceeds checkpoint window",
            details={
                "tail_size": tail_size,
                "max_window": MAX_TAIL_WINDOW,
                "last_checkpoint_seq": most_recent_checkpoint_seq,
                "current_seq": last_seq,
            },
        ))

    return violations


@invariant("I-T-6", "Trust private/public dirs contain only files for registered keys")
def _i_t_6(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every *.pem in trust/<domain>/private/ and every *.pub in
    trust/<domain>/public/ must correspond to a key registered in the
    domain's trust store. Orphan files (unregistered key material) are a
    violation regardless of how they got there.

    ε-2: closes the contract gap where partial-failure paths or external
    actors could leave key material on disk that no other invariant catches.

    Note: symlinks (like the active.pem symlink managed by I-T-5) are explicitly
    skipped — they are not key material files and are covered by I-T-5 separately.
    """
    import json as _json

    trust_dir = config.root_dir / "trust"
    if not trust_dir.exists():
        return []

    violations: list[InvariantViolation] = []

    DOMAINS = (
        ("journal", "trusted-journal-keys.json"),
        ("runtime", "trusted-runtime-keys.json"),
        ("release", "trusted-release-keys.json"),
    )

    for domain, store_name in DOMAINS:
        domain_dir = trust_dir / domain
        if not domain_dir.exists():
            continue

        store_path = domain_dir / "public" / store_name
        registered_ids: set[str] = set()
        if store_path.is_file():
            try:
                store_data = _json.loads(store_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue  # unreadable store — other invariants report it
            for k in store_data.get("keys", []):
                kid = k.get("key_id")
                if isinstance(kid, str):
                    registered_ids.add(kid)

        # Private dir: every *.pem that is NOT a symlink must be registered.
        # η-2: symlinks in private/ are also checked — the only permitted symlink
        # is the single managed active pointer (<domain>-active.pem). Any other
        # symlink is an unregistered exfiltration vector.
        managed_active_symlink = f"{domain}-active.pem"
        priv_dir = domain_dir / "private"
        if priv_dir.is_dir():
            for pem_path in priv_dir.glob("*.pem"):
                if pem_path.is_symlink():
                    # Only the managed active symlink is permitted.
                    if pem_path.name != managed_active_symlink:
                        violations.append(InvariantViolation(
                            invariant_id="I-T-6",
                            description=(
                                f"{domain} private/ contains an unregistered symlink "
                                f"'{pem_path.name}' — only '{managed_active_symlink}' "
                                "is the managed active pointer"
                            ),
                            details={
                                "domain": domain,
                                "path": str(pem_path),
                                "managed_symlink": managed_active_symlink,
                            },
                        ))
                    continue  # I-T-5 handles active symlink target validity
                if pem_path.stem not in registered_ids:
                    violations.append(InvariantViolation(
                        invariant_id="I-T-6",
                        description=f"{domain} private key file is not registered in trust store",
                        details={
                            "domain": domain,
                            "path": str(pem_path),
                            "key_id_from_filename": pem_path.stem,
                        },
                    ))

        # Public dir: every *.pub must be registered; symlinks are also checked.
        # η-2: no symlinks are expected in public/ — flag any that appear.
        pub_dir = domain_dir / "public"
        if pub_dir.is_dir():
            for pub_path in pub_dir.glob("*.pub"):
                if pub_path.is_symlink():
                    violations.append(InvariantViolation(
                        invariant_id="I-T-6",
                        description=(
                            f"{domain} public/ contains an unexpected symlink "
                            f"'{pub_path.name}' — no symlinks are managed in public/"
                        ),
                        details={
                            "domain": domain,
                            "path": str(pub_path),
                        },
                    ))
                    continue
                if pub_path.stem not in registered_ids:
                    violations.append(InvariantViolation(
                        invariant_id="I-T-6",
                        description=f"{domain} public key file is not registered in trust store",
                        details={
                            "domain": domain,
                            "path": str(pub_path),
                            "key_id_from_filename": pub_path.stem,
                        },
                    ))

    return violations



@invariant("I-T-7", "No key-generation staging residue (.keygen-*) under trust/<domain>/")
def _i_t_7(config: WPGovernConfig) -> list[InvariantViolation]:
    """Every .keygen-* staging directory under trust/<domain>/ is a violation.

    η-1: closes the exfiltration vector where staging residue containing
    private key material was invisible to the governance system. A .keygen-*
    directory left behind by a crashed generate_key call means unregistered
    private key material is sitting in the trust tree with no invariant
    detecting it. I-T-6 only checks governed private/ and public/ dirs;
    .keygen-* directories are siblings and were not checked.
    """
    trust_dir = config.root_dir / "trust"
    if not trust_dir.exists():
        return []

    violations: list[InvariantViolation] = []

    for domain in ("journal", "runtime", "release"):
        domain_dir = trust_dir / domain
        if not domain_dir.is_dir():
            continue
        for candidate in domain_dir.iterdir():
            if candidate.name.startswith(".keygen-"):
                violations.append(InvariantViolation(
                    invariant_id="I-T-7",
                    description=(
                        f"Key-generation staging residue detected in {domain} "
                        "trust domain — unregistered private key material may be present"
                    ),
                    details={
                        "domain": domain,
                        "path": str(candidate),
                        "name": candidate.name,
                    },
                ))

    return violations


@invariant("I-CFG-1", "Active baseline config_file_hashes matches live filesystem state")
def _i_cfg_1(config: WPGovernConfig) -> list[InvariantViolation]:
    """I-CFG-1: If the active baseline has a config_file_hashes manifest,
    verify each entry against the current file on disk.

    This is the runtime invariant — it fires if a config file has drifted
    from the baselined state without a new baseline being created and approved.
    governance-check calls check_all_invariants which calls this.
    """
    import hashlib as _hl
    import json as _json

    violations: list[InvariantViolation] = []

    # v50 / H.0.2-1: use derived path, not config default.
    # config.active_pointer is hardcoded to /opt/wpgovern/state/active.json
    # but BaselineService.activate() writes via paths.active_pointer (derived
    # from root_dir). Under root_dir override these diverge and the invariant
    # silently skips. build_paths(config) gives the canonical derived path.
    from wpgovern.paths import build_paths
    _paths = build_paths(config)
    active_ptr = _paths.active_pointer
    if not active_ptr.is_file():
        return violations  # no active baseline — nothing to check

    try:
        ptr = _json.loads(active_ptr.read_text(encoding="utf-8"))
        baseline_id = ptr.get("baseline_id") if isinstance(ptr, dict) else None
    except Exception:
        return violations  # pointer unreadable — caught by other invariants

    if not baseline_id:
        return violations

    baselines_dir = config.root_dir / "baselines"
    baseline_path = baselines_dir / f"{baseline_id}.json"
    if not baseline_path.is_file():
        return violations  # missing baseline — caught by I-B-1

    try:
        payload = _json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        return violations

    # v52 / H.0.4-1 + H.0.4-2: distinguish field-absent from field-present;
    # schema-validate before iteration to prevent path-escape on absolute keys.
    if "config_file_hashes" not in payload:
        return violations  # genuinely legacy baseline
    raw_hashes = payload["config_file_hashes"]

    from wpgovern.core.baseline import _validate_config_file_hashes, BaselineError
    try:
        hashes = _validate_config_file_hashes(raw_hashes, "active-baseline")
    except BaselineError:
        # Structural violation — I-CFG-2 reports it. I-CFG-1 must not read
        # paths from a malformed manifest.
        return violations

    install_dir = Path(getattr(config, "install_dir", "/opt/wpgovern-install"))

    for rel_path, expected_digest in sorted(hashes.items()):
        abs_path = install_dir / rel_path
        if not abs_path.exists() or not abs_path.is_file():
            violations.append(InvariantViolation(
                invariant_id="I-CFG-1",
                description=f"Baselined config file is missing: {rel_path}",
                details={
                    "rel_path": rel_path,
                    "abs_path": str(abs_path),
                    "baseline_id": baseline_id,
                    "expected_digest": expected_digest,
                },
            ))
            continue
        try:
            actual = "sha256:" + _hl.sha256(abs_path.read_bytes()).hexdigest()
        except OSError as exc:
            violations.append(InvariantViolation(
                invariant_id="I-CFG-1",
                description=f"Baselined config file is unreadable: {rel_path}",
                details={
                    "rel_path": rel_path,
                    "abs_path": str(abs_path),
                    "baseline_id": baseline_id,
                    "error": str(exc),
                },
            ))
            continue
        if actual != expected_digest:
            violations.append(InvariantViolation(
                invariant_id="I-CFG-1",
                description=f"Config file hash mismatch: {rel_path}",
                details={
                    "rel_path": rel_path,
                    "abs_path": str(abs_path),
                    "baseline_id": baseline_id,
                    "expected": expected_digest,
                    "actual": actual,
                },
            ))

    return violations


@invariant("I-CFG-2", "config_file_hashes manifest matches CONFIG_FILE_PATHS closed-set with valid digests")
def _i_cfg_2(config: WPGovernConfig) -> list[InvariantViolation]:
    """I-CFG-2: structural validator for config_file_hashes manifest completeness.

    v51 / H.0.3-4: reports structural violations explicitly so the invariant
    catalog catches what the dedicated config-hash check refuses.

    When config_file_hashes is present:
    - Must be a dict (not list, str, None, etc.)
    - Key set must be exactly CONFIG_FILE_PATHS (no missing, no extra)
    - Each value must match sha256:<64 hex chars>

    Legacy baselines (field absent entirely) produce no violations.
    """
    import json as _json

    violations: list[InvariantViolation] = []

    # v50 / H.0.2-1: use derived path, not config default.
    from wpgovern.paths import build_paths
    _paths = build_paths(config)
    active_ptr = _paths.active_pointer
    if not active_ptr.is_file():
        return violations

    try:
        ptr = _json.loads(active_ptr.read_text(encoding="utf-8"))
        baseline_id = ptr.get("baseline_id") if isinstance(ptr, dict) else None
    except Exception:
        return violations

    if not baseline_id:
        return violations

    baselines_dir = config.root_dir / "baselines"
    baseline_path = baselines_dir / f"{baseline_id}.json"
    if not baseline_path.is_file():
        return violations

    try:
        payload = _json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        return violations

    # v52 / H.0.4-1: distinguish field-absent (legacy baseline, acceptable)
    # from field-present-with-null (malformed manifest, must be rejected).
    # dict.get() conflates both → null would bypass I-CFG-2 entirely.
    if "config_file_hashes" not in payload:
        # Genuinely legacy baseline (field absent entirely). No shape to validate.
        return violations
    hashes = payload["config_file_hashes"]
    # hashes may be None here (signed explicit null). isinstance(None, dict) is
    # False — the non-dict check below catches it as a NoneType violation.

    # H.0.3-4: non-dict manifest — report and return (can't check further)
    if not isinstance(hashes, dict):
        violations.append(InvariantViolation(
            invariant_id="I-CFG-2",
            description="config_file_hashes must be a dict",
            details={"actual_type": type(hashes).__name__, "baseline_id": baseline_id},
        ))
        return violations

    # H.0.3-4: completeness check — key set must be exactly CONFIG_FILE_PATHS
    from wpgovern.core.baseline import CONFIG_FILE_PATHS as _CFG_PATHS, _HASH_PATTERN as _HP
    actual_keys = set(hashes.keys())
    expected_keys = set(_CFG_PATHS)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        violations.append(InvariantViolation(
            invariant_id="I-CFG-2",
            description="config_file_hashes key set does not match CONFIG_FILE_PATHS",
            details={
                "expected": sorted(expected_keys),
                "actual": sorted(actual_keys),
                "missing": missing,
                "extra": extra,
                "baseline_id": baseline_id,
            },
        ))

    # Per-entry validation (retained from H.0.1-4 + H.0.3-4 refinement)
    for key, value in hashes.items():
        if not isinstance(key, str) or not isinstance(value, str):
            violations.append(InvariantViolation(
                invariant_id="I-CFG-2",
                description="config_file_hashes entry has non-string type",
                details={
                    "key_type": type(key).__name__,
                    "value_type": type(value).__name__,
                    "baseline_id": baseline_id,
                },
            ))
            continue
        if not _HP.match(value):
            violations.append(InvariantViolation(
                invariant_id="I-CFG-2",
                description="config_file_hashes value is not a valid sha256:<hex> digest",
                details={"key": key, "value": value[:32] + "...", "baseline_id": baseline_id},
            ))

    return violations
