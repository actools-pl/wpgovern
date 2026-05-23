"""
WPGovern baseline lifecycle service.

``BaselineService`` manages the four-stage baseline lifecycle:

    draft → submitted → approved → active

Each transition is guarded by advisory locks. The ``activate`` transition
commits four files atomically via ``AtomicTransaction`` with crash-recovery
journal integration:

  1. Baseline record     (status → active)
  2. Approval record     (status → consumed)
  3. Active pointer      (points to the new active baseline)
  4. Supersession record (audit trail of the previous baseline)

``BaselineRecord`` is a stdlib dataclass defined here.

WordPress state capture
-----------------------
``create_draft()`` invokes ``docker compose exec php wp`` to capture the
live WordPress plugin list, theme list, and core version. This command is
monkeypatched in tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
import pathlib
from typing import Any

from wpgovern.core.signing import SigningService
from wpgovern.errors import NotFoundError, PolicyError, ValidationError
from wpgovern.paths import Paths, build_paths
from wpgovern.policy.approval import ApprovalService
from wpgovern.utils.locking import LockManager
from wpgovern.utils.time import utc_now_iso


class BaselineError(PolicyError):
    """Raised for baseline lifecycle failures."""


# H.0-A: Config-file paths that are file-hash baselined.
# Paths are relative to config.install_dir (default: /opt/wpgovern-install/).
# Source: strategic deployment report v1.1, "What WPGovern governs" table.
CONFIG_FILE_PATHS = (
    "docker-compose.yml",
    "Caddyfile",
    "my.cnf",
    "wp-config.php",
)


@dataclass(slots=True)
class BaselineRecord:
    """A baseline record as loaded from or written to disk."""

    baseline_id: str
    created_at: str
    status: str
    wp_version: str
    plugins: list[dict[str, Any]]
    themes: list[dict[str, Any]]
    submitted_at: str | None = None
    approved_at: str | None = None
    activated_at: str | None = None
    config_file_hashes: dict[str, str] | None = None  # H.0-A: optional, None for legacy


class BaselineId(str):
    """Thin str subclass so baseline IDs carry a .baseline_id property
    for compatibility with call sites that use attribute access."""

    @property
    def baseline_id(self) -> str:
        return str(self)


class BaselineService:
    """Baseline lifecycle service.

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance.
        signing: ``SigningService`` instance.
        approvals: ``ApprovalService`` instance.
        lock_manager: ``LockManager`` instance.
    """

    def __init__(
        self,
        config: Any = None,
        paths: Paths | None = None,
        signing: SigningService | None = None,
        approvals: ApprovalService | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        self._config = config  # H.0-A: stored so _config_install_dir can read install_dir
        self.paths = paths or build_paths(config)
        self.signing = signing or SigningService(paths=self.paths)
        self.approvals = approvals or ApprovalService(
            paths=self.paths, signing=self.signing
        )
        self.lock_manager = lock_manager or LockManager(
            locks_dir=self.paths.locks_dir
        )

    def create_draft(
        self,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> "BaselineId":
        """Capture current WordPress runtime state as a signed draft baseline.

        Returns the baseline_id string (as a ``BaselineId`` instance).
        """
        self.paths.baselines_dir.mkdir(parents=True, exist_ok=True)
        baseline_id = _timestamped_id("baseline")
        # Collision guard: with UUID suffix collisions are negligible but
        # fail-closed is the discipline here.
        if (self.paths.baselines_dir / f"{baseline_id}.json").exists():
            import uuid
            baseline_id = f"{baseline_id}-{uuid.uuid4().hex[:4]}"
        plugins = self._wp_json_list(["plugin", "list", "--format=json"])
        themes = self._wp_json_list(["theme", "list", "--format=json"])
        wp_version = self._wp_text(
            ["core", "version", "--skip-plugins", "--skip-themes"]
        )

        # H.0-A: compute config-file hashes BEFORE entering AtomicTransaction.
        # If any file is missing, fail-closed here — before any state mutation.
        config_file_hashes = _compute_config_file_hashes(self._config_install_dir())

        record = BaselineRecord(
            baseline_id=baseline_id,
            created_at=utc_now_iso(),
            status="draft",
            wp_version=wp_version,
            plugins=plugins,
            themes=themes,
            config_file_hashes=config_file_hashes,
        )
        path = self.paths.baselines_dir / f"{baseline_id}.json"

        # F4: stage JSON and signature sidecar atomically via AtomicTransaction.
        # Pre-fix: _write_baseline then sign_runtime_artifact were two separate
        # steps — a crash between them left an unsigned draft that blocked all
        # future operations on that baseline (load refused, I-B-1 would flag it).
        from wpgovern.utils.transaction import AtomicTransaction
        staging_root = self.paths.root / "state" / ".transactions"
        staging_root.mkdir(parents=True, exist_ok=True)
        payload = {
            "baseline_id": baseline_id,
            "created_at": record.created_at,
            "status": record.status,
            "wp_version": record.wp_version,
            "plugins": record.plugins,
            "themes": record.themes,
        }
        if record.config_file_hashes is not None:
            payload["config_file_hashes"] = record.config_file_hashes
        with AtomicTransaction(staging_root, service_label=None) as txn:
            txn.stage_signed_json(path, payload, self.signing)
            txn.commit()

        if audit_logger is not None and actor_context is not None:
            audit_logger.emit(
                event_type="baseline.create",
                actor=str(actor_context.get("actor_id") or ""),
                outcome="success",
                details={**actor_context, "baseline_id": baseline_id},
            )
        return BaselineId(baseline_id)

    def load(self, baseline_id: str) -> BaselineRecord:
        """Load a baseline record, verifying its signature.

        Always verifies the signature sidecar. A missing sidecar is an
        integrity failure — create_draft() signs immediately, so a
        missing sidecar means either the file was never completed or
        the sidecar was deleted (a bypass vector).

        For diagnostic/forensic use, use ``load_unverified_for_diagnostics_only``.
        """
        _validate_baseline_id(baseline_id)
        path = self.paths.baselines_dir / f"{baseline_id}.json"
        if not path.exists():
            raise BaselineError(f"Baseline '{baseline_id}' not found")

        sig_path = pathlib.Path(str(path) + ".sig.json")
        if not sig_path.exists():
            raise BaselineError(
                f"Baseline '{baseline_id}' signature file missing. "
                "This indicates the record was not properly created or "
                "the signature was deleted. Refusing to load."
            )
        try:
            self.signing.verify_file(path)
        except Exception as exc:
            raise BaselineError(
                f"Baseline '{baseline_id}' signature verification failed: {exc}"
            ) from exc

        return self._parse_baseline(path)

    def load_unverified_for_diagnostics_only(
        self, baseline_id: str
    ) -> BaselineRecord:
        """Load a baseline WITHOUT signature verification.

        For forensic/diagnostic use only — e.g. inspecting a record
        whose signing key has been revoked. Must NOT be called by any
        state-transition path (submit, approve, activate).
        """
        _validate_baseline_id(baseline_id)
        path = self.paths.baselines_dir / f"{baseline_id}.json"
        if not path.exists():
            raise BaselineError(f"Baseline '{baseline_id}' not found")
        return self._parse_baseline(path)

    def _parse_baseline(self, path: pathlib.Path) -> BaselineRecord:
        """Parse a baseline JSON file into a BaselineRecord."""
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BaselineError(
                f"Baseline '{path.stem}' is not valid JSON: {exc}"
            ) from exc
        # v52 / H.0.4-1: distinguish field-absent (legacy) from field-present-null.
        # payload.get() conflates both — a signed baseline with explicit null
        # would be treated as a legacy baseline and skip validation.
        if "config_file_hashes" in payload:
            raw_hashes = _validate_config_file_hashes(
                payload["config_file_hashes"], path.stem
            )
        else:
            raw_hashes = None  # genuinely legacy baseline (field absent)
        return BaselineRecord(
            baseline_id=payload["baseline_id"],
            created_at=payload["created_at"],
            status=payload["status"],
            wp_version=payload["wp_version"],
            plugins=list(payload.get("plugins", [])),
            themes=list(payload.get("themes", [])),
            submitted_at=payload.get("submitted_at"),
            approved_at=payload.get("approved_at"),
            activated_at=payload.get("activated_at"),
            config_file_hashes=raw_hashes,
        )

    def submit(
        self,
        baseline_id: str,
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> BaselineRecord:
        """Transition a draft baseline to submitted status.

        Uses AtomicTransaction so a kill between JSON write and signature
        does not leave a stale/missing sidecar. Recovery replays the intent
        and produces a consistent result.
        """
        _validate_baseline_id(baseline_id)
        from wpgovern.utils.transaction import AtomicTransaction
        from wpgovern.core.trust import TrustService
        staging_root = self.paths.root / "state" / ".transactions"
        staging_root.mkdir(parents=True, exist_ok=True)
        trust_svc = TrustService(paths=self.paths)

        with self.lock_manager.acquire_many(["baselines"]):
            record = self.load(baseline_id)
            if record.status != "draft":
                raise BaselineError(
                    f"Baseline '{baseline_id}' has status '{record.status}' "
                    "and cannot be submitted"
                )
            record.status = "submitted"
            record.submitted_at = utc_now_iso()
            path = self.paths.baselines_dir / f"{baseline_id}.json"
            payload = self._baseline_payload(record)

            with AtomicTransaction(
                staging_root,
                service_label="BaselineService.submit",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=trust_svc,
            ) as txn:
                txn.stage_signed_json(path, payload, self.signing)
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type="baseline.submit",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**actor_context, "baseline_id": baseline_id},
                )
            return record

    def approve(
        self,
        baseline_id: str,
        approved_by: str = "python-control-plane",
        *,
        audit_logger: object | None = None,
        actor_context: dict | None = None,
    ) -> str:
        """Transition a submitted baseline to approved and write a bound approval.

        Returns the approval_id.
        """
        _validate_baseline_id(baseline_id)
        if not approved_by.strip():
            raise BaselineError("approved_by cannot be empty")

        approved_at = utc_now_iso()

        from wpgovern.utils.transaction import AtomicTransaction
        from wpgovern.core.trust import TrustService
        staging_root = self.paths.root / "state" / ".transactions"
        staging_root.mkdir(parents=True, exist_ok=True)
        trust_svc = TrustService(paths=self.paths)

        with self.lock_manager.acquire_many(["approvals", "baselines"]):
            record = self.load(baseline_id)
            if record.status != "submitted":
                raise BaselineError(
                    f"Baseline '{baseline_id}' has status '{record.status}' "
                    "and cannot be approved"
                )
            record.status = "approved"
            record.approved_at = approved_at
            baseline_path = self.paths.baselines_dir / f"{baseline_id}.json"

            approval_id = _timestamped_id("approval")
            approval_path = self.paths.approvals_dir / f"{approval_id}.json"
            approval_payload = {
                "approval_id": approval_id,
                "type": "baseline",
                "baseline_id": baseline_id,
                "approved_by": approved_by,
                "approved_at": approved_at,
                "status": "approved",
            }

            # Write baseline + signature + approval record + approval signature
            # as a single atomic transaction. A kill between any of these steps
            # previously left baseline marked approved without approval evidence.
            with AtomicTransaction(
                staging_root,
                service_label="BaselineService.approve",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=trust_svc,
            ) as txn:
                txn.stage_signed_json(baseline_path, self._baseline_payload(record), self.signing)
                txn.stage_signed_json(approval_path, approval_payload, self.signing)
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                audit_logger.emit(
                    event_type="baseline.approve",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={
                        **actor_context,
                        "baseline_id": baseline_id,
                        "approval_id": approval_id,
                    },
                )
            return approval_id

    def activate(
        self,
        baseline_id: str,
        approval_id: str,
        *,
        audit_logger: Any = None,
        actor_context: dict[str, Any] | None = None,
    ) -> BaselineRecord:
        """Activate an approved baseline.

        Commits four files atomically via ``AtomicTransaction`` with crash-
        recovery journal integration:

        1. Baseline record  (status → active)
        2. Approval record  (status → consumed)
        3. Active pointer   (baseline_id updated)
        4. Supersession record

        Reconciliation gate: raises ``BaselineError`` if a reconciliation
        requirement file exists.
        """
        _validate_baseline_id(baseline_id)
        if not approval_id.strip():
            raise BaselineError("approval_id cannot be empty")

        lock_names = ["governance", "approvals", "baselines", "active-state"]
        with self.lock_manager.acquire_many(lock_names):
            baseline_path = self.paths.baselines_dir / f"{baseline_id}.json"
            if not baseline_path.exists():
                raise BaselineError(f"Baseline '{baseline_id}' not found")

            approval_path_check = (
                self.paths.approvals_dir / f"{approval_id}.json"
            )
            if not approval_path_check.exists():
                raise BaselineError(f"Approval '{approval_id}' not found")

            approval_loaded = self.approvals.load(approval_id)
            if approval_loaded.get("type") != "baseline":
                raise BaselineError(
                    f"Approval '{approval_id}' is not a baseline approval"
                )
            if approval_loaded.get("baseline_id") != baseline_id:
                raise BaselineError(
                    f"Approval '{approval_id}' does not match baseline "
                    f"'{baseline_id}'"
                )

            if self.paths.reconciliation_required.exists():
                gate_value = (
                    self.paths.reconciliation_required.read_text(
                        encoding="utf-8"
                    ).strip()
                    or "unknown"
                )
                raise BaselineError(
                    f"Activation blocked: reconciliation required ({gate_value})"
                )

            self.signing.verify_runtime_artifact(baseline_path)
            self.signing.verify_runtime_artifact(approval_path_check)

            record = self.load(baseline_id)
            now = utc_now_iso()
            previous_json: str | None = None

            if self.paths.active_pointer.exists():
                self.signing.verify_active_pointer()
                try:
                    current_payload = json.loads(
                        self.paths.active_pointer.read_text(encoding="utf-8")
                    )
                except json.JSONDecodeError as exc:
                    raise BaselineError(
                        f"Active pointer is not valid JSON: {exc}"
                    ) from exc
                previous_json = current_payload.get("baseline_id")

            record.status = "active"
            record.activated_at = now
            baseline_payload = self._baseline_payload(record)

            approval_consume_path, approval_consumed_payload = (
                self.approvals.prepare_consume(approval_id, expected_type="baseline")
            )

            active_payload = {
                "baseline_id": baseline_id,
                "activated_at": now,
                "previous_baseline_id": previous_json,
            }

            self.paths.state_supersessions.mkdir(parents=True, exist_ok=True)
            supersession_id = _timestamped_id("supersession")
            supersession_path = (
                self.paths.state_supersessions / f"{supersession_id}.json"
            )
            supersession_payload = {
                "supersession_id": supersession_id,
                "superseded_baseline_id": previous_json,
                "replacement_baseline_id": baseline_id,
                "recorded_at": now,
            }

            from wpgovern.utils.transaction import AtomicTransaction

            staging_root = self.paths.root / "state" / ".transactions"
            staging_root.mkdir(parents=True, exist_ok=True)

            with AtomicTransaction(
                staging_root,
                service_label="BaselineService.activate",
                actor_id=(actor_context or {}).get("actor_id"),
                journal_root=self.paths.root,
                trust_service=self.signing.trust,
            ) as txn:
                txn.stage_signed_json(
                    baseline_path, baseline_payload, self.signing
                )
                txn.stage_signed_json(
                    approval_consume_path,
                    approval_consumed_payload,
                    self.signing,
                )
                txn.stage_signed_json(
                    self.paths.active_pointer, active_payload, self.signing
                )
                txn.stage_signed_json(
                    supersession_path, supersession_payload, self.signing
                )
                txn.commit()

            if audit_logger is not None and actor_context is not None:
                details = {
                    "baseline_id": baseline_id,
                    "approval_id": approval_id,
                    "from": previous_json,
                    "to": baseline_id,
                }
                audit_logger.emit(
                    event_type="baseline.activate",
                    actor=str(actor_context.get("actor_id") or ""),
                    outcome="success",
                    details={**details, **actor_context},
                )
            return record

    def _baseline_payload(self, record: BaselineRecord) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "baseline_id": record.baseline_id,
            "created_at": record.created_at,
            "status": record.status,
            "wp_version": record.wp_version,
            "plugins": record.plugins,
            "themes": record.themes,
        }
        if record.submitted_at is not None:
            payload["submitted_at"] = record.submitted_at
        if record.approved_at is not None:
            payload["approved_at"] = record.approved_at
        if record.activated_at is not None:
            payload["activated_at"] = record.activated_at
        if record.config_file_hashes is not None:
            payload["config_file_hashes"] = record.config_file_hashes
        return payload

    def _write_baseline(self, path: Path, record: BaselineRecord) -> None:
        _atomic_write_json(path, self._baseline_payload(record))

    def _wp_json_list(self, args: list[str]) -> list[dict[str, Any]]:
        output = self._docker_wp(args)
        try:
            value = json.loads(output or "[]")
        except json.JSONDecodeError as exc:
            raise BaselineError(
                f"WP-CLI returned invalid JSON for {' '.join(args)}: {exc}"
            ) from exc
        if not isinstance(value, list):
            raise BaselineError(
                f"WP-CLI returned non-list JSON for {' '.join(args)}"
            )
        return value

    def _wp_text(self, args: list[str]) -> str:
        return self._docker_wp(args).strip()

    def _config_install_dir(self) -> Path:
        """Return the install_dir from config.

        H.0-A: install_dir is now functional (not purely informational).
        Read it directly from self._config to avoid touching v47's broader
        path-derivation logic (R4 known limit, deferred to post-H.0 scope).
        """
        cfg = self._config
        if cfg is not None and hasattr(cfg, "install_dir"):
            return Path(cfg.install_dir)
        return Path("/opt/wpgovern-install")

    def _docker_wp(self, wp_args: list[str]) -> str:
        # H.0-B: wp-cli is in the wordpress:cli image (profile-gated cli service),
        # not in the wordpress:fpm image used by the php service. Use cli profile.
        # See strategic deployment report v1.1, "Stack composition".
        cmd = ["docker", "compose", "run", "--rm", "-T", "cli", "wp", *wp_args]
        try:
            completed = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            raise BaselineError(
                f"WP-CLI command failed: {stderr or exc}"
            ) from exc
        return completed.stdout


# ---------------------------------------------------------------------------
# Module-level helpers (importable for monkeypatching in tests)
# ---------------------------------------------------------------------------


def _timestamped_id(prefix: str) -> str:
    """Generate a collision-resistant ID from a timestamp and a UUID4 suffix.

    Second-resolution timestamps alone collide when two operations happen
    within the same second (automation, test environments, batch execution).
    The UUID4 suffix makes the probability of collision negligible.
    """
    import uuid
    stamp = (
        utc_now_iso().replace("-", "").replace(":", "").replace("T", "")[:14]
    )
    suffix = uuid.uuid4().hex[:8]
    return f"{prefix}-{stamp}-{suffix}"

def _utcnow_compact() -> str:
    return utc_now_iso().replace("-", "").replace(":", "").replace("T", "")[:14]


def _validate_baseline_id(baseline_id: str) -> None:
    if not baseline_id.strip():
        raise BaselineError("baseline_id cannot be empty")
    if "/" in baseline_id or "\\" in baseline_id or ".." in baseline_id:
        raise ValidationError(f"invalid path separators '{baseline_id}'")


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    data = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    try:
        with tmp_path.open("w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

# ---------------------------------------------------------------------------
# H.0-A — Config-file hashing helpers
# ---------------------------------------------------------------------------

import re as _re

_HASH_PATTERN = _re.compile(r'^sha256:[0-9a-f]{64}$')


def _sha256_hex(data: bytes) -> str:
    """Return 'sha256:' + hex-encoded SHA-256 digest of the given bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _validate_relative_path(rel_path: str, context: str = "") -> None:
    """Raise BaselineError if rel_path is not one of the four governed config paths.

    H.0.1-4: H.0 governs exactly four known paths. The validator enforces
    closed-set membership in CONFIG_FILE_PATHS, which automatically refuses
    any other shape — absolute paths, traversal sequences, Windows backslashes,
    NUL bytes, empty strings, and any future malformed key.
    CONFIG_FILE_PATHS is the single source of truth for what is governed.
    """
    if rel_path not in CONFIG_FILE_PATHS:
        raise BaselineError(
            f"config_file_hashes key {rel_path!r} is not one of the four "
            f"governed config files {CONFIG_FILE_PATHS!r} — refused"
            f"{' ' + context if context else ''}"
        )


def _validate_config_file_hashes(
    raw: object, baseline_id: str
) -> dict[str, str]:
    """Validate the config_file_hashes value loaded from a baseline JSON.

    Enforces:
    - The value is a dict[str, str].
    - Every key is a relative path with no traversal sequences.
    - Every value matches the pattern sha256:<64 hex chars>.

    Returns the validated dict. Raises BaselineError on any violation.
    This is the I-CFG-2 load-time contract.
    """
    if not isinstance(raw, dict):
        raise BaselineError(
            f"Baseline '{baseline_id}': config_file_hashes must be a dict, "
            f"got {type(raw).__name__}"
        )
    validated: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise BaselineError(
                f"Baseline '{baseline_id}': config_file_hashes entries must be "
                f"str→str, got {type(key).__name__}→{type(value).__name__}"
            )
        _validate_relative_path(key, context=f"in baseline '{baseline_id}'")
        if not _HASH_PATTERN.match(value):
            raise BaselineError(
                f"Baseline '{baseline_id}': config_file_hashes[{key!r}] value "
                f"does not match sha256:<64 hex chars>: {value!r}"
            )
        validated[key] = value

    # v51 / H.0.3-3: when config_file_hashes is present, it must contain exactly
    # the four governed paths. Legacy baselines (field absent entirely) are
    # handled at the caller — this validator is only invoked when field is present.
    actual = set(validated.keys())
    expected = set(CONFIG_FILE_PATHS)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {missing!r}")
        if extra:
            details.append(f"extra {extra!r}")
        raise BaselineError(
            f"Baseline '{baseline_id}': config_file_hashes must contain exactly "
            f"{sorted(expected)!r}, got {sorted(actual)!r} ({'; '.join(details)})"
        )

    return validated


def _compute_config_file_hashes(install_dir: Path) -> dict[str, str]:
    """Hash all CONFIG_FILE_PATHS relative to install_dir.

    Fail-closed: raises BaselineError if any path is missing.
    H.0.1-3: refuses symlinks for the four governed paths.
    H.0.1-5: provides a clearer diagnostic when install_dir itself is the problem.
    Hash computation happens before any AtomicTransaction is entered.
    """
    # H.0.1-5: clearer diagnostic when install_dir itself is the problem.
    # The previous behaviour raised "config file missing" when the real issue
    # was that install_dir didn't exist — an operator would look for the wrong thing.
    if not install_dir.exists():
        raise BaselineError(
            f"Cannot create baseline: install_dir {str(install_dir)!r} does not "
            f"exist. Configure WPGovernConfig(install_dir=...) or ensure the "
            f"installer has placed config files at the expected location."
        )
    if not install_dir.is_dir():
        raise BaselineError(
            f"Cannot create baseline: install_dir {str(install_dir)!r} is not a "
            f"directory."
        )

    result: dict[str, str] = {}
    for rel_path in CONFIG_FILE_PATHS:
        abs_path = install_dir / rel_path
        # H.0.1-3: refuse symlinks before any other check. is_file() and
        # exists() follow symlinks, so they would silently accept a symlink
        # pointing outside install_dir. Symlinks for governed config files
        # are refused — operators must place the actual files in install_dir.
        if abs_path.is_symlink():
            raise BaselineError(
                f"Cannot create baseline: config file {str(abs_path)!r} is a "
                f"symlink. Symlinks are refused for governed config files; place "
                f"the actual file at the expected location."
            )
        if not abs_path.exists():
            raise BaselineError(
                f"Cannot create baseline: required config file {str(abs_path)!r} "
                f"is missing. Ensure the installer has completed phase H.4 before "
                f"creating a baseline."
            )
        if not abs_path.is_file():
            raise BaselineError(
                f"Cannot create baseline: config path {str(abs_path)!r} exists "
                f"but is not a regular file."
            )
        result[rel_path] = _sha256_hex(abs_path.read_bytes())
    return result
