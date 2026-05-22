"""
WPGovern structured governance reporter.

``GovernanceReporter.report()`` builds a higher-level structured dict on top
of ``GovernanceChecker`` and the existing Python services. Intended for
human review and automation that needs more context than the deterministic
exit code alone.

Report sections:
  summary        — exit_code, reason, ok flag
  trust          — runtime and release trust store status
  active_state   — active pointer presence, validity, and current baseline
  reconciliation — reconciliation requirement and records
  emergency      — pending review count, emergency records, review records
  audit          — chain integrity status
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wpgovern.audit.verifier import AuditVerifier
from wpgovern.config import DEFAULT_CONFIG, WPGovernConfig
from wpgovern.core.signing import SigningService
from wpgovern.core.trust import TrustService
from wpgovern.paths import WPGovernPaths, build_paths
from wpgovern.status.checker import GovernanceCheckResult, GovernanceChecker
from wpgovern.utils.jsonio import read_json


@dataclass(slots=True, frozen=True)
class GovernanceReport:
    """Structured governance report."""

    summary: dict[str, Any]
    trust: dict[str, Any]
    active_state: dict[str, Any]
    reconciliation: dict[str, Any]
    emergency: dict[str, Any]
    audit: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "trust": self.trust,
            "active_state": self.active_state,
            "reconciliation": self.reconciliation,
            "emergency": self.emergency,
            "audit": self.audit,
        }


class GovernanceReporter:
    """Structured governance reporter.

    Args:
        config: ``WPGovernConfig`` instance.
    """

    def __init__(self, config: WPGovernConfig = DEFAULT_CONFIG) -> None:
        self.config = config
        self.paths: WPGovernPaths = build_paths(config)
        self.checker = GovernanceChecker(config)
        self.trust = TrustService(config)
        self.signing = SigningService(config, trust_service=self.trust)
        self.audit = AuditVerifier(config)

    def report(self) -> dict[str, Any]:
        """Build and return the full governance report as a dict."""
        result = self.checker.check()
        rpt = GovernanceReport(
            summary={
                "exit_code": result.exit_code,
                "reason": result.reason,
                "ok": result.exit_code == 0,
            },
            trust=self._build_trust_section(),
            active_state=self._build_active_state_section(result),
            reconciliation=self._build_reconciliation_section(),
            emergency=self._build_emergency_section(),
            audit=self._build_audit_section(),
        )
        return rpt.as_dict()

    def _build_trust_section(self) -> dict[str, Any]:
        runtime_store = (
            self.paths.trust_runtime_public / "trusted-runtime-keys.json"
        )
        release_store = (
            self.paths.trust_release_public / "trusted-release-keys.json"
        )
        runtime_payload = _safe_read_json(runtime_store)
        release_payload = _safe_read_json(release_store)

        return {
            "runtime": {
                "store_path": str(runtime_store),
                "store_present": runtime_store.is_file(),
                "status": self._trust_status(domain="runtime"),
                "active_key_id": (
                    runtime_payload.get("active_key_id")
                    if isinstance(runtime_payload, dict)
                    else None
                ),
                "keys": (
                    runtime_payload.get("keys", [])
                    if isinstance(runtime_payload, dict)
                    else []
                ),
            },
            "release": {
                "store_path": str(release_store),
                "store_present": release_store.is_file(),
                "status": self._trust_status(domain="release"),
                "active_key_id": (
                    release_payload.get("active_key_id")
                    if isinstance(release_payload, dict)
                    else None
                ),
                "keys": (
                    release_payload.get("keys", [])
                    if isinstance(release_payload, dict)
                    else []
                ),
            },
        }

    def _build_active_state_section(
        self, result: GovernanceCheckResult
    ) -> dict[str, Any]:
        active_pointer_present = self.paths.active_pointer.is_file()
        active_pointer_valid = False
        active_pointer_error: str | None = None
        if active_pointer_present:
            try:
                self.signing.verify_active_pointer()
                active_pointer_valid = True
            except Exception as exc:  # noqa: BLE001
                active_pointer_error = str(exc)

        return {
            "active_pointer_path": str(self.paths.active_pointer),
            "active_pointer_present": active_pointer_present,
            "active_pointer_valid": active_pointer_valid,
            "active_pointer_error": active_pointer_error,
            "active_baseline": result.active_baseline,
        }

    def _build_reconciliation_section(self) -> dict[str, Any]:
        required_path = self.paths.reconciliation_required
        required_id: str | None = None
        if required_path.is_file():
            try:
                required_id = (
                    required_path.read_text(encoding="utf-8").strip() or None
                )
            except Exception:  # noqa: BLE001
                required_id = None

        records = []
        if self.paths.state_reconciliation.is_dir():
            for path in _iter_state_json(self.paths.state_reconciliation):
                payload = _safe_read_json(path)
                if isinstance(payload, dict):
                    records.append(payload)

        return {
            "required": required_path.exists(),
            "required_id": required_id,
            "records": records,
        }

    def _build_emergency_section(self) -> dict[str, Any]:
        emergency_records = []
        pending_review_count = 0
        if self.paths.state_emergency.is_dir():
            for path in _iter_state_json(self.paths.state_emergency):
                payload = _safe_read_json(path)
                if not isinstance(payload, dict):
                    continue
                if payload.get("reviewed", False) is not True:
                    pending_review_count += 1
                emergency_records.append(payload)

        review_records = []
        if self.paths.state_emergency_reviews.is_dir():
            for path in _iter_state_json(self.paths.state_emergency_reviews):
                payload = _safe_read_json(path)
                if isinstance(payload, dict):
                    review_records.append(payload)

        return {
            "pending_review_count": pending_review_count,
            "emergency_records": emergency_records,
            "review_records": review_records,
        }

    def _build_audit_section(self) -> dict[str, Any]:
        audit_path = self.audit.paths.audit
        try:
            result = self.audit.verify()
            return {
                "path": str(audit_path),
                "present": True,
                "ok": result.ok,
                "entries": result.entries,
                "message": result.message,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "path": str(audit_path),
                "present": audit_path.is_file(),
                "ok": False,
                "entries": 0,
                "message": str(exc),
            }

    def _trust_status(self, *, domain: str) -> str:
        try:
            if domain == "runtime":
                self.trust.verify_runtime_trust()
            else:
                self.trust.verify_release_trust()
            return "ok"
        except Exception as exc:  # noqa: BLE001
            return f"error: {exc}"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _iter_state_json(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return [
        path for path in sorted(directory.glob("*.json"))
        if not path.name.endswith(".sig.json")
    ]


def _safe_read_json(path: Path) -> Any | None:
    try:
        return read_json(path)
    except Exception:
        return None
