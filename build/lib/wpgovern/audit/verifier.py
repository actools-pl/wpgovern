"""
WPGovern audit chain verifier.

``AuditVerifier`` provides three operations:

``verify()`` — full chain integrity check over the entire log. Re-derives
every ``self_hash`` and checks every ``prev_hash`` link and ``seq`` number.
Raises ``IntegrityError`` on any violation.

``last_checkpoint()`` — scans for the most recent ``audit.review.checkpoint``
event. Returns the raw record dict, or None if no checkpoint exists.

``review_window()`` — returns the window of records since the last checkpoint
(or the full log if no checkpoint exists), with chain integrity verification
inside the window and a list of highlighted high-severity events.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from wpgovern.errors import IntegrityError, NotFoundError
from wpgovern.paths import Paths, build_paths

AUDIT_GENESIS_HASH: str = "0" * 64

# Event types that appear in the human-review summary.
# Auditors must explicitly see and acknowledge these events.
REVIEW_HIGHLIGHT_EVENT_TYPES: frozenset[str] = frozenset({
    "recovery.refused",
    "recovery.stuck",
    "breakglass.approve",
    "breakglass.review",
    "breakglass.activate",
    "key-compromise-runtime",
    "key-compromise-release",
    "key-compromise-journal",
    "journal.key.revoked",
    "baseline.activate",
    "reconciliation.refused",
    "audit.review.checkpoint",
    "b4.cleared",
    "trust.backup.restored",   # wipe-and-replace of all trust material
})


@dataclass(slots=True)
class AuditVerificationResult:
    """Result of a full chain integrity verification."""

    ok: bool
    entries: int
    errors: list[str]
    message: str = "chain intact"


@dataclass
class AuditReviewWindow:
    """The window of audit records between two checkpoints.

    ``start_hash``: self_hash of the last checkpoint record, or the genesis
    hash if no prior checkpoint exists.
    ``end_hash``: self_hash of the most recent record in the window.
    ``records_in_window``: count of records in the window.
    ``highlighted``: records whose event_type is in REVIEW_HIGHLIGHT_EVENT_TYPES.
    ``period_start`` / ``period_end``: ISO timestamps of the window boundaries.
    ``chain_ok``: True if the full chain verifies from start_hash to end_hash.
    ``chain_errors``: any chain integrity errors found in the window.
    """

    start_hash: str
    end_hash: str
    records_in_window: int
    highlighted: list[dict] = field(default_factory=list)
    period_start: str = ""
    period_end: str = ""
    chain_ok: bool = True
    chain_errors: list[str] = field(default_factory=list)


class AuditVerifier:
    """Audit chain verifier.

    Args:
        config: ``WPGovernConfig`` instance.
        paths: ``Paths`` instance. Derived from ``config`` if not provided.
    """

    def __init__(self, config: object = None, paths: Paths | None = None) -> None:
        if paths is None:
            paths = build_paths(config)
        self.config = config
        self.paths = paths

    def verify(self) -> AuditVerificationResult:
        """Full chain integrity check over the entire audit log.

        For every record: checks ``seq`` continuity, ``prev_hash`` linkage,
        and re-derives ``self_hash`` from the stored record body.

        Raises ``NotFoundError`` if the log is missing.
        Raises ``IntegrityError`` if any violation is found.
        """
        ledger = self.paths.audit
        if not ledger.exists():
            raise NotFoundError(f"Audit log missing: {ledger}")

        errors: list[str] = []
        prev_hash = AUDIT_GENESIS_HASH
        entries = 0

        with ledger.open("r", encoding="utf-8") as fh:
            for line_number, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                entries += 1
                # Malformed JSON is a chain integrity failure, not a
                # framework error. Convert immediately to IntegrityError
                # so the caller's except IntegrityError catches it and
                # governance-check exits 51 rather than falling through
                # to the bare except Exception: return None path.
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {line_number}: invalid JSON ({exc})")
                    # Cannot verify any further records; break and raise below.
                    break

                if payload.get("seq") != entries:
                    errors.append(f"seq={payload.get('seq')}, expected {entries}")
                if payload.get("prev_hash") != prev_hash:
                    errors.append(f"line {line_number}: prev_hash mismatch")

                stored_hash = payload.get("self_hash")
                without_hash = dict(payload)
                without_hash.pop("self_hash", None)
                computed = hashlib.sha256(
                    json.dumps(
                        without_hash, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                if stored_hash != computed:
                    errors.append(f"line {line_number}: self_hash mismatch")

                prev_hash = str(stored_hash or "")

        if errors:
            raise IntegrityError("; ".join(errors))
        return AuditVerificationResult(
            ok=True, entries=entries, errors=[], message="chain intact"
        )

    def verify_checkpoint_signature(self, checkpoint_record: dict) -> bool:
        """Verify the runtime-key signature of a checkpoint record.

        The signature companion record (event_type=audit.checkpoint.signature)
        immediately follows the checkpoint record in the chain. This method
        scans for it and verifies the signature against the checkpoint's
        self_hash.

        Returns True if a valid signature exists, False if no signature record
        is found. Raises IntegrityError if a signature record exists but fails
        verification.
        """
        from wpgovern.core.trust import TrustService
        from wpgovern.core.signing import SigningService

        checkpoint_hash = checkpoint_record.get("self_hash", "")
        checkpoint_id = checkpoint_record.get("details", {}).get("checkpoint_id")

        ledger = self.paths.audit
        if not ledger.exists():
            return False

        # Scan the full chain for a companion signature record bound by
        # checkpoint_hash (and checkpoint_id if present). No scan window —
        # a checkpoint_id binding means we never miss the companion regardless
        # of how many records interleave between checkpoint and signature.
        found_checkpoint = False
        with ledger.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not found_checkpoint:
                    if (record.get("event_type") == "audit.review.checkpoint"
                            and record.get("self_hash") == checkpoint_hash):
                        found_checkpoint = True
                    continue

                if record.get("event_type") == "audit.checkpoint.signature":
                    d = record.get("details", {})
                    # Primary binding: checkpoint_hash must match.
                    if d.get("checkpoint_hash") != checkpoint_hash:
                        continue  # different checkpoint's companion — skip
                    # Secondary binding: checkpoint_id.
                    # If the checkpoint record has a checkpoint_id, the companion
                    # MUST also have the same checkpoint_id — no fallback to
                    # hash-only matching for new-format records.
                    rec_cp_id = d.get("checkpoint_id")
                    if checkpoint_id:
                        if not rec_cp_id:
                            continue  # new-format checkpoint; companion missing ID — skip
                        if rec_cp_id != checkpoint_id:
                            continue  # ID mismatch — different checkpoint
                    sig = d.get("checkpoint_signature")
                    if not sig:
                        raise IntegrityError("Signature record has no signature payload")

                    signing = SigningService(config=self.config)
                    signing.verify_bytes(
                        checkpoint_hash.encode("utf-8"), sig, domain="runtime"
                    )
                    return True

        return False

    def last_checkpoint(self) -> dict | None:
        """Return the most recent ``audit.review.checkpoint`` record, or None."""
        ledger = self.paths.audit
        if not ledger.exists():
            return None
        last: dict | None = None
        with ledger.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("event_type") == "audit.review.checkpoint":
                        last = record
                except json.JSONDecodeError:
                    pass
        return last

    def review_window(self) -> AuditReviewWindow:
        """Return the window of audit records since the last checkpoint.

        Covers everything from the last checkpoint's self_hash to the log
        head. If no checkpoint exists, covers the entire log.

        Verifies both prev_hash continuity and self_hash recomputation for
        every record in the window. A tampered record (mutated fields with
        a stale hash) is detected and reported in chain_errors.
        """
        ledger = self.paths.audit
        if not ledger.exists():
            return AuditReviewWindow(
                start_hash=AUDIT_GENESIS_HASH,
                end_hash=AUDIT_GENESIS_HASH,
                records_in_window=0,
            )

        checkpoint = self.last_checkpoint()
        if checkpoint:
            window_start_hash = checkpoint.get("self_hash", AUDIT_GENESIS_HASH)
            in_window = False
        else:
            window_start_hash = AUDIT_GENESIS_HASH
            in_window = True

        records_in_window = 0
        highlighted: list[dict] = []
        period_start = ""
        period_end = ""
        end_hash = AUDIT_GENESIS_HASH
        chain_errors: list[str] = []
        prev_hash = window_start_hash

        with ledger.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    # A malformed line is a chain integrity violation —
                    # silently skipping it would report chain_ok=True over
                    # a corrupt window. Surface it as a chain error so
                    # audit-review refuses to write a checkpoint and the
                    # operator sees the corruption.
                    chain_errors.append(f"invalid JSON in audit log: {exc}")
                    continue

                record_hash = record.get("self_hash", "")
                record_prev = record.get("prev_hash", "")

                if not in_window:
                    if record_prev == window_start_hash:
                        in_window = True
                    else:
                        prev_hash = record_hash
                        continue

                if records_in_window > 0 and record_prev != prev_hash:
                    chain_errors.append(
                        f"chain break at seq={record.get('seq')}: prev_hash mismatch"
                    )

                stored_hash = record.get("self_hash", "")
                without_hash = dict(record)
                without_hash.pop("self_hash", None)
                computed = hashlib.sha256(
                    json.dumps(
                        without_hash, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()
                if stored_hash != computed:
                    chain_errors.append(
                        f"self_hash mismatch at seq={record.get('seq')}: "
                        f"stored={stored_hash[:12]}\u2026 computed={computed[:12]}\u2026"
                    )

                records_in_window += 1
                ts = record.get("timestamp", "")
                if not period_start:
                    period_start = ts
                period_end = ts
                end_hash = record_hash
                prev_hash = record_hash

                event_type = record.get("event_type", "")
                if event_type in REVIEW_HIGHLIGHT_EVENT_TYPES:
                    highlighted.append({
                        "seq": record.get("seq"),
                        "timestamp": ts,
                        "event_type": event_type,
                        "actor": record.get("actor", ""),
                        "outcome": record.get("outcome", ""),
                        "self_hash": record_hash[:16] + "\u2026",
                        "details": _safe_details_summary(record.get("details", {})),
                    })

        return AuditReviewWindow(
            start_hash=window_start_hash,
            end_hash=end_hash,
            records_in_window=records_in_window,
            highlighted=highlighted,
            period_start=period_start,
            period_end=period_end,
            chain_ok=len(chain_errors) == 0,
            chain_errors=chain_errors,
        )


def _safe_details_summary(details: dict) -> dict:
    """Return a trimmed summary of details for human display."""
    keep = (
        "txn_id", "service", "reason", "key_id", "domain",
        "intent_signature_key_id", "b4_event",
    )
    return {k: v for k, v in details.items() if k in keep}
