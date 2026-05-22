"""
Append-only hash-chained audit logger for the WPGovern governance control plane.

Every governance action is recorded as a JSON record in a newline-delimited log
file. Records are hash-chained: each record's ``prev_hash`` is the ``self_hash``
of the preceding record, and ``self_hash`` is the SHA-256 of the record's own
fields excluding ``self_hash``. This detects blind tampering (a single record
mutated in isolation will have a wrong ``self_hash``). It does not detect
consistent rewrite by an attacker with write access — that is the "audit
transparency" future pass (see KNOWN_LIMITS).

AuditRecord
-----------
Stdlib dataclass; fields: seq, timestamp, event_type, actor, outcome, details,
prev_hash, self_hash. Defined here because it is tightly coupled to the hash
computation logic in this module.

sanitise_details()
------------------
Filters the details dict before it reaches the chain. Two checks apply:

1. **Field-name check**: any field whose name is in the secret-field-names set
   (``password``, ``secret``, ``token``, ``private_key``, ``credential``,
   ``api_key``, ``secret_key``) raises ``AuditError`` immediately. This catches
   callers who accidentally pass raw credentials under any of these names.

2. **PEM-marker check**: any string value that contains a PEM private-key header
   (``BEGIN PRIVATE KEY``, ``BEGIN RSA PRIVATE KEY``, etc.) raises ``AuditError``.
   This catches literal key material in any field regardless of field name.

Operator reason and justification text is **never** rejected on content. A reason
like ``"Per password rotation policy"`` is accepted. Only the two structural checks
above apply.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from wpgovern.audit.fs_hardening import AuditFSHardener
from wpgovern.errors import ValidationError, WPGovernError
from wpgovern.paths import Paths, build_paths
from wpgovern.utils.locking import LockManager


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AUDIT_GENESIS_HASH: str = "0" * 64

AUDIT_MAX_DETAILS_SIZE: int = 4096

# Backward-compat alias for tests that import the old single-string name
AUDIT_FAILURE_ALLOWED_EVENT_PREFIX: str = "recovery."
AUDIT_FAILURE_ALLOWED_EVENT_PREFIXES: tuple[str, ...] = (
    "recovery.",
    "release.",
    "baseline.",
    "trust.",
    "rollback.",
    "breakglass.",
    "reconciliation.",
    "key-compromise-",
    "journal.",
    "approval.",
    "b4.",
)

_SERVICE_LABEL_RE = re.compile(r"^[A-Za-z0-9_.]+$")

# Field names that are inherently secret. Any detail dict key whose lowercased
# name appears in this set is rejected immediately — before the allowlist filter.
_SECRET_FIELD_NAMES: frozenset[str] = frozenset({
    "password",
    "secret",
    "token",
    "private_key",
    "credential",
    "api_key",
    "secret_key",
})

# Pattern-based detection for compound secret key names at all nesting depths.
# Catches access_token, refresh_token, bearer_token, client_secret,
# private-key, privateKey, apiKey, credential_file, password_hash, etc.
# Operator reason text is never rejected — this pattern applies to KEY NAMES only.
import re as _re_audit
_SECRET_KEY_PATTERN = _re_audit.compile(
    r"(password|passwd|secret|token|credential|api[_\-]?key|"
    r"private[_\-]?key|bearer|auth[_\-]?token|access[_\-]?token|"
    r"refresh[_\-]?token|client[_\-]?secret|private[Kk]ey|api[Kk]ey)",
    _re_audit.IGNORECASE,
)


def _is_secret_key(key: str) -> bool:
    """Return True if a field key name looks like a secret field.

    Applies Unicode NFKC normalization + casefold so confusables like
    Cyrillic 'а' (pаssword) and space/hyphen variants (api key, api-key)
    are caught alongside the obvious forms.

    For confusable Unicode characters that NFKC doesn't collapse to ASCII
    (e.g. Cyrillic 'а'), we also try ASCII-only matching (strip non-ASCII).
    """
    import unicodedata
    # Normalize: NFKC + casefold
    normalized = unicodedata.normalize("NFKC", str(key)).casefold()
    # Also collapse spaces, hyphens, underscores → canonical form for matching
    canonical = _re_audit.sub(r"[\s\-_]+", "", normalized)

    # Confusable form: replace non-ASCII chars with 'a' (common confusable target).
    # This catches pаssword (Cyrillic а → replace → password).
    confusable_form = "".join(
        c if ord(c) < 128 else "a"
        for c in normalized
    )
    confusable_canonical = _re_audit.sub(r"[\s\-_]+", "", confusable_form)

    # Exact match on normalized/canonical form
    if normalized in _SECRET_FIELD_NAMES or canonical in _SECRET_FIELD_NAMES:
        return True
    if confusable_form in _SECRET_FIELD_NAMES or confusable_canonical in _SECRET_FIELD_NAMES:
        return True
    # Pattern match
    return bool(
        _SECRET_KEY_PATTERN.search(normalized)
        or _SECRET_KEY_PATTERN.search(canonical)
        or _SECRET_KEY_PATTERN.search(confusable_form)
        or _SECRET_KEY_PATTERN.search(confusable_canonical)
    )


# Token-like value prefixes that indicate machine credentials.
# Only applied to VALUES — operator reason text is never blocked on this.
# Applied only when the outer field type is a nested machine-field (dict/list),
# not for top-level string fields where the value could be operator prose.
_TOKEN_VALUE_PREFIXES: tuple[str, ...] = (
    "sk-",           # OpenAI / Stripe secret keys
    "ghp_",          # GitHub personal access tokens
    "gho_",          # GitHub OAuth tokens
    "ghs_",          # GitHub app installation tokens
    "github_pat_",   # GitHub fine-grained PATs
    "xoxb-",         # Slack bot tokens
    "xoxp-",         # Slack user tokens
    "xoxa-",         # Slack app tokens
    "ya29.",         # Google OAuth access tokens
    "akia",          # AWS access key IDs (case-insensitive prefix handled below)
    "asia",          # AWS temporary access key IDs
)

_TOKEN_VALUE_PATTERNS = [
    _re_audit.compile(r"^bearer\s+\S{8,}", _re_audit.IGNORECASE),  # Bearer <token>
    _re_audit.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}"),                # AWS access keys
    _re_audit.compile(r"^ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$"),  # JWT
]


def _looks_like_token_value(value: str) -> bool:
    """Return True if a string value looks like a machine credential token.

    Strips leading/trailing whitespace before checking so ' ghp_...' is caught.
    """
    stripped = value.strip()
    # Prefix match (case-insensitive for AWS)
    lower = stripped.lower()
    if any(lower.startswith(prefix) for prefix in _TOKEN_VALUE_PREFIXES):
        return True
    # Pattern match for Bearer/AWS/JWT
    return any(pat.search(stripped) for pat in _TOKEN_VALUE_PATTERNS)

# PEM private-key header fragments. Any string value containing one of these
# (case-insensitive) is rejected as likely key material.
_PEM_MARKERS: tuple[str, ...] = (
    "begin encrypted private key",
    "begin private key",
    "begin rsa private key",
    "begin ec private key",
    "begin openssh private key",   # OpenSSH format
    "begin dsa private key",       # M1: DSA private keys
    "begin pgp private key block", # M1: PGP/GPG private keys
)

# Broader regex for any "BEGIN ... PRIVATE KEY ..." PEM block.
# Catches all current and future private key types without needing
# to enumerate each variant explicitly.
import re as _re_pem
_PRIVATE_KEY_HEADER_RE = _re_pem.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----",
    _re_pem.IGNORECASE,
)

# Authoritative allowlist of detail field names. Any field not in this set is
# stripped silently by sanitise_details(). Defined once here; never partitioned
# by version elsewhere in the codebase.
AUDIT_ALLOWED_FIELDS: frozenset[str] = frozenset({
    "actor",
    "actor_id",
    "actor_type",
    "action",
    "target_id",
    "baseline_id",
    "approval_id",
    "incident_id",
    "reason",
    "status",
    "key_id",
    "from",
    "to",
    "reconciliation_id",
    "emergency_id",
    "review_id",
    "outcome",
    "findings",
    "change_ticket",
    "ttl_minutes",
    "expires_at",
    "justification",
    "reviewed_by",
    "reviewed_at",
    "disposition",
    "source",
    "rollback_id",
    "previous_baseline_id",
    "replacement_baseline_id",
    "superseded_baseline_id",
    "revoke_reason",
    "domain",
    "approval_type",
    "target_baseline_id",
    "supersession_id",
    "version",
    "txn_id",
    "service",
    "targets_restored_count",
    "targets_deleted_count",
    "divergent_targets_count",
    "recovery_report_id",
    "recovery_report_hash",
    "intent_signature_key_id",
    "b4_event",
    "review_period_start",
    "review_period_end",
    "records_reviewed",
    "highlighted_count",
    "chain_start_hash",
    "chain_end_hash",
    "review_status",
    "checkpoint_signature",     # step 3: runtime-key signature of the checkpoint hash
    "checkpoint_seq",           # step 3: seq of the checkpoint being signed
    "checkpoint_hash",          # step 3: self_hash of the checkpoint being signed
    "checkpoint_id",            # P1.4: unique ID binding checkpoint to signature companion
    "output_path",
    "size_bytes",
    "algorithm",
    "backup_source",
    "restored_to",
    "forced",
})

_VALID_OUTCOMES: frozenset[str] = frozenset({
    "success",
    "failure",
    "warning",
    "info",
    "skipped",
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuditError(ValidationError):
    """Raised for audit log failures."""


# ---------------------------------------------------------------------------
# AuditRecord
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AuditRecord:
    """A single hash-chained audit record."""

    seq: int
    timestamp: str
    event_type: str
    actor: str
    outcome: str
    details: dict[str, Any]
    prev_hash: str
    self_hash: str

    def without_self_hash(self) -> dict[str, Any]:
        """Return all fields except ``self_hash``, used for hash computation."""
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "actor": self.actor,
            "outcome": self.outcome,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }

    def as_dict(self) -> dict[str, Any]:
        """Return the full record as a dict, including ``self_hash``."""
        payload = self.without_self_hash()
        payload["self_hash"] = self.self_hash
        return payload


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """Append-only audit logger with SHA-256 hash chain.

    Filesystem hardening:
    - Audit directory created as mode 0700.
    - Audit log created/maintained as mode 0600.
    - All append operations serialized under the ``audit`` advisory lock.

    Args:
        config: ``WPGovernConfig`` instance. Used to locate paths and
            pass to the alerter.
        paths: ``Paths`` instance. Derived from ``config`` if not provided.
        lock_manager: ``LockManager`` instance. Created from
            ``paths.locks_dir`` if not provided.
    """

    def __init__(
        self,
        config: Any = None,
        paths: Paths | None = None,
        lock_manager: LockManager | None = None,
    ) -> None:
        if paths is None:
            paths = build_paths(config)
        self.config = config
        self.paths = paths
        self.lock_manager = lock_manager or LockManager(locks_dir=self.paths.locks_dir)
        self.paths.audit.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.paths.audit.parent, 0o700)

    def emit(
        self,
        event_type: str,
        actor: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Alias for ``log()``. Preferred name for call sites."""
        return self.log(event_type, actor, outcome, details)

    def log(
        self,
        event_type: str,
        actor: str,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> AuditRecord:
        """Append a governance event to the audit chain.

        ``outcome="failure"`` is only valid for ``recovery.*`` event types.
        Any other outcome value outside the known set raises ``AuditError``.

        Returns the written ``AuditRecord``.
        """
        if outcome == "failure" and not any(
            event_type.startswith(p) for p in AUDIT_FAILURE_ALLOWED_EVENT_PREFIXES
        ):
            raise AuditError(
                f"Audit outcome 'failure' is restricted to governance event families. "
                f"Event type {event_type!r} is not in the allowed set. "
                f"(got event_type={event_type!r})"
            )
        if outcome not in _VALID_OUTCOMES:
            raise AuditError(
                f"Unknown audit outcome: {outcome!r}. "
                f"Valid outcomes: {sorted(_VALID_OUTCOMES)}"
            )

        enriched_details: dict[str, Any] = {
            "actor_id": actor,
            "reason": None,
            "change_ticket": None,
            **(details or {}),
        }
        sanitized = self.sanitise_details(enriched_details)
        timestamp = _utcnow()

        with self.lock_manager.acquire("audit"):
            AuditFSHardener(self.paths.audit).ensure_restrictive_permissions()
            self.paths.audit.parent.mkdir(parents=True, exist_ok=True)
            seq, prev_hash = self._read_chain_state_unlocked()

            record = AuditRecord(
                seq=seq + 1,
                timestamp=timestamp,
                event_type=event_type,
                actor=actor,
                outcome=outcome,
                details=sanitized,
                prev_hash=prev_hash,
                self_hash="",
            )
            record.self_hash = self.compute_hash(record.without_self_hash())
            self._append_record_unlocked(record)

        # Fire alerts after the chain write, outside the audit lock,
        # so alerting delay or failure cannot affect chain integrity.
        # Best-effort: any alerter exception is absorbed.
        try:
            from wpgovern.audit.alerter import alerter_from_config
            alerter = alerter_from_config(self.config)
            alerter.maybe_alert(
                event_type=event_type,
                actor=actor,
                outcome=outcome,
                details=sanitized,
                self_hash=record.self_hash,
                timestamp=timestamp,
            )
        except Exception:  # noqa: BLE001
            pass  # alerting must never block governance operations

        return record

    def sanitise_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Filter and validate a details dict before it reaches the chain.

        Steps:
        1. Verify the whole payload is JSON-serializable.
        2. Verify the payload is within ``AUDIT_MAX_DETAILS_SIZE`` bytes.
        3. For each key/value: reject secret field names; strip unknown fields;
           validate remaining values (PEM markers, non-printable chars, types).

        Returns the sanitized dict containing only ``AUDIT_ALLOWED_FIELDS`` keys.
        """
        try:
            encoded = json.dumps(details, sort_keys=True, separators=(",", ":"))
        except TypeError as exc:
            raise AuditError(
                f"Audit details are not JSON serializable: {exc}"
            ) from exc

        if len(encoded.encode("utf-8")) > AUDIT_MAX_DETAILS_SIZE:
            raise AuditError("Audit details exceeds size limit")

        sanitized: dict[str, Any] = {}
        for key, value in details.items():
            # Field-name check: reject keys that are inherently secret.
            # This happens BEFORE the allowlist filter so that a caller
            # passing {"password": "x"} gets an explicit error rather than
            # having the field silently dropped.
            if _is_secret_key(key):
                raise AuditError(
                    f"Audit details field '{key}' appears to contain a secret. "
                    "Secrets must not be written to the audit chain."
                )
            if key not in AUDIT_ALLOWED_FIELDS:
                continue
            self._validate_value(key, value)
            sanitized[key] = value
        return sanitized

    def compute_hash(self, payload: dict[str, Any]) -> str:
        """Compute SHA-256 of the canonical JSON serialization of ``payload``."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_chain_state_unlocked(self) -> tuple[int, str]:
        """Return (last_seq, last_self_hash) from the audit log.

        Returns (0, AUDIT_GENESIS_HASH) when the log does not exist or is empty.
        """
        ledger = self.paths.audit
        if not ledger.exists():
            return 0, AUDIT_GENESIS_HASH

        last_line = ""
        with ledger.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last_line = line

        if not last_line:
            return 0, AUDIT_GENESIS_HASH

        try:
            payload = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise AuditError(
                f"Last audit entry is not valid JSON: {exc}"
            ) from exc

        seq = int(payload.get("seq", 0))
        prev_hash = str(payload.get("self_hash") or AUDIT_GENESIS_HASH)
        return seq, prev_hash

    def _append_record_unlocked(self, record: AuditRecord) -> None:
        ledger = self.paths.audit
        line = (
            json.dumps(record.as_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        )
        try:
            with ledger.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(ledger, 0o600)
        except OSError as exc:
            raise AuditError(f"Failed to append audit record: {exc}") from exc

    def _validate_value(self, key: str, value: Any, _depth: int = 0) -> None:
        """Validate a single key/value pair for the audit chain.

        Raises AuditError on:
        - ``service`` field that does not match ``^[A-Za-z0-9_.]+$``
        - String values containing PEM private-key material
        - String values containing non-printable characters (except tab/newline/CR)
        - Nested dict/list values whose contents contain any of the above
        - Values that are not JSON-serializable types
        - Nested structures exceeding maximum recursion depth
        """
        _MAX_DEPTH = 8
        if _depth > _MAX_DEPTH:
            raise AuditError(
                f"Audit details field '{key}' exceeds maximum nesting depth {_MAX_DEPTH}"
            )

        if isinstance(value, str):
            if key == "service" and not _SERVICE_LABEL_RE.match(value):
                raise AuditError(
                    f"Audit details field 'service' must match "
                    f"^[A-Za-z0-9_.]+$ (got: {value!r})"
                )
            # PEM-marker check: structural key material, not operator text.
            lower_value = value.lower()
            if (any(marker in lower_value for marker in _PEM_MARKERS)
                    or _PRIVATE_KEY_HEADER_RE.search(value)):
                raise AuditError(
                    f"Audit details field '{key}' contains PEM key material. "
                    "Private keys must not be written to the audit chain."
                )
            if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in value):
                raise AuditError(
                    f"Audit details contains non-printable characters in field '{key}'"
                )
        elif isinstance(value, dict):
            # Recursively validate nested dict values. Also check nested keys
            # for secret field names — a caller could embed {"password": "x"}
            # inside an allowed outer field like "b4_event".
            for nested_key, nested_val in value.items():
                if isinstance(nested_key, str) and _is_secret_key(nested_key):
                    raise AuditError(
                        f"Audit details nested field '{nested_key}' inside '{key}' "
                        "appears to contain a secret. Secrets must not be written "
                        "to the audit chain."
                    )
                # H3: check for token-shaped values in nested machine fields
                if isinstance(nested_val, str) and _looks_like_token_value(nested_val):
                    raise AuditError(
                        f"Audit details nested field '{nested_key}' inside '{key}' "
                        "contains a value that looks like a machine credential token. "
                        "Credentials must not be written to the audit chain."
                    )
                # M1: also catch Authorization/Cookie header strings in dict values
                if isinstance(nested_val, str):
                    lower_val = nested_val.strip().lower()
                    if lower_val.startswith("authorization:"):
                        raise AuditError(
                            f"Audit details nested field '{nested_key}' inside '{key}' "
                            "contains an Authorization header. "
                            "Credentials must not be written to the audit chain."
                        )
                    if lower_val.startswith("cookie:") or lower_val.startswith("set-cookie:"):
                        raise AuditError(
                            f"Audit details nested field '{nested_key}' inside '{key}' "
                            "contains a Cookie header. "
                            "Credentials must not be written to the audit chain."
                        )
                self._validate_value(nested_key, nested_val, _depth=_depth + 1)
        elif isinstance(value, list):
            # Recursively validate list elements.
            # For string elements: always check for token-like values in nested lists.
            # The list itself is already under some field key, so elements are always
            # in a machine-field context (not top-level operator prose).
            for i, item in enumerate(value):
                if isinstance(item, str) and _looks_like_token_value(item):
                    raise AuditError(
                        f"Audit details nested list item inside '{key}' "
                        "contains a value that looks like a machine credential token. "
                        "Credentials must not be written to the audit chain."
                    )
                # Also catch header strings with credential-like patterns:
                # "Authorization: Bearer ...", "Authorization: Basic ...",
                # "Cookie: sessionid=...", "Set-Cookie: ..."
                if isinstance(item, str):
                    stripped_item = item.strip()
                    lower_item = stripped_item.lower()
                    if lower_item.startswith("authorization:"):
                        raise AuditError(
                            f"Audit details nested list item inside '{key}' "
                            "contains an Authorization header. "
                            "Credentials must not be written to the audit chain."
                        )
                    if lower_item.startswith("cookie:") or lower_item.startswith("set-cookie:"):
                        raise AuditError(
                            f"Audit details nested list item inside '{key}' "
                            "contains a Cookie header. "
                            "Credentials must not be written to the audit chain."
                        )
                self._validate_value(f"{key}[{i}]", item, _depth=_depth + 1)
        elif value is None:
            return
        elif not isinstance(value, (bool, int, float)):
            raise AuditError(
                f"Unsupported audit detail type for field '{key}': "
                f"{type(value).__name__}"
            )


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
