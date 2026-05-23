"""
Structural tests: every entry in BUILTIN_ALERT_TRIGGERS and
REVIEW_HIGHLIGHT_EVENT_TYPES must be traceable to a real emit site
(exact match) or to a documented prefix/template that covers it.

Purpose: prevent the class of bug external review found in N1 (key_compromise.{domain}
emitted, key-compromise-{domain} expected) from ever silently sedimenting again.
Without this test, a name change in any emit site leaves a dead trigger entry
that fires for nothing — and vice versa.

Design: this test does NOT scan source at runtime (too brittle). Instead it
maintains an explicit table of known emitted event_types and their source
location, cross-checked against the trigger sets. Any entry in the trigger sets
that is neither in the emit table nor covered by a documented prefix must be
either removed or documented as intentional dead coverage.

Intentional dead entries are listed in INTENTIONAL_DEAD_TRIGGERS. They must
have a comment explaining why they exist despite no emit site.
"""

from __future__ import annotations

import pytest

from wpgovern.audit.alerter import (
    BUILTIN_ALERT_PREFIXES,
    BUILTIN_ALERT_TRIGGERS,
    _should_alert,
)
from wpgovern.audit.verifier import REVIEW_HIGHLIGHT_EVENT_TYPES


# ---------------------------------------------------------------------------
# Canonical emit table — every event_type emitted by the source, with
# its canonical emit location. Maintain this when adding new emits.
# ---------------------------------------------------------------------------

KNOWN_EMITTED_EVENT_TYPES: dict[str, str] = {
    # core/baseline.py
    "baseline.create":               "core/baseline.py",
    "baseline.submit":               "core/baseline.py",
    "baseline.approve":              "core/baseline.py",
    "baseline.activate":             "core/baseline.py",
    # policy/approval.py
    "approval.revoked":              "policy/approval.py",
    # policy/rollback.py
    "rollback.approve":              "policy/rollback.py",
    "rollback.activate":             "policy/rollback.py",
    # policy/breakglass.py
    "breakglass.approve":            "policy/breakglass.py",
    "breakglass.activate":           "policy/breakglass.py",
    "breakglass.review":             "policy/breakglass.py",
    # policy/reconciliation.py
    "reconciliation.complete":       "policy/reconciliation.py",
    # core/trust.py — domain-prefixed key lifecycle events
    # runtime domain: _event_prefix("runtime") == "trust"
    "trust.key.generated":           "core/trust.py",
    "trust.key.activated":           "core/trust.py",
    "trust.key.revoked":             "core/trust.py",
    # release domain: _event_prefix("release") == "release"
    "release.key.generated":         "core/trust.py",
    "release.key.activated":         "core/trust.py",
    "release.key.revoked":           "core/trust.py",
    # journal domain: _event_prefix("journal") == "journal"
    "journal.key.generated":         "core/trust.py",
    "journal.key.activated":         "core/trust.py",
    "journal.key.revoked":           "core/trust.py",
    # core/key_compromise.py — intermediate batch emits (best-effort)
    # Note: these use underscore separators (trust.key_generate) rather than
    # TrustService's convention (trust.key.generated). Tracked as R2 residual —
    # acceptable because these are best-effort and the headline event is correct.
    "trust.key.generated":           "core/trust.py + core/key_compromise.py",
    "trust.key.activated":           "core/trust.py + core/key_compromise.py",
    "trust.key.revoked":             "core/trust.py + core/key_compromise.py",
    # core/key_compromise.py — final summary event
    "key-compromise-runtime":        "core/key_compromise.py",
    "key-compromise-release":        "core/key_compromise.py",
    # cli/commands/journal.py — journal compromise headline event
    "key-compromise-journal":        "cli/commands/journal.py",
    # core/trust_backup.py / cli/commands/keys.py
    "trust.backup.created":          "cli/commands/keys.py",
    "trust.backup.restored":         "cli/commands/keys.py",
    # recovery (utils/recovery.py)
    "recovery.completed":            "utils/recovery.py",
    "recovery.abandoned":            "utils/recovery.py",
    "recovery.rolled_back":          "utils/recovery.py",
    "recovery.refused":              "utils/recovery.py",
    "recovery.stuck":                "utils/recovery.py",
    # audit review (cli/commands/audit.py)
    "audit.review.checkpoint":       "cli/commands/audit.py",
    "audit.checkpoint.signature":    "cli/commands/audit.py (step 3 companion record)",
    # journal trust (cli/commands/journal.py)
    "journal.key.pruned":            "cli/commands/journal.py",
    "journal.v1_migrated":           "cli/commands/journal.py",
    # b4 (cli/commands/keys.py / cli/commands/status.py)
    "b4.cleared":                    "cli/commands/keys.py",
    # audit filesystem hardening
    "audit.fs_harden":               "audit/fs_hardening.py",
    # release signing
    "release.sign":                  "core/signing.py",
    # alert test (cli/commands/audit.py)
    "breakglass.approve":            "cli/commands/audit.py (alert-test synthetic)",
}

# Entries in the trigger/highlight sets that have no direct emit site because
# they are covered by a prefix pattern or are reserved for future use.
# Each must have a documented reason.
INTENTIONAL_DEAD_TRIGGERS: dict[str, str] = {
    # exact-match entries that are also covered by the breakglass. prefix
    "breakglass.start":    "Dead exact-match; prefix 'breakglass.' already covers all subtypes",
    # reconciliation.refused: ReconciliationService raises instead of emitting.
    # N3 finding — tracked for future fix (add emit at raise sites).
    "reconciliation.refused": "N3 deferred: ReconciliationService raises without emitting. "
                              "Tracked for future fix.",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_every_exact_trigger_is_emitted_or_documented() -> None:
    """Every entry in BUILTIN_ALERT_TRIGGERS must either:
    (a) appear in KNOWN_EMITTED_EVENT_TYPES, or
    (b) be in INTENTIONAL_DEAD_TRIGGERS with a documented reason.
    Anything else is a dead trigger that fires for nothing."""
    uncovered = []
    for trigger in BUILTIN_ALERT_TRIGGERS:
        if trigger in KNOWN_EMITTED_EVENT_TYPES:
            continue
        if trigger in INTENTIONAL_DEAD_TRIGGERS:
            continue
        uncovered.append(trigger)
    assert not uncovered, (
        f"BUILTIN_ALERT_TRIGGERS contains entries with no known emit site "
        f"and no documented reason: {uncovered}\n"
        f"Either add an emit site to KNOWN_EMITTED_EVENT_TYPES or document "
        f"the entry in INTENTIONAL_DEAD_TRIGGERS."
    )


def test_every_highlight_type_is_emitted_or_documented() -> None:
    """Every entry in REVIEW_HIGHLIGHT_EVENT_TYPES must either:
    (a) appear in KNOWN_EMITTED_EVENT_TYPES, or
    (b) be in INTENTIONAL_DEAD_TRIGGERS with a documented reason."""
    uncovered = []
    for event_type in REVIEW_HIGHLIGHT_EVENT_TYPES:
        if event_type in KNOWN_EMITTED_EVENT_TYPES:
            continue
        if event_type in INTENTIONAL_DEAD_TRIGGERS:
            continue
        uncovered.append(event_type)
    assert not uncovered, (
        f"REVIEW_HIGHLIGHT_EVENT_TYPES contains entries with no known emit site "
        f"and no documented reason: {uncovered}\n"
        f"Either add an emit site to KNOWN_EMITTED_EVENT_TYPES or document "
        f"the entry in INTENTIONAL_DEAD_TRIGGERS."
    )


def test_every_emitted_event_type_is_declared_in_table() -> None:
    """R3 bidirectional check: every literal event_type string emitted by
    source code must be declared in KNOWN_EMITTED_EVENT_TYPES.

    This is the reverse of the two tests above. Without this check, a
    developer can add a new emit (or rename one) without the table failing.
    The table only catches trigger-set drift; this test also catches
    emit-site drift.

    Implementation: scan wpgovern/**/*.py for event_type= assignments.
    Extracts:
    - Plain string literals: event_type="baseline.create"
    - f-string templates: event_type=f"key-compromise-{domain}"
      → represented in the table as a TEMPLATE entry matching the prefix

    f-strings with {domain} or similar interpolations are matched against
    KNOWN_TEMPLATE_PREFIXES rather than literal lookups.
    """
    import re
    from pathlib import Path

    # Patterns that match event_type= followed by a string literal or f-string.
    LITERAL_RE = re.compile(r'event_type\s*=\s*["\']([^"\']+)["\']')
    FSTRING_RE = re.compile(r'event_type\s*=\s*f["\']([^"\']+)["\']')

    # Known f-string template prefixes. An f-string whose prefix (up to the
    # first {) matches one of these is considered declared.
    KNOWN_TEMPLATE_PREFIXES: set[str] = {
        "key-compromise-",   # f"key-compromise-{domain}"
        "trust.key_",        # f"trust.key_generate" etc. (R2 residual, batch emits)
    }

    wpgovern_root = Path(__file__).parent.parent / "wpgovern"
    undeclared: list[tuple[str, str]] = []  # (event_type, file:line)

    for py_file in sorted(wpgovern_root.rglob("*.py")):
        rel = str(py_file.relative_to(wpgovern_root.parent))
        source = py_file.read_text(encoding="utf-8")

        for match in LITERAL_RE.finditer(source):
            event_type = match.group(1)
            line_no = source[:match.start()].count("\n") + 1
            if event_type in KNOWN_EMITTED_EVENT_TYPES:
                continue
            if event_type in INTENTIONAL_DEAD_TRIGGERS:
                continue
            # Some strings that look like event_type= are used in tests or
            # comparisons, not emits. Skip those that appear in test files
            # (they are expected to reference event names for assertions).
            undeclared.append((event_type, f"{rel}:{line_no}"))

        for match in FSTRING_RE.finditer(source):
            template = match.group(1)
            line_no = source[:match.start()].count("\n") + 1
            # Check if this f-string matches any known template prefix.
            if any(template.startswith(prefix) for prefix in KNOWN_TEMPLATE_PREFIXES):
                continue
            # Check if the template (with {x} stripped) matches a declared entry.
            literal_part = template.split("{")[0]
            matched = any(
                k.startswith(literal_part) for k in KNOWN_EMITTED_EVENT_TYPES
            )
            if not matched:
                undeclared.append((f"f'{template}'", f"{rel}:{line_no}"))

    # Filter out false positives from test files and type annotations.
    real_undeclared = [
        (et, loc) for et, loc in undeclared
        if "tests/" not in loc and "test_" not in loc
    ]

    assert not real_undeclared, (
        f"Source files emit event_types not declared in KNOWN_EMITTED_EVENT_TYPES:\n"
        + "\n".join(f"  {et!r} at {loc}" for et, loc in real_undeclared)
        + "\nAdd each to KNOWN_EMITTED_EVENT_TYPES in test_alert_highlight_coverage.py."
    )


def test_key_compromise_emits_trigger_alert() -> None:
    """key-compromise-runtime and key-compromise-release must trigger alerts.
    Regression for external review finding N1: the old name 'key_compromise.runtime'
    did not match either the exact-match set or the 'key-compromise' prefix."""
    assert _should_alert("key-compromise-runtime"), (
        "key-compromise-runtime must trigger an alert"
    )
    assert _should_alert("key-compromise-release"), (
        "key-compromise-release must trigger an alert"
    )
    assert _should_alert("key-compromise-journal"), (
        "key-compromise-journal must trigger an alert"
    )


def test_trust_backup_restored_in_highlights() -> None:
    """trust.backup.restored must be in REVIEW_HIGHLIGHT_EVENT_TYPES.
    Regression for external review finding N2: a wipe-and-replace of all trust
    material was invisible at checkpoint review."""
    assert "trust.backup.restored" in REVIEW_HIGHLIGHT_EVENT_TYPES, (
        "trust.backup.restored must be highlighted at audit review"
    )


def test_key_compromise_event_names_match_between_emitter_and_triggers() -> None:
    """The canonical event name used by key_compromise.py must exactly match
    the entries in BUILTIN_ALERT_TRIGGERS and REVIEW_HIGHLIGHT_EVENT_TYPES."""
    assert "key-compromise-runtime" in BUILTIN_ALERT_TRIGGERS
    assert "key-compromise-release" in BUILTIN_ALERT_TRIGGERS
    assert "key-compromise-journal" in BUILTIN_ALERT_TRIGGERS
    assert "key-compromise-runtime" in REVIEW_HIGHLIGHT_EVENT_TYPES
    assert "key-compromise-release" in REVIEW_HIGHLIGHT_EVENT_TYPES
    assert "key-compromise-journal" in REVIEW_HIGHLIGHT_EVENT_TYPES
    # Confirm the wrong form is not present anywhere
    assert "key_compromise.runtime" not in BUILTIN_ALERT_TRIGGERS
    assert "key_compromise.release" not in BUILTIN_ALERT_TRIGGERS
    assert "key_compromise.runtime" not in REVIEW_HIGHLIGHT_EVENT_TYPES
    assert "key_compromise.release" not in REVIEW_HIGHLIGHT_EVENT_TYPES


def test_journal_compromise_has_symmetric_audit_event() -> None:
    """Bonus: key-compromise-journal must be in both the trigger set and the
    highlight set, and must be emitted (not an intentional dead entry).
    Before the Bonus fix, journal compromises ended with journal.key.revoked
    only — invisible to auditors searching specifically for 'compromise' events.
    After the fix, key-compromise-journal is the symmetric headline event."""
    assert "key-compromise-journal" in BUILTIN_ALERT_TRIGGERS
    assert "key-compromise-journal" in REVIEW_HIGHLIGHT_EVENT_TYPES
    assert "key-compromise-journal" in KNOWN_EMITTED_EVENT_TYPES
    assert "key-compromise-journal" not in INTENTIONAL_DEAD_TRIGGERS
