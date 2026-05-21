"""
CI guard tests — prevent methodology regressions from silently accumulating.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest


def test_readme_test_counts_consistent() -> None:
    """All numeric test count references in README must match actual collections.

    β-4: The previous guard used re.search (first match only). README had stale
    counts in multiple places (~618, 596) that were not caught. This stronger
    version finds ALL numeric test references and validates each one against
    the actual fast or full collection count.

    v50 / H.0.2-4: detect subprocess collection failure cleanly. Previously,
    a missing test extra (e.g., hypothesis not installed) caused collection
    to fail; the guard misread this as stale README counts. The fix: check
    returncode and surface the actual environmental issue.
    """
    cwd = Path(__file__).parent.parent

    fast_result = subprocess.run(
        ["python", "-m", "pytest", "--collect-only", "-q",
         "--ignore=tests/test_hypothesis.py", "--ignore=tests/test_kill_points.py"],
        capture_output=True, text=True, cwd=cwd,
    )
    # v50 / H.0.2-4: detect collection failure
    if fast_result.returncode != 0:
        pytest.fail(
            f"Fast collection failed (returncode={fast_result.returncode}). "
            f"Install test extras (e.g. 'pip install -e .[test]') and retry. "
            f"stdout tail: {fast_result.stdout[-500:]}"
        )
    fast_match = re.search(r"(\d+) tests? collected", fast_result.stdout)
    if not fast_match:
        pytest.skip("Could not determine fast test count")
    fast_count = int(fast_match.group(1))

    full_result = subprocess.run(
        ["python", "-m", "pytest", "--collect-only", "-q"],
        capture_output=True, text=True, cwd=cwd,
    )
    # v50 / H.0.2-4: same returncode check for full collection
    if full_result.returncode != 0:
        pytest.fail(
            f"Full collection failed (returncode={full_result.returncode}). "
            f"Install test extras (e.g. 'pip install -e .[test]') and retry. "
            f"stdout tail: {full_result.stdout[-500:]}"
        )
    full_match = re.search(r"(\d+) tests? collected", full_result.stdout)
    if not full_match:
        pytest.skip("Could not determine full test count")
    full_count = int(full_match.group(1))

    readme = (cwd / "README.md").read_text(encoding="utf-8")
    matches = list(re.finditer(r"~?(\d+)\s+tests?\b", readme))

    legitimate = {fast_count, full_count}
    stale = []
    for m in matches:
        n = int(m.group(1))
        if n not in legitimate:
            line_start = readme.rfind("\n", 0, m.start()) + 1
            line_end = readme.find("\n", m.end())
            line = readme[line_start:line_end if line_end != -1 else None].strip()
            stale.append((n, line))

    assert not stale, (
        f"README contains stale test counts. Legitimate values: "
        f"fast={fast_count}, full={full_count}. Stale references: {stale}"
    )


def test_no_or_true_in_test_files() -> None:
    """No test file should use 'or True' to make assertions tautological."""
    tests_dir = Path(__file__).parent
    violations = []
    for f in sorted(tests_dir.glob("*.py")):
        if f.name == Path(__file__).name:
            continue
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bor True\b", line) and "# CI-exempt" not in line:
                violations.append(f"{f.name}:{i}: {line.strip()}")
    assert not violations, "Found 'or True':\n" + "\n".join(f"  {v}" for v in violations)


def test_no_noop_invariants() -> None:
    """No invariant should be a literal no-op (return [])."""
    from wpgovern.utils.invariants import _INVARIANT_REGISTRY
    import inspect
    noop_ids = []
    for inv_id, name, fn in _INVARIANT_REGISTRY:
        src = inspect.getsource(fn)
        lines = [l.strip() for l in src.splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        non_doc_non_return = [l for l in lines
                               if not l.startswith(('"""', "'''", 'return []', 'def '))]
        if not non_doc_non_return and any(l == "return []" for l in lines):
            noop_ids.append(f"{inv_id}: {name}")
    assert not noop_ids, "No-op invariants:\n" + "\n".join(f"  {i}" for i in noop_ids)


def test_no_reviewer_name_leakage() -> None:
    """Source and docs must not reference specific reviewer identities."""
    forbidden = [a + b for a, b in [
        ("Sir", " Opus"), ("Chat", "GPT"), ("Deep", "Seek"),
        ("Gr", "ok"), ("Sir ", "Claude"),
    ]]
    repo_root = Path(__file__).parent.parent
    this_file = Path(__file__).resolve()
    violations = []
    for fpath in sorted(repo_root.rglob("*.py")):
        if any(s in str(fpath) for s in ["venv", ".pytest_cache", "__pycache__"]):
            continue
        if fpath.resolve() == this_file:
            continue
        try:
            text = fpath.read_text(encoding="utf-8")
        except OSError:
            continue
        for p in forbidden:
            if p in text:
                violations.append(f"{fpath.relative_to(repo_root)}: '{p}'")
    for fpath in sorted(repo_root.rglob("*.md")):
        if any(s in str(fpath) for s in ["venv", ".pytest_cache"]):
            continue
        # Strategic planning documents and phase briefs legitimately name
        # participants by role. The guard applies to source code and tests,
        # not internal coordination documents.
        #
        # External-review packaging discipline: when the codebase is zipped
        # for external review, the entire docs/ tree is removed from the zip
        # before sending. The package shipped externally never contains
        # planning documents or phase briefs. This preserves internal
        # honesty about participants and external opacity about team shape.
        if fpath.name == "STRATEGIC_DEPLOYMENT_REPORT.md":
            continue
        if "docs/briefs/" in str(fpath) or "docs\\briefs\\" in str(fpath):
            continue
        try:
            text = fpath.read_text(encoding="utf-8")
        except OSError:
            continue
        for p in forbidden:
            if p in text:
                violations.append(f"{fpath.relative_to(repo_root)}: '{p}'")
    assert not violations, (
        "Reviewer names in source/docs:\n" + "\n".join(f"  {v}" for v in violations)
    )


def test_no_silent_exception_swallowing_in_invariants() -> None:
    """No invariant should use 'except Exception: pass' to swallow errors."""
    src = Path("wpgovern/utils/invariants.py").read_text(encoding="utf-8")
    bad = re.findall(r"except\s+Exception(?:\s+as\s+\w+)?\s*:\s*\n\s*pass", src)
    assert not bad, (
        f"Found {len(bad)} silent except Exception: pass in invariants.py."
    )


def test_no_duplicate_invariant_ids() -> None:
    """Each invariant ID must be registered exactly once.

    A duplicate registration is usually an editor accident (function pasted
    twice instead of replaced) that produces duplicated violation entries in
    operator output without any test failure to catch it. Catching the
    duplicate at registration time prevents this class of silent slip.

    ε.2-2: adds structural enforcement — seventh CI guard.
    """
    from wpgovern.utils.invariants import _INVARIANT_REGISTRY

    counts: dict[str, int] = {}
    for inv_id, _desc, _fn in _INVARIANT_REGISTRY:
        counts[inv_id] = counts.get(inv_id, 0) + 1

    duplicates = {iid: c for iid, c in counts.items() if c > 1}
    assert not duplicates, (
        f"Invariant IDs registered multiple times: {duplicates}. "
        "Each invariant must have exactly one definition. "
        "This usually indicates a copy-paste accident in invariants.py."
    )


def test_no_unsigned_compromise_reports() -> None:
    """key_compromise.py must not have any path that writes a JSON report
    without going through stage_signed_json (AtomicTransaction).

    η-3 fixed the if-domain=runtime conditional that left release-domain
    compromise reports unsigned. This guard ensures the pattern does not
    regress — no direct _atomic_write_json calls remain alongside signing
    in the compromise service.
    """
    from pathlib import Path
    import re

    src = (Path(__file__).parent.parent / "wpgovern" / "core" / "key_compromise.py"
           ).read_text(encoding="utf-8")

    # Find any call to _atomic_write_json that is NOT inside a comment or docstring
    # and is NOT the function definition itself.
    non_comment_lines = [
        (i + 1, line) for i, line in enumerate(src.splitlines())
        if not line.lstrip().startswith("#")
        and "_atomic_write_json(" in line
        and "def _atomic_write_json" not in line
    ]

    assert not non_comment_lines, (
        "key_compromise.py contains direct _atomic_write_json calls that bypass "
        "the signed-write pattern. Use _atomic_write_and_sign instead:\n"
        + "\n".join(f"  line {n}: {line.strip()}" for n, line in non_comment_lines)
    )


# ---------------------------------------------------------------------------
# H.0-A CI guards
# ---------------------------------------------------------------------------


def test_baseline_record_has_optional_config_field() -> None:
    """CI guard: BaselineRecord.config_file_hashes must be an optional field
    with default value None.

    Prevents future regression where someone makes the field required and
    breaks loading of legacy baselines that pre-date H.0.

    Enforces the optional-field discipline from the H.0 brief (Section 4.1).
    """
    import dataclasses
    from wpgovern.core.baseline import BaselineRecord

    fields = {f.name: f for f in dataclasses.fields(BaselineRecord)}
    assert "config_file_hashes" in fields, (
        "BaselineRecord must have a config_file_hashes field"
    )
    field = fields["config_file_hashes"]
    assert field.default is None, (
        "config_file_hashes must default to None (optional-field discipline); "
        f"got default={field.default!r}"
    )


def test_no_wp_content_hashing_in_baseline_service() -> None:
    """CI guard: baseline.py must not hash wp-content/ subdirectories.

    Per v1.1 scope decision, wp-content/plugins and wp-content/themes hashing
    is delegated to specialized tools (Wordfence, Sucuri, MalCare). H.0 and
    subsequent phases must not introduce filesystem paths into baseline.py
    that reference wp-content/, plugins/, or themes/ as hashing targets.

    Scans source code for the literal strings 'wp-content/' and 'plugins/'
    (as filesystem path fragments, not as wp-cli arguments like 'plugin list').
    """
    from pathlib import Path
    source = (
        Path(__file__).parent.parent / "wpgovern" / "core" / "baseline.py"
    ).read_text(encoding="utf-8")

    # Check for filesystem path patterns that would indicate wp-content hashing.
    # wp-cli arguments like "plugin" or "theme" (without trailing /) are fine.
    forbidden_patterns = [
        "wp-content/",
        "plugins/",    # filesystem path fragment (plugins/ dir)
        "themes/",     # filesystem path fragment (themes/ dir)
    ]
    violations = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue  # skip comments
        for pattern in forbidden_patterns:
            if pattern in line:
                violations.append((line_no, pattern, line.rstrip()))

    assert not violations, (
        "baseline.py must not reference wp-content/ subdirectory paths. "
        "Per v1.1 scope decision, wp-content hashing is delegated to "
        "specialized tools. Violations:\n"
        + "\n".join(f"  line {ln}: {pat!r} found in: {txt}" for ln, pat, txt in violations)
    )


def test_h0_has_integration_tests_for_governance_check() -> None:
    """H.0.1: governance-check coverage requires integration tests.

    The original H.0 shipped with helper-only unit tests; external review
    surfaced that the integrated check() path was broken because no test
    exercised it end-to-end. This guard ensures the integration test class
    exists and exercises real GovernanceChecker.check().

    Prevents regression where someone deletes the integration tests in a
    future refactor.
    """
    import re
    repo_root = Path(__file__).parent.parent
    test_file = repo_root / "tests" / "test_h0_config_file_hashing.py"
    assert test_file.exists(), "H.0 test file is missing"
    text = test_file.read_text(encoding="utf-8")
    assert "class TestGovernanceCheckConfigHashIntegration" in text, (
        "Integration test class TestGovernanceCheckConfigHashIntegration is missing — "
        "H.0.1 finding regressed"
    )
    cls_match = re.search(
        r"class TestGovernanceCheckConfigHashIntegration.*?(?=\nclass |\Z)",
        text, re.DOTALL,
    )
    assert cls_match, "Integration test class body not found"
    cls_body = cls_match.group(0)
    assert ".check()" in cls_body, (
        "Integration tests must invoke GovernanceChecker.check(), not just helpers"
    )
