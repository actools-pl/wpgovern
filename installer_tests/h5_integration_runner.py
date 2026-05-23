#!/usr/bin/env python3
"""
h5_integration_runner.py — Isolated-root_dir runner for H.5 integration tests.

Calls the Python service layer with WPGovernConfig(root_dir=..., install_dir=...)
overrides so tests run without /opt/wpgovern being present.

BaselineService.create_draft calls _docker_wp (docker compose run ... wp) to
capture WordPress runtime state (plugins, themes, version). For isolated
integration tests there is no running stack, so _docker_wp is monkeypatched
to return safe empty/stub values while the real config-file hash computation
runs against the actual governed files in install_dir.

Usage:
    python3 h5_integration_runner.py \\
        --root-dir /tmp/root --install-dir /tmp/install \\
        run-ceremony [--actor-id installer] [--reason "byte-one bootstrap"]

    python3 h5_integration_runner.py \\
        --root-dir /tmp/root --install-dir /tmp/install \\
        governance-check

Exit 0 = success, non-zero = failure.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _build_config(root_dir: str, install_dir: str):
    from wpgovern.config import WPGovernConfig
    return WPGovernConfig(root_dir=Path(root_dir), install_dir=Path(install_dir))


def _patch_docker_wp(baseline_svc):
    """Monkeypatch _docker_wp so tests run without a live WordPress stack.

    The real _docker_wp runs: docker compose run --rm -T cli wp <args>
    For integration tests we return stub runtime values while keeping the
    real config-file hash computation (which reads from install_dir on disk).
    """
    def _stub_docker_wp(wp_args):
        cmd = wp_args[0] if wp_args else ""
        if cmd == "plugin":
            return json.dumps([])          # empty plugin list
        if cmd == "theme":
            return json.dumps([])          # empty theme list
        if cmd == "core":
            return "6.5\n"                  # stub wp version
        return ""
    baseline_svc._docker_wp = _stub_docker_wp


def run_ceremony(config, actor_id: str, reason: str) -> int:
    from wpgovern.core.actor import resolve_actor_context
    from wpgovern.core.trust import TrustService
    from wpgovern.core.baseline import BaselineService
    from wpgovern.status.checker import GovernanceChecker

    actor_ctx = resolve_actor_context(actor_id, reason, None)
    ts = TrustService(config=config)
    bs = BaselineService(config=config)
    _patch_docker_wp(bs)                   # isolate from live stack

    # Steps 1–2: runtime key
    rt = ts.generate_runtime_key("runtime-1")
    ts.activate_runtime_key(rt.key_id)
    print(f"runtime key: {rt.key_id}", file=sys.stderr)

    # Steps 3–4: journal key
    jt = ts.generate_journal_key("journal-1")
    ts.activate_journal_key(jt.key_id)
    print(f"journal key: {jt.key_id}", file=sys.stderr)

    # Step 5: baseline-create (captures config-file hashes from install_dir)
    baseline_id = bs.create_draft(actor_context=actor_ctx)
    print(f"baseline created: {baseline_id}", file=sys.stderr)

    # Step 6: baseline-submit
    bs.submit(baseline_id, actor_context=actor_ctx)
    print("baseline submitted", file=sys.stderr)

    # Step 7: baseline-approve (self-approval; documented bootstrap exception)
    approval_id = bs.approve(baseline_id, approved_by=actor_id, actor_context=actor_ctx)
    print(f"baseline approved: {approval_id}", file=sys.stderr)

    # Step 8: baseline-activate
    bs.activate(baseline_id, approval_id, actor_context=actor_ctx)
    print("baseline activated", file=sys.stderr)

    # Step 9: governance-check
    checker = GovernanceChecker(config)
    result = checker.check()
    if result.exit_code != 0:
        print(f"governance-check FAILED: {result}", file=sys.stderr)
        return 1

    print("governance-check PASSED — system is governed", file=sys.stderr)
    return 0


def governance_check(config) -> int:
    from wpgovern.status.checker import GovernanceChecker

    # Also patch _docker_wp on a throwaway BaselineService so checker doesn't
    # fail if it re-queries WordPress state internally
    try:
        from wpgovern.core.baseline import BaselineService
        bs = BaselineService(config=config)
        _patch_docker_wp(bs)
    except Exception:
        pass

    checker = GovernanceChecker(config)
    result = checker.check()
    if result.exit_code != 0:
        print(f"governance-check FAILED: {result}", file=sys.stderr)
        return 1
    print("governance-check PASSED", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="WPGovern isolated integration runner")
    parser.add_argument("--root-dir",     required=True, help="Isolated governance root dir")
    parser.add_argument("--install-dir",  required=True, help="Dir with four governed config files")
    sub = parser.add_subparsers(dest="command")

    cp = sub.add_parser("run-ceremony")
    cp.add_argument("--actor-id", default="installer")
    cp.add_argument("--reason",   default="byte-one bootstrap")

    sub.add_parser("governance-check")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    try:
        config = _build_config(args.root_dir, args.install_dir)
        if args.command == "run-ceremony":
            return run_ceremony(config, args.actor_id, args.reason)
        if args.command == "governance-check":
            return governance_check(config)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
