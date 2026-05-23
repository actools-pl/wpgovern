#!/usr/bin/env python3
"""Thin CLI wrapper: routes wpgovern CLI commands to isolated root_dir/install_dir.
Called by the production-path test shim. Exercises real Python argparse + service layer.
"""
import sys
import json
from pathlib import Path

def main():
    args = sys.argv[1:]
    # Parse --root-dir and --install-dir from prefix (added by shim)
    root_dir = install_dir = None
    cli_args = []
    i = 0
    while i < len(args):
        if args[i] == "--root-dir":   root_dir = args[i+1];   i += 2; continue
        if args[i] == "--install-dir": install_dir = args[i+1]; i += 2; continue
        if args[i] == "--":           cli_args = args[i+1:];  break
        cli_args.append(args[i]); i += 1

    from wpgovern.config import WPGovernConfig
    from wpgovern.core.trust import TrustService
    from wpgovern.core.baseline import BaselineService
    from wpgovern.status.checker import GovernanceChecker
    import json

    cfg = WPGovernConfig(root_dir=Path(root_dir), install_dir=Path(install_dir))
    cmd = cli_args[0] if cli_args else ""
    remaining = cli_args[1:]

    def _get_actor():
        actor_id = "installer"
        reason = "byte-one bootstrap"
        i = 0
        while i < len(remaining):
            if remaining[i] == "--actor-id" and i+1 < len(remaining):
                actor_id = remaining[i+1]; i += 2; continue
            if remaining[i] == "--reason" and i+1 < len(remaining):
                reason = remaining[i+1]; i += 2; continue
            i += 1
        from wpgovern.core.actor import resolve_actor_context
        return resolve_actor_context(actor_id, reason, None)

    try:
        if cmd == "version": print("0.1.0"); return 0
        if cmd == "trust-key-generate":
            key_id = remaining[0] if remaining else "runtime-1"
            ts = TrustService(config=cfg)
            r = ts.generate_runtime_key(key_id)
            print(r.key_id); return 0
        if cmd == "trust-key-activate":
            key_id = remaining[0] if remaining else "runtime-1"
            ts = TrustService(config=cfg)
            ts.activate_runtime_key(key_id); print(key_id); return 0
        if cmd == "journal-key-generate":
            key_id = remaining[0] if remaining else "journal-1"
            ts = TrustService(config=cfg)
            r = ts.generate_journal_key(key_id); print(r.key_id); return 0
        if cmd == "journal-key-activate":
            key_id = remaining[0] if remaining else "journal-1"
            ts = TrustService(config=cfg)
            ts.activate_journal_key(key_id); print(key_id); return 0
        if cmd == "baseline-create":
            bs = BaselineService(config=cfg)
            import json as _json
            bs._docker_wp = lambda wp_args: (_json.dumps([]) if wp_args[0] in ("plugin","theme") else "6.5\n")
            print(bs.create_draft(actor_context=_get_actor())); return 0
        if cmd == "baseline-submit":
            bid = remaining[0]
            bs = BaselineService(config=cfg)
            bs.submit(bid, actor_context=_get_actor()); print(bid); return 0
        if cmd == "baseline-approve":
            bid = remaining[0]
            actor = _get_actor()
            actor_id = "installer"
            for i, a in enumerate(remaining):
                if a == "--actor-id" and i+1 < len(remaining): actor_id = remaining[i+1]
            bs = BaselineService(config=cfg)
            print(bs.approve(bid, approved_by=actor_id, actor_context=actor)); return 0
        if cmd == "baseline-activate":
            bid, aid = remaining[0], remaining[1]
            bs = BaselineService(config=cfg)
            bs.activate(bid, aid, actor_context=_get_actor()); return 0
        if cmd == "governance-check":
            result = GovernanceChecker(cfg).check()
            return result.exit_code
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 1

if __name__ == "__main__":
    sys.exit(main())
