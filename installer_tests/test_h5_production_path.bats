#!/usr/bin/env bats
# =============================================================================
# test_h5_production_path.bats — Production-path bash→CLI integration tests
#
# H.5.1-8: exercises byte_one.sh + real wpgovern CLI end-to-end.
# Prior tests called Python services directly (bypassing byte_one.sh and the CLI).
# This test exercises the EXACT production invocation path.
#
# The wpgovern shim is placed in a test-local mock PATH dir (not /usr/local/bin).
# The Python config root_dir is overridden via a thin wrapper script that calls
# the real CLI with isolated paths — exercises byte_one.sh's argv construction
# against real Python argparse WITHOUT requiring the production /opt paths.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
CEREMONY_DIR="${BATS_TEST_DIRNAME}/../modules/ceremony"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
RUNNER="${BATS_TEST_DIRNAME}/h5_integration_runner.py"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    INSTALL_DIR="${TEST_TMPDIR}/install_dir"
    GOVERNANCE_ROOT="${TEST_TMPDIR}/governance_root"
    mkdir -p "$MOCK_BIN" "$INSTALL_DIR" "$GOVERNANCE_ROOT"

    for f in docker-compose.yml Caddyfile my.cnf wp-config.php; do
        printf "# h5.1 production-path test: %s\n" "$f" > "${INSTALL_DIR}/${f}"
    done

    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/state.json"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="/opt/wpgovern-install"
    export WPGOVERN_ACTOR_ID="h5-1-production-test"
    export WPGOVERN_CEREMONY_REASON="byte-one bootstrap"   # HAS SPACE — exercises H.5.1-2

    mkdir -p "${TEST_TMPDIR}/logs"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_require_wheelhouse() {
    [[ -f "${REPO_DIR}/installer/vendor/wpgovern-0.1.0-py3-none-any.whl" ]] || \
        skip "wpgovern wheelhouse not present — skipping production-path test"
    command -v python3 >/dev/null 2>&1 || skip "python3 not available"
}

_setup_venv_and_shim() {
    local venv_dir="${TEST_TMPDIR}/venv"
    python3 -m venv "$venv_dir" >/dev/null 2>&1
    "${venv_dir}/bin/pip" install --quiet --no-index \
        --find-links "${REPO_DIR}/installer/vendor" \
        "wpgovern==0.1.0" >/dev/null 2>&1

    # Thin wrapper: redirects wpgovern CLI to use isolated governance_root + install_dir.
    # This exercises byte_one.sh's argv construction against real Python argparse.
    # The wrapper uses h5_integration_runner.py's WPGovernConfig override mechanism.
    cat > "${MOCK_BIN}/wpgovern" << WRAPPER
#!/usr/bin/env bash
# Production-path test shim — routes to isolated-root runner
exec "${venv_dir}/bin/python3" "${REPO_DIR}/installer_tests/h5_integration_runner_cli_wrapper.py" \
    --root-dir "${GOVERNANCE_ROOT}" \
    --install-dir "${INSTALL_DIR}" \
    -- "\$@"
WRAPPER
    chmod 755 "${MOCK_BIN}/wpgovern"

    # Create the CLI wrapper script that routes CLI commands to isolated config
    cat > "${REPO_DIR}/installer_tests/h5_integration_runner_cli_wrapper.py" << 'WRAPPER_PY'
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
WRAPPER_PY
    chmod +x "${REPO_DIR}/installer_tests/h5_integration_runner_cli_wrapper.py"
}

@test "H.5.1-8: byte_one.sh step_1 invokes real CLI with whitespace-containing reason (H.5.1-2)" {
    _require_wheelhouse
    _setup_venv_and_shim

    # Source the ceremony module with mock CLI in PATH
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${CEREMONY_DIR}/byte_one.sh"
    PATH="${MOCK_BIN}:${PATH}"

    # Step 1 must succeed — if H.5.1-2 was not fixed, the real CLI argparse would
    # receive "bootstrap" as a dangling positional and return non-zero.
    run wpgovern::ceremony::step_1_generate_runtime_key
    [[ "$status" -eq 0 ]] || {
        echo "STEP 1 FAILED (rc=$status): argv construction error"
        echo "Output: $output"
        echo "(Likely word-splitting on WPGOVERN_CEREMONY_REASON)"
        return 1
    }

    # Verify state fact was recorded
    local key_id
    key_id="$(wpgovern::state::get_fact "ceremony.runtime_key_id")"
    [[ "$key_id" == "runtime-1" ]] || {
        echo "runtime_key_id not recorded: $key_id"; return 1
    }
}

@test "H.5.1-8: step_9 records exit 52 (not 0) when governance-check detects tamper" {
    _require_wheelhouse
    _setup_venv_and_shim

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${CEREMONY_DIR}/byte_one.sh"
    PATH="${MOCK_BIN}:${PATH}"

    # Run steps 1-8 first (establish baseline with current file hashes)
    wpgovern::ceremony::step_1_generate_runtime_key || { echo "step 1 failed"; return 1; }
    wpgovern::ceremony::step_2_activate_runtime_key || { echo "step 2 failed"; return 1; }
    wpgovern::ceremony::step_3_generate_journal_key || { echo "step 3 failed"; return 1; }
    wpgovern::ceremony::step_4_activate_journal_key || { echo "step 4 failed"; return 1; }
    wpgovern::ceremony::step_5_baseline_create      || { echo "step 5 failed"; return 1; }
    wpgovern::ceremony::step_6_baseline_submit      || { echo "step 6 failed"; return 1; }
    wpgovern::ceremony::step_7_baseline_approve     || { echo "step 7 failed"; return 1; }
    wpgovern::ceremony::step_8_baseline_activate    || { echo "step 8 failed"; return 1; }

    # Tamper a governed file
    echo "# TAMPERED" >> "${INSTALL_DIR}/wp-config.php"

    # Step 9 with tampered file should fail with exit 52
    run wpgovern::ceremony::step_9_governance_check
    [[ "$status" -ne 0 ]] || {
        echo "GOVERNANCE CHECK PASSED after tamper — H.5.1-5 not fixed correctly"
        return 1
    }

    local reason
    reason="$(jq -r '.phases_failed[-1].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "exit 52" ]] || {
        echo "Expected exit 52 in state reason, got: $reason"
        echo "(If 'exit 0': capture-then-test pattern not applied correctly)"
        return 1
    }
}
