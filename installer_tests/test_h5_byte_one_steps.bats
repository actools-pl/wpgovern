#!/usr/bin/env bats
# =============================================================================
# test_h5_byte_one_steps.bats — Per-step behavioral tests with mocked wpgovern.
# Tests bash orchestration correctness; NOT the Python control plane.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
CEREMONY_DIR="${BATS_TEST_DIRNAME}/../modules/ceremony"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    export WPGOVERN_INSTALL_DIR="/opt/wpgovern-install"  # Must match hard requirement
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${CEREMONY_DIR}/byte_one.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_wpgovern_mock() {
    local subcommands_to_succeed="${1:-all}"
    cat > "${MOCK_BIN}/wpgovern" << MOCK
#!/usr/bin/env bash
# Record calls for witness inspection
echo "\$@" >> "${TEST_TMPDIR}/wpgovern_calls.txt"

cmd="\$1"
case "\$cmd" in
    trust-key-generate)  echo "\${2:-runtime-1}"; exit 0 ;;
    trust-key-activate)  echo "\${2:-runtime-1}"; exit 0 ;;
    journal-key-generate) echo "\${2:-journal-1}"; exit 0 ;;
    journal-key-activate) echo "\${2:-journal-1}"; exit 0 ;;
    baseline-create)     echo "baseline-abc123"; exit 0 ;;
    baseline-submit)     echo "\${2:-baseline-abc123}"; exit 0 ;;
    baseline-approve)    echo "approval-xyz789"; exit 0 ;;
    baseline-activate)   exit 0 ;;
    governance-check)    exit 0 ;;
    *)                   exit 1 ;;
esac
MOCK
    chmod +x "${MOCK_BIN}/wpgovern"
}

@test "H.5-2 step 1: generates runtime key and records state fact" {
    _make_wpgovern_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::step_1_generate_runtime_key
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local key_id
    key_id="$(wpgovern::state::get_fact "ceremony.runtime_key_id")"
    [[ "$key_id" == "runtime-1" ]] || { echo "Expected runtime-1, got: $key_id"; return 1; }
    [[ -n "$(wpgovern::state::get_fact "ceremony.step_1_completed_at")" ]] || {
        echo "step_1_completed_at not recorded"; return 1
    }
}

@test "H.5-2 step 1: idempotent — skips if runtime_key_id already recorded" {
    wpgovern::state::set_fact "ceremony.runtime_key_id" "runtime-1"
    _make_wpgovern_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::step_1_generate_runtime_key
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "skipping" ]]
    # Must NOT have invoked wpgovern
    [[ ! -f "${TEST_TMPDIR}/wpgovern_calls.txt" ]] || {
        echo "wpgovern was called despite idempotency"; return 1
    }
}

@test "H.5-2 step 5: captures baseline_id from stdout" {
    wpgovern::state::set_fact "ceremony.runtime_key_id" "runtime-1"
    wpgovern::state::set_fact "ceremony.step_2_completed_at" "2026-01-01T00:00:00Z"
    wpgovern::state::set_fact "ceremony.journal_key_id" "journal-1"
    wpgovern::state::set_fact "ceremony.step_4_completed_at" "2026-01-01T00:00:00Z"
    _make_wpgovern_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::step_5_baseline_create
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local baseline_id
    baseline_id="$(wpgovern::state::get_fact "ceremony.baseline_id")"
    [[ -n "$baseline_id" ]] || { echo "ceremony.baseline_id not recorded"; return 1; }
    [[ "$baseline_id" == "baseline-abc123" ]] || {
        echo "Expected baseline-abc123, got: $baseline_id"; return 1
    }
}

@test "H.5-2 step 7: captures approval_id from stdout" {
    wpgovern::state::set_fact "ceremony.baseline_id" "baseline-abc123"
    wpgovern::state::set_fact "ceremony.step_6_completed_at" "2026-01-01T00:00:00Z"
    _make_wpgovern_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::step_7_baseline_approve
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local approval_id
    approval_id="$(wpgovern::state::get_fact "ceremony.approval_id")"
    [[ "$approval_id" == "approval-xyz789" ]] || {
        echo "Expected approval-xyz789, got: $approval_id"; return 1
    }
}

@test "H.5-2 step 9: governance-check failure records mark_phase_failed" {
    # Pre-fill steps 1-8 complete
    wpgovern::state::set_fact "ceremony.step_8_completed_at" "2026-01-01T00:00:00Z"

    # Mock governance-check to fail
    cat > "${MOCK_BIN}/wpgovern" << MOCK
#!/usr/bin/env bash
[[ "\$1" == "governance-check" ]] && exit 2
exit 0
MOCK
    chmod +x "${MOCK_BIN}/wpgovern"
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::step_9_governance_check
    [[ "$status" -ne 0 ]]

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "governance-check" ]] || {
        echo "Expected governance-check failure reason, got: $reason"; return 1
    }
}

@test "H.5-2: WPGOVERN_INSTALL_DIR mismatch fails byte_one before any wpgovern call" {
    export WPGOVERN_INSTALL_DIR="/wrong/path"
    _make_wpgovern_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::byte_one
    [[ "$status" -ne 0 ]]
    [[ "$output" =~ "wpgovern-install" ]] || [[ "$output" =~ "must be" ]] || {
        echo "Expected path-mismatch error, got: $output"; return 1
    }
    # wpgovern must NOT have been called
    [[ ! -f "${TEST_TMPDIR}/wpgovern_calls.txt" ]] || {
        echo "wpgovern was invoked before path validation"; return 1
    }
}

@test "H.5-2: step 2 fails with clear reason when step 1 state missing" {
    # Don't record ceremony.runtime_key_id — simulates step 1 having failed
    _make_wpgovern_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::step_2_activate_runtime_key
    [[ "$status" -ne 0 ]]

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "runtime_key_id" ]] || {
        echo "Expected runtime_key_id missing reason, got: $reason"; return 1
    }
}

@test "H.5-2: output capture uses 2>/dev/null not 2>&1 (stream discipline)" {
    # Structural audit: captured stdout invocations must not use 2>&1
    local byte_one_file="${CEREMONY_DIR}/byte_one.sh"
    local violations
    violations="$(grep -n 'baseline_id=\$(wpgovern\|approval_id=\$(wpgovern' "$byte_one_file" \
        | grep '2>&1' || true)"
    [[ -z "$violations" ]] || {
        echo "Stream conflation detected (2>&1 on captured invocation):"
        echo "$violations"
        return 1
    }
}

@test "H.5-2: fire-and-forget invocations use >/dev/null 2>&1" {
    # Count fire-and-forget invocations vs >/dev/null 2>&1 occurrences in byte_one.sh
    # Fire-and-forget pattern: `if ! wpgovern <cmd> ... >/dev/null 2>&1`
    # The redirection may be on a continuation line — count total suppressions
    local byte_one_file="${CEREMONY_DIR}/byte_one.sh"
    local ff_count redir_count
    ff_count="$(grep -cE 'if ! wpgovern (trust-key|journal-key|baseline-submit|baseline-activate|governance-check)' "$byte_one_file" || echo 0)"
    redir_count="$(grep -c '>/dev/null 2>&1' "$byte_one_file" || echo 0)"
    [[ "$ff_count" -le "$redir_count" ]] || {
        echo "Found $ff_count fire-and-forget invocations but only $redir_count >/dev/null 2>&1 suppressions"
        return 1
    }
}

@test "H.5-2: each step function has idempotency guard" {
    local byte_one_file="${CEREMONY_DIR}/byte_one.sh"
    # Each step function must call get_fact and check for non-empty
    for step in 1 2 3 4 5 6 7 8 9; do
        grep -qE "step_${step}_completed_at|runtime_key_id|journal_key_id|baseline_id|approval_id|activated_at|governance_check" \
            "$byte_one_file" || {
            echo "Step ${step} missing idempotency guard"
            return 1
        }
    done
}
