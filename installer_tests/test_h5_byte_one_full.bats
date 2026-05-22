#!/usr/bin/env bats
# =============================================================================
# test_h5_byte_one_full.bats — Full nine-step sequence tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
CEREMONY_DIR="${BATS_TEST_DIRNAME}/../modules/ceremony"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    export WPGOVERN_INSTALL_DIR="/opt/wpgovern-install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_ACTOR_ID="test-installer"
    export WPGOVERN_CEREMONY_REASON="byte-one bootstrap"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${CEREMONY_DIR}/byte_one.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_full_mock() {
    local call_log="${TEST_TMPDIR}/wpgovern_calls.txt"
    : > "$call_log"
    cat > "${MOCK_BIN}/wpgovern" << MOCK
#!/usr/bin/env bash
echo "\$@" >> "${call_log}"
case "\$1" in
    trust-key-generate)  echo "runtime-1"; exit 0 ;;
    trust-key-activate)  echo "runtime-1"; exit 0 ;;
    journal-key-generate) echo "journal-1"; exit 0 ;;
    journal-key-activate) echo "journal-1"; exit 0 ;;
    baseline-create)     echo "baseline-test-001"; exit 0 ;;
    baseline-submit)     echo "baseline-test-001"; exit 0 ;;
    baseline-approve)    echo "approval-test-001"; exit 0 ;;
    baseline-activate)   exit 0 ;;
    governance-check)    exit 0 ;;
    *)                   exit 1 ;;
esac
MOCK
    chmod +x "${MOCK_BIN}/wpgovern"
}

@test "H.5-2 full: all nine steps complete; state facts recorded" {
    _make_full_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::byte_one
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    # Verify all key state facts
    local governance_passed
    governance_passed="$(wpgovern::state::get_fact "ceremony.governance_check_passed_at")"
    [[ -n "$governance_passed" ]] || { echo "governance_check_passed_at not set"; return 1; }

    local baseline_id
    baseline_id="$(wpgovern::state::get_fact "ceremony.baseline_id")"
    [[ "$baseline_id" == "baseline-test-001" ]] || {
        echo "baseline_id mismatch: $baseline_id"; return 1
    }

    local approval_id
    approval_id="$(wpgovern::state::get_fact "ceremony.approval_id")"
    [[ "$approval_id" == "approval-test-001" ]] || {
        echo "approval_id mismatch: $approval_id"; return 1
    }

    # All nine step timestamps recorded
    for i in 1 2 3 4 5 6 7 8 9; do
        local ts
        ts="$(wpgovern::state::get_fact "ceremony.step_${i}_completed_at")"
        [[ -n "$ts" ]] || { echo "step_${i}_completed_at not recorded"; return 1; }
    done
}

@test "H.5-2 full: partial resume — steps 1-5 pre-seeded; only 6-9 invoke wpgovern" {
    _make_full_mock
    PATH="${MOCK_BIN}:${PATH}"

    # Pre-seed steps 1-5 complete
    wpgovern::state::set_fact "ceremony.runtime_key_id" "runtime-1"
    wpgovern::state::set_fact "ceremony.step_1_completed_at" "2026-01-01T00:00:00Z"
    wpgovern::state::set_fact "ceremony.step_2_completed_at" "2026-01-01T00:00:00Z"
    wpgovern::state::set_fact "ceremony.journal_key_id" "journal-1"
    wpgovern::state::set_fact "ceremony.step_3_completed_at" "2026-01-01T00:00:00Z"
    wpgovern::state::set_fact "ceremony.step_4_completed_at" "2026-01-01T00:00:00Z"
    wpgovern::state::set_fact "ceremony.baseline_id" "baseline-pre-seeded"
    wpgovern::state::set_fact "ceremony.step_5_completed_at" "2026-01-01T00:00:00Z"

    run wpgovern::ceremony::byte_one
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local calls
    calls="$(cat "${TEST_TMPDIR}/wpgovern_calls.txt" 2>/dev/null || true)"

    # Steps 1-5 must NOT appear in calls (they were skipped)
    echo "$calls" | grep -q "trust-key-generate" && {
        echo "trust-key-generate was called despite step 1 being pre-seeded"; return 1
    } || true
    echo "$calls" | grep -q "baseline-create" && {
        echo "baseline-create was called despite step 5 being pre-seeded"; return 1
    } || true

    # Steps 6-9 MUST appear
    echo "$calls" | grep -q "baseline-submit" || { echo "baseline-submit not called"; return 1; }
    echo "$calls" | grep -q "governance-check" || { echo "governance-check not called"; return 1; }
}

@test "H.5-2 full: WPGOVERN_INSTALL_DIR mismatch fails before any step" {
    export WPGOVERN_INSTALL_DIR="/wrong/path/should/fail"
    _make_full_mock
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::ceremony::byte_one
    [[ "$status" -ne 0 ]]

    # No wpgovern calls should have been made
    [[ ! -s "${TEST_TMPDIR}/wpgovern_calls.txt" ]] || {
        local calls; calls="$(cat "${TEST_TMPDIR}/wpgovern_calls.txt")"
        echo "wpgovern was called despite path mismatch: $calls"; return 1
    }

    # Specific mark_phase_failed reason
    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "wpgovern-install" ]] || [[ "$reason" =~ "must be" ]] || {
        echo "Expected path-mismatch reason, got: $reason"; return 1
    }
}
