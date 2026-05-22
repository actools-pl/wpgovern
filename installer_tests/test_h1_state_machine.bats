#!/usr/bin/env bats
# =============================================================================
# test_h1_state_machine.bats — State machine round-trip and atomic write tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    ENV_FILE="${TEST_TMPDIR}/wpgovern.env"
    cat > "$ENV_FILE" <<ENV
WPGOVERN_OPERATOR_EMAIL="test@example.com"
WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
ENV
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"

    # Source bootstrap + state into the test environment once
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::bootstrap::load_env "$ENV_FILE"
    export STATE_FILE="${TEST_TMPDIR}/install/.wpgovern-installer-state.json"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

@test "state::init creates state file with empty arrays on fresh start" {
    wpgovern::state::init
    [[ -f "$STATE_FILE" ]]
    local phases_complete
    phases_complete="$(jq -r '.phases_complete | length' "$STATE_FILE")"
    [[ "$phases_complete" -eq 0 ]]
    local phases_failed
    phases_failed="$(jq -r '.phases_failed | length' "$STATE_FILE")"
    [[ "$phases_failed" -eq 0 ]]
}

@test "state::init creates state file with started_at and last_run_at" {
    wpgovern::state::init
    [[ -f "$STATE_FILE" ]]
    local started_at
    started_at="$(jq -r '.started_at' "$STATE_FILE")"
    [[ -n "$started_at" ]]
    local last_run_at
    last_run_at="$(jq -r '.last_run_at' "$STATE_FILE")"
    [[ -n "$last_run_at" ]]
}

@test "state::init is idempotent — calling twice preserves existing data" {
    wpgovern::state::init
    wpgovern::state::mark_phase_complete "host"
    wpgovern::state::init  # second call
    local phases_complete
    phases_complete="$(jq -r '.phases_complete | length' "$STATE_FILE")"
    [[ "$phases_complete" -eq 1 ]]
}

@test "state::init on corrupt file reinitializes cleanly" {
    echo "CORRUPT JSON {{{" > "$STATE_FILE"
    wpgovern::state::init
    [[ -f "$STATE_FILE" ]]
    jq empty "$STATE_FILE"  # must be valid JSON
}

# ---------------------------------------------------------------------------
# Phase tracking
# ---------------------------------------------------------------------------

@test "state::phase_complete returns 1 for unknown phase before init" {
    run wpgovern::state::phase_complete "host"
    [[ "$status" -ne 0 ]]
}

@test "state::mark_phase_complete adds phase to phases_complete" {
    wpgovern::state::init
    wpgovern::state::mark_phase_complete "host"
    run wpgovern::state::phase_complete "host"
    [[ "$status" -eq 0 ]]
}

@test "state::mark_phase_complete is idempotent — no duplicates" {
    wpgovern::state::init
    wpgovern::state::mark_phase_complete "host"
    wpgovern::state::mark_phase_complete "host"  # second time
    local count
    count="$(jq -r '.phases_complete | length' "$STATE_FILE")"
    [[ "$count" -eq 1 ]]
}

@test "state::phase_complete returns 1 for phase not yet completed" {
    wpgovern::state::init
    run wpgovern::state::phase_complete "stack"
    [[ "$status" -ne 0 ]]
}

# ---------------------------------------------------------------------------
# Failure tracking
# ---------------------------------------------------------------------------

@test "state::mark_phase_failed adds entry to phases_failed" {
    wpgovern::state::init
    wpgovern::state::mark_phase_failed "host" "docker install failed"
    local count
    count="$(jq -r '.phases_failed | length' "$STATE_FILE")"
    [[ "$count" -eq 1 ]]
    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$STATE_FILE")"
    [[ "$reason" == "docker install failed" ]]
}

@test "state::mark_phase_failed records phase name and timestamp" {
    wpgovern::state::init
    wpgovern::state::mark_phase_failed "host" "test reason"
    local phase
    phase="$(jq -r '.phases_failed[0].phase' "$STATE_FILE")"
    [[ "$phase" == "host" ]]
    local failed_at
    failed_at="$(jq -r '.phases_failed[0].failed_at' "$STATE_FILE")"
    [[ -n "$failed_at" ]]
}

# ---------------------------------------------------------------------------
# Facts round-trip
# ---------------------------------------------------------------------------

@test "state::set_fact and state::get_fact round-trip correctly" {
    wpgovern::state::init
    wpgovern::state::set_fact "host.packages_installed" "true"
    local result
    result="$(wpgovern::state::get_fact "host.packages_installed")"
    [[ "$result" == "true" ]]
}

@test "state::get_fact returns empty string for unknown key" {
    wpgovern::state::init
    local result
    result="$(wpgovern::state::get_fact "nonexistent.key")"
    [[ -z "$result" ]]
}

@test "state::set_fact overwrites existing value" {
    wpgovern::state::init
    wpgovern::state::set_fact "host.version" "1.0"
    wpgovern::state::set_fact "host.version" "2.0"
    local result
    result="$(wpgovern::state::get_fact "host.version")"
    [[ "$result" == "2.0" ]]
}

# ---------------------------------------------------------------------------
# Atomic write (Lesson 7: verify state file is either old or new, never partial)
# ---------------------------------------------------------------------------

@test "state file uses atomic write — .tmp file cleaned up after mark_phase_complete" {
    wpgovern::state::init
    wpgovern::state::mark_phase_complete "host"
    # No .tmp file should remain
    [[ ! -f "${STATE_FILE}.tmp" ]]
}

@test "state file is valid JSON after every operation" {
    wpgovern::state::init
    wpgovern::state::mark_phase_complete "host"
    wpgovern::state::set_fact "host.packages_installed" "true"
    wpgovern::state::mark_phase_failed "stack" "intentional test failure"
    jq empty "$STATE_FILE"
}

@test "state file round-trips: written content equals read content" {
    wpgovern::state::init
    wpgovern::state::mark_phase_complete "host"
    wpgovern::state::set_fact "test.key" "test.value"

    # Read back and verify structural integrity
    local phases_json
    phases_json="$(jq -c '.phases_complete' "$STATE_FILE")"
    [[ "$phases_json" == '["host"]' ]]
    local fact_value
    fact_value="$(jq -r '.host_facts["test.key"]' "$STATE_FILE")"
    [[ "$fact_value" == "test.value" ]]
}

# ---------------------------------------------------------------------------
# H.1.1-1 — State write atomicity regression tests
# These tests exercise the SPECIFIC defect: function called from inside an
# `if` block (which suppresses errexit), with a state file whose schema
# will cause jq to fail. Pre-fix: 0-byte state file + success return.
# Post-fix: non-zero return + original state preserved + no orphan .tmp files.
# ---------------------------------------------------------------------------

@test "H.1.1-1: mark_phase_complete returns non-zero on jq failure" {
    wpgovern::state::init
    # Corrupt the phases_complete field to a non-array (jq filter will fail)
    printf '{"started_at":"x","last_run_at":"x","phases_complete":"corrupt","phases_failed":[],"host_facts":{}}\n' \
        > "$STATE_FILE"

    run wpgovern::state::mark_phase_complete "host"
    [[ "$status" -ne 0 ]]
}

@test "H.1.1-1: mark_phase_complete preserves original state on jq failure (if-context)" {
    wpgovern::state::init
    printf '{"started_at":"x","last_run_at":"x","phases_complete":"corrupt","phases_failed":[],"host_facts":{}}\n' \
        > "$STATE_FILE"
    local original
    original="$(cat "$STATE_FILE")"

    # Invoke in errexit-suppressed context (the exact scenario that was broken)
    if wpgovern::state::mark_phase_complete "host"; then
        true
    fi

    # State file must NOT be empty
    [[ -s "$STATE_FILE" ]]
    # State file must be unchanged (jq failed, mv never happened)
    [[ "$(cat "$STATE_FILE")" == "$original" ]]
}

@test "H.1.1-1: state writes leave no orphan .tmp files on jq failure" {
    wpgovern::state::init
    printf '{"started_at":"x","last_run_at":"x","phases_complete":"corrupt","phases_failed":[],"host_facts":{}}\n' \
        > "$STATE_FILE"

    if wpgovern::state::mark_phase_complete "host"; then true; fi

    # Lesson 7: no .tmp.* files should remain (mktemp-based temp, cleaned on failure)
    local orphan_count
    orphan_count="$(find "${TEST_TMPDIR}/install" -name "*.tmp.*" 2>/dev/null | wc -l)"
    [[ "$orphan_count" -eq 0 ]]
}
