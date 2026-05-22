#!/usr/bin/env bats
# =============================================================================
# test_h4_prepare.bats — WordPress directory preparation tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
WP_DIR="${BATS_TEST_DIRNAME}/../modules/wp"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${WP_DIR}/prepare.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "H.4-1: fresh install creates directory with 755 perms" {
    run wpgovern::wp::prepare
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local wp_dir="${TEST_TMPDIR}/install/wordpress"
    [[ -d "$wp_dir" ]] || { echo "Directory not created"; return 1; }
    local perms; perms="$(stat -c '%a' "$wp_dir")"
    [[ "$perms" == "755" ]] || { echo "Expected 755, got $perms"; return 1; }
}

@test "H.4-1: directory created with correct UID:GID (33:33)" {
    wpgovern::wp::prepare
    local owner; owner="$(stat -c '%u:%g' "${TEST_TMPDIR}/install/wordpress")"
    [[ "$owner" == "33:33" ]] || { echo "Expected 33:33, got $owner"; return 1; }
}

@test "H.4-1: re-run with correct ownership is idempotent (logged as skipping)" {
    wpgovern::wp::prepare
    run wpgovern::wp::prepare
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already prepared" ]] || [[ "$output" =~ "skipping" ]]
}

@test "H.4-1: state fact wp.prepare.completed_at recorded" {
    wpgovern::wp::prepare
    local ts; ts="$(wpgovern::state::get_fact "wp.prepare.completed_at")"
    [[ -n "$ts" ]] || { echo "wp.prepare.completed_at not set"; return 1; }
}

@test "H.4-1: no credential values in prepare output" {
    export WPGOVERN_DB_WP_PASSWORD="SENTINEL_WP_PREPARE_h4"
    run wpgovern::wp::prepare
    if echo "$output" | grep -qF "SENTINEL_WP_PREPARE_h4"; then
        echo "Unexpected credential in output"; return 1
    fi
}
