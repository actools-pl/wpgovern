#!/usr/bin/env bats
# test_h7_status.bats — backup status command

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

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
    source "${BACKUP_DIR}/status.sh"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.7-8: status human output includes expected fields" {
    wpgovern::state::set_fact "backup.last_full_at" "2026-01-01T12:00:00Z"
    wpgovern::state::set_fact "backup.last_full_size_bytes" "1048576"
    run wpgovern::backup::status "human"
    [[ "$status" -eq 0 ]]
    echo "$output" | grep -q "Last full backup" || { echo "Missing 'Last full backup'"; return 1; }
    echo "$output" | grep -q "2026-01-01" || { echo "Missing timestamp"; return 1; }
}

@test "H.7-8: status --json produces valid JSON" {
    wpgovern::state::set_fact "backup.last_full_at" "2026-01-01T12:00:00Z"
    wpgovern::state::set_fact "backup.last_restore_test_result" "PASS"
    run wpgovern::backup::status "--json"
    [[ "$status" -eq 0 ]]
    echo "$output" | jq . >/dev/null 2>&1 || { echo "Invalid JSON: $output"; return 1; }
    echo "$output" | jq -e '.last_full_at' >/dev/null || { echo "Missing last_full_at"; return 1; }
}

@test "H.7-8: status --json includes restore_test_result" {
    wpgovern::state::set_fact "backup.last_restore_test_result" "PASS"
    run wpgovern::backup::status "--json"
    local result; result="$(echo "$output" | jq -r '.last_restore_test_result')"
    [[ "$result" == "PASS" ]] || { echo "Expected PASS, got $result"; return 1; }
}
