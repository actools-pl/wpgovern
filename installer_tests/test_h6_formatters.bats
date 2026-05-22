#!/usr/bin/env bats
# =============================================================================
# test_h6_formatters.bats — Output format tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
AUDIT_DIR="${BATS_TEST_DIRNAME}/../modules/audit"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    export WPGOVERN_DOMAIN="test.example.com"
    export NO_COLOR=1

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    source "${AUDIT_DIR}/formatters.sh"
    source "${AUDIT_DIR}/orchestrator.sh"

    # Seed findings buffer with known data
    _WPGOVERN_AUDIT_FINDINGS="WPG-WP-001|LOW|PASS|1|Core version OK|
WPG-SEC-002|HIGH|FAIL|3|HTTPS not enforced|Add redirect in Caddyfile
WPG-STACK-001|HIGH|WARN|2|Container health degraded|docker compose up -d"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.6-6: NO_COLOR suppresses ANSI sequences in human format" {
    export NO_COLOR=1
    run wpgovern::audit::format_human
    [[ "$status" -eq 0 ]]
    if echo "$output" | grep -q $'\033'; then
        echo "ANSI escape sequences present with NO_COLOR set"; return 1
    fi
}

@test "H.6-6: CI formatter sorts findings by fix-ID" {
    # Seed with unsorted fix-IDs
    _WPGOVERN_AUDIT_FINDINGS="WPG-WP-001|LOW|PASS|1|msg1|
WPG-SEC-002|HIGH|FAIL|3|msg2|fix2
WPG-BKUP-001|MEDIUM|WARN|2|msg3|"
    run wpgovern::audit::format_ci
    [[ "$status" -eq 0 ]]
    # WPG-BKUP-001 < WPG-SEC-002 < WPG-WP-001 alphabetically
    local bkup_pos sec_pos wp_pos
    bkup_pos="$(echo "$output" | grep -n "WPG-BKUP-001" | cut -d: -f1)"
    sec_pos="$(echo "$output" | grep -n "WPG-SEC-002" | cut -d: -f1)"
    wp_pos="$(echo "$output" | grep -n "WPG-WP-001" | cut -d: -f1)"
    [[ "$bkup_pos" -lt "$sec_pos" && "$sec_pos" -lt "$wp_pos" ]] || {
        echo "CI output not sorted by fix-ID"
        echo "bkup=$bkup_pos sec=$sec_pos wp=$wp_pos"
        return 1
    }
}

@test "H.6-6: JSON formatter produces valid JSON" {
    run wpgovern::audit::format_json
    [[ "$status" -eq 0 ]]
    echo "$output" | jq . >/dev/null 2>&1 || {
        echo "JSON output is not valid JSON"
        echo "Output: $output"
        return 1
    }
}

@test "H.6-6: JSON output contains required top-level fields" {
    run wpgovern::audit::format_json
    [[ "$status" -eq 0 ]]
    local json="$output"
    echo "$json" | jq -e '.wpgovern_install_audit_version' >/dev/null || { echo "Missing version"; return 1; }
    echo "$json" | jq -e '.timestamp' >/dev/null || { echo "Missing timestamp"; return 1; }
    echo "$json" | jq -e '.domain' >/dev/null || { echo "Missing domain"; return 1; }
    echo "$json" | jq -e '.summary' >/dev/null || { echo "Missing summary"; return 1; }
    echo "$json" | jq -e '.findings' >/dev/null || { echo "Missing findings"; return 1; }
    echo "$json" | jq -e '.exit_code' >/dev/null || { echo "Missing exit_code"; return 1; }
}

@test "H.6-6: JSON exit_code is 1 when FAIL findings present" {
    run wpgovern::audit::format_json
    [[ "$status" -eq 0 ]]
    local ec; ec="$(echo "$output" | jq '.exit_code')"
    [[ "$ec" -eq 1 ]] || { echo "Expected exit_code=1 (has FAIL), got $ec"; return 1; }
}

@test "H.6-6: JSON summary counts correct" {
    run wpgovern::audit::format_json
    local pass warn fail
    pass="$(echo "$output" | jq '.summary.pass')"
    warn="$(echo "$output" | jq '.summary.warn')"
    fail="$(echo "$output" | jq '.summary.fail')"
    [[ "$pass" -eq 1 ]] || { echo "Expected 1 PASS, got $pass"; return 1; }
    [[ "$warn" -eq 1 ]] || { echo "Expected 1 WARN, got $warn"; return 1; }
    [[ "$fail" -eq 1 ]] || { echo "Expected 1 FAIL, got $fail"; return 1; }
}
