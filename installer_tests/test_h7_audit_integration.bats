#!/usr/bin/env bats
# test_h7_audit_integration.bats — WPG-BKUP-001/002 and WPG-DR-01

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
AUDIT_DIR="${BATS_TEST_DIRNAME}/../modules/audit"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DOMAIN="test.example.com"
    export NO_COLOR=1
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${AUDIT_DIR}/orchestrator.sh"
    source "${AUDIT_DIR}/infrastructure.sh"
    source "${AUDIT_DIR}/security.sh"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.7-6: WPG-BKUP-001 PASS when backup is recent (< 24h)" {
    local backup_dir="${TEST_TMPDIR}/backups"
    mkdir -p "$backup_dir"
    export WPGOVERN_BACKUP_DIR="$backup_dir"
    # Set state fact to recent timestamp
    wpgovern::state::set_fact "backup.last_full_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    _audit_probe_backup_currency
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-001" | grep -q "|PASS|" || {
        echo "Expected PASS for recent backup"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"; return 1
    }
}

@test "H.7-6: WPG-BKUP-001 FAIL when backup dir absent" {
    export WPGOVERN_BACKUP_DIR="${TEST_TMPDIR}/nonexistent"
    _audit_probe_backup_currency
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-001" | grep -q "|FAIL|" || {
        echo "Expected FAIL when backup dir absent"; return 1
    }
}

@test "H.7-6: WPG-BKUP-002 FAIL when restore-test never run" {
    _audit_probe_backup_integrity
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-002" | grep -q "|FAIL|" || {
        echo "Expected FAIL when no restore-test"; return 1
    }
}

@test "H.7-6: WPG-BKUP-002 PASS when restore-test passed recently (< 7 days)" {
    wpgovern::state::set_fact "backup.last_restore_test_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    wpgovern::state::set_fact "backup.last_restore_test_result" "PASS"
    _audit_probe_backup_integrity
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-002" | grep -q "|PASS|" || {
        echo "Expected PASS for recent restore-test"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"; return 1
    }
}

@test "H.7-6: WPG-DR-01 WARN when ack-key-backup not run" {
    # No state fact set
    _audit_probe_dr_key_backup
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-DR-01" | grep -q "|WARN|" || {
        echo "Expected WARN when key not acknowledged"; return 1
    }
}

@test "H.7-6: WPG-DR-01 PASS when ack-key-backup was run" {
    wpgovern::state::set_fact "dr.key_backed_up_at" "2026-01-01T00:00:00Z"
    _audit_probe_dr_key_backup
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-DR-01" | grep -q "|PASS|" || {
        echo "Expected PASS when key acknowledged"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"; return 1
    }
}

@test "H.7-6: WPG-DR-01 PASS message says 'acknowledged' not 'verified' (wording audit)" {
    wpgovern::state::set_fact "dr.key_backed_up_at" "2026-01-01T00:00:00Z"
    _audit_probe_dr_key_backup
    local msg; msg="$(echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-DR-01" | cut -d'|' -f5)"
    echo "$msg" | grep -q "acknowledged" || { echo "Expected 'acknowledged' in PASS message"; return 1; }
    # Must NOT say "verified" (WPGovern cannot verify off-server backup)
    echo "$msg" | grep -qi "WPGovern.*verif\|verif.*WPGovern" && {
        echo "FAIL: PASS message implies WPGovern verified the backup"
        return 1
    } || true
}
