#!/usr/bin/env bats
# =============================================================================
# test_h6_orchestrator.bats — Audit runner and integration tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
AUDIT_DIR="${BATS_TEST_DIRNAME}/../modules/audit"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DOMAIN="test.example.com"
    export NO_COLOR=1  # disable ANSI in tests

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${AUDIT_DIR}/formatters.sh"
    source "${AUDIT_DIR}/orchestrator.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

_load_stub_probes() {
    # Replace all probe functions with stubs that emit configurable findings
    local status="${1:-PASS}"  # default all PASS
    for fn in _audit_probe_wp_core_version _audit_probe_wp_plugin_updates \
              _audit_probe_wp_cron_status _audit_probe_wp_config_drift \
              _audit_probe_wp_security_plugin _audit_probe_redis_writeback \
              _audit_probe_login_session _audit_probe_http_cache_headers \
              _audit_probe_trusted_host_rejection _audit_probe_containers_healthy \
              _audit_probe_disk_pressure _audit_probe_memory_pressure \
              _audit_probe_tls_cert_expiry _audit_probe_backup_currency \
              _audit_probe_backup_integrity _audit_probe_mariadb_reachable \
              _audit_probe_https_enforced _audit_probe_security_headers \
              _audit_probe_ports_open _audit_probe_server_header_hidden \
              _audit_probe_docker_images_pinned _audit_probe_dr_key_backup; do
        local stub_id="${fn/_audit_probe_/WPG-STUB-}"
        eval "${fn}() { _audit_finding '${stub_id}' 'LOW' '${status}' '0' 'stub finding for ${fn}' ''; }"
    done
}

@test "H.6-5: all-PASS audit returns exit 0" {
    _load_stub_probes "PASS"
    run wpgovern::audit::run_full "ci"
    [[ "$status" -eq 0 ]] || { echo "Expected 0, got $status"; return 1; }
}

@test "H.6-5: one FAIL finding returns exit 1" {
    _load_stub_probes "PASS"
    # Override one probe to emit FAIL
    _audit_probe_wp_core_version() {
        _audit_finding "WPG-WP-001" "HIGH" "FAIL" "1" "forced test failure" "fix it"
    }
    run wpgovern::audit::run_full "ci"
    [[ "$status" -eq 1 ]] || { echo "Expected 1, got $status"; return 1; }
}

@test "H.6-5: unknown mode returns exit 2" {
    run wpgovern::audit::run_full "invalid-mode"
    [[ "$status" -eq 2 ]]
}

@test "H.6-5: --security mode includes Layer 3 but not Layer 2 container check" {
    _load_stub_probes "PASS"
    run wpgovern::audit::run_full "security"
    [[ "$status" -eq 0 ]]
    # Layer 3 (security probe) should appear; Layer 2 (stack) should not
    echo "$output" | grep -q "WPG-STUB-containers_healthy" && {
        echo "Layer 2 probe ran in security mode — should not"; return 1
    } || true
    echo "$output" | grep -q "WPG-STUB-https_enforced" || {
        echo "Layer 3 probe missing from security mode output"; return 1
    }
}

@test "H.6-5: full audit runs layers 1 then 2 then 3 (ordering)" {
    local order_file="${TEST_TMPDIR}/probe_order.txt"
    : > "$order_file"
    _audit_probe_wp_core_version()     { echo "L1"  >> "$order_file"; _audit_finding "WPG-WP-001" "LOW" "PASS" "1" "x" ""; }
    _audit_probe_wp_plugin_updates()   { _audit_finding "WPG-WP-002" "LOW" "PASS" "1" "x" ""; }
    _audit_probe_wp_cron_status()      { _audit_finding "WPG-WP-003" "LOW" "PASS" "1" "x" ""; }
    _audit_probe_wp_config_drift()     { _audit_finding "WPG-WP-004" "LOW" "PASS" "1" "x" ""; }
    _audit_probe_wp_security_plugin()  { _audit_finding "WPG-WP-007" "LOW" "PASS" "1" "x" ""; }
    _audit_probe_redis_writeback()     { _audit_finding "WPG-STACK-005" "LOW" "PASS" "1.5" "x" ""; }
    _audit_probe_login_session()       { _audit_finding "WPG-WP-008" "LOW" "PASS" "1.5" "x" ""; }
    _audit_probe_http_cache_headers()  { _audit_finding "WPG-SEC-010" "LOW" "PASS" "1.5" "x" ""; }
    _audit_probe_trusted_host_rejection() { _audit_finding "WPG-SEC-011" "LOW" "PASS" "1.5" "x" ""; }
    _audit_probe_containers_healthy()  { echo "L2"  >> "$order_file"; _audit_finding "WPG-STACK-001" "LOW" "PASS" "2" "x" ""; }
    _audit_probe_disk_pressure()       { _audit_finding "WPG-STACK-002" "LOW" "PASS" "2" "x" ""; }
    _audit_probe_memory_pressure()     { _audit_finding "WPG-STACK-003" "LOW" "PASS" "2" "x" ""; }
    _audit_probe_tls_cert_expiry()     { _audit_finding "WPG-SEC-001" "LOW" "PASS" "2" "x" ""; }
    _audit_probe_backup_currency()     { _audit_finding "WPG-BKUP-001" "LOW" "PASS" "2" "x" ""; }
    _audit_probe_mariadb_reachable()   { _audit_finding "WPG-STACK-004" "LOW" "PASS" "2" "x" ""; }
    _audit_probe_https_enforced()      { echo "L3"  >> "$order_file"; _audit_finding "WPG-SEC-002" "LOW" "PASS" "3" "x" ""; }
    _audit_probe_security_headers()    { _audit_finding "WPG-SEC-003" "LOW" "PASS" "3" "x" ""; }
    _audit_probe_ports_open()          { _audit_finding "WPG-SEC-008" "LOW" "PASS" "3" "x" ""; }
    _audit_probe_server_header_hidden() { _audit_finding "WPG-SEC-005" "LOW" "PASS" "3" "x" ""; }
    _audit_probe_docker_images_pinned() { _audit_finding "WPG-SEC-009" "LOW" "PASS" "3" "x" ""; }
    _audit_probe_dr_key_backup()        { _audit_finding "WPG-DR-01"   "LOW" "PASS" "3" "x" ""; }  # H.7
    _audit_probe_backup_integrity()     { _audit_finding "WPG-BKUP-002" "LOW" "PASS" "2" "x" ""; }  # H.7

    wpgovern::audit::run_full "ci" >/dev/null
    local order; order="$(cat "$order_file")"
    [[ "$order" == $'L1\nL2\nL3' ]] || { echo "Layer ordering wrong: $order"; return 1; }
}

@test "H.6.2-5: probe crash returns exit code 2 (internal error contract)" {
    # All layer stubs return PASS normally
    _load_stub_probes "PASS"
    # Override one probe to crash (non-zero return without emitting a finding)
    _audit_probe_wp_core_version() { return 2; }

    run wpgovern::audit::run_full "ci"
    [[ "$status" -eq 2 ]] || {
        echo "Expected exit code 2 (internal error), got $status"
        return 1
    }
}

@test "H.6.2-5: probe crash with FAIL finding still returns exit code 2 (2 > 1)" {
    _load_stub_probes "PASS"
    # One probe crashes
    _audit_probe_wp_core_version() { return 1; }
    # Another emits FAIL
    _audit_probe_wp_plugin_updates() {
        _audit_finding "WPG-WP-002" "HIGH" "FAIL" "1" "test fail" "fix it"
    }

    run wpgovern::audit::run_full "ci"
    [[ "$status" -eq 2 ]] || {
        echo "Expected 2 (crash > FAIL), got $status"
        return 1
    }
}
