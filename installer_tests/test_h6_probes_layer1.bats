#!/usr/bin/env bats
# =============================================================================
# test_h6_probes_layer1.bats — Layer 1 WordPress probes with mocked wp-cli
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
AUDIT_DIR="${BATS_TEST_DIRNAME}/../modules/audit"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"
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
    source "${AUDIT_DIR}/probes.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

_make_docker_wp_mock() {
    local subcommand_output="$1"
    local exit_code="${2:-0}"
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
echo "${subcommand_output}"
exit ${exit_code}
MOCK
    chmod +x "${MOCK_BIN}/docker"
}

@test "H.6-1: plugin update count 0 → PASS finding" {
    _make_docker_wp_mock "0" 0
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_wp_plugin_updates
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-002" || { echo "Missing WPG-WP-002"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "|PASS|" || { echo "Expected PASS"; return 1; }
}

@test "H.6-1: plugin update count 3 → WARN finding" {
    _make_docker_wp_mock "3" 0
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_wp_plugin_updates
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-002" || { echo "Missing WPG-WP-002"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "|WARN|" || { echo "Expected WARN"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "3 WordPress plugin" || { echo "Missing count"; return 1; }
}

@test "H.6-1: active plugins contain wordfence → WPG-WP-007 PASS" {
    _make_docker_wp_mock "wordfence" 0
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_wp_security_plugin
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-007" || { echo "Missing WPG-WP-007"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-WP-007" | grep -q "|PASS|" || {
        echo "Expected PASS for wordfence"; return 1
    }
}

@test "H.6-1: no security plugin in active list → WPG-WP-007 WARN (architectural signal)" {
    _make_docker_wp_mock "akismet
contact-form-7
yoast-seo" 0
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_wp_security_plugin
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-007" || { echo "Missing WPG-WP-007"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-WP-007" | grep -q "|WARN|" || {
        echo "Expected WARN (architectural delegation signal)"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-WP-007" | \
        grep -q "architectural delegation signal" || {
        echo "Missing delegation signal in message"; return 1
    }
}

@test "H.6-1: probe timeout → WARN finding (not crash)" {
    # Mock docker that sleeps longer than timeout (simulates hang)
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
sleep 999
MOCK
    chmod +x "${MOCK_BIN}/docker"

    # Override timeout command to fail fast (simulates 1s timeout expiry)
    cat > "${MOCK_BIN}/timeout" << 'MOCK'
#!/usr/bin/env bash
# Simulate timeout expiry for test speed
shift   # discard the duration arg
exit 124  # timeout exit code
MOCK
    chmod +x "${MOCK_BIN}/timeout"
    PATH="${MOCK_BIN}:${PATH}"

    _audit_probe_wp_plugin_updates
    # Should produce a WARN (timeout), not crash
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-002" || { echo "Missing WPG-WP-002"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-WP-002" | grep -q "|WARN|" || {
        echo "Expected WARN on timeout"; return 1
    }
}

@test "H.6-1: cron event overdue >1hr → WPG-WP-003 WARN" {
    local stale_ts=$(( $(date +%s) - 7200 ))  # 2 hours ago
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
printf '[{"hook":"wp_scheduled_delete","timestamp":${stale_ts},"schedule":"daily"}]\n'
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_wp_cron_status
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-WP-003" || { echo "Missing WPG-WP-003"; return 1; }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-WP-003" | grep -q "|WARN|" || {
        echo "Expected WARN for overdue cron"; return 1
    }
}
