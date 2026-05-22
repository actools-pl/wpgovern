#!/usr/bin/env bats
# =============================================================================
# test_h6_probes_layer2.bats — Layer 2 infrastructure probes
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
    source "${AUDIT_DIR}/infrastructure.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

@test "H.6-3: all 4 containers healthy → WPG-STACK-001 PASS" {
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if [[ "$1 $2" == "compose ps" ]]; then
    printf '[{"Name":"caddy","Health":"healthy"},{"Name":"mariadb","Health":"healthy"},{"Name":"php","Health":"healthy"},{"Name":"wordpress","Health":"healthy"}]\n'
    exit 0
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_containers_healthy
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-001" | grep -q "|PASS|" || {
        echo "Expected PASS"; return 1
    }
}

@test "H.6-3: one container not healthy → WPG-STACK-001 FAIL" {
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if [[ "$1 $2" == "compose ps" ]]; then
    printf '[{"Name":"caddy","Health":"healthy"},{"Name":"mariadb","Health":"unhealthy"},{"Name":"php","Health":"healthy"},{"Name":"wordpress","Health":"healthy"}]\n'
    exit 0
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_containers_healthy
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-001" | grep -q "|FAIL|" || {
        echo "Expected FAIL"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-001" | grep -q "mariadb" || {
        echo "Expected mariadb in message"; return 1
    }
}

@test "H.6-3: disk at 95% → WPG-STACK-002 FAIL CRITICAL" {
    cat > "${MOCK_BIN}/df" << 'MOCK'
#!/usr/bin/env bash
echo "Use%"
echo " 95%"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/df"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_disk_pressure
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-002" | grep -q "|FAIL|" || {
        echo "Expected FAIL at 95%"; return 1
    }
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-002" | grep -q "CRITICAL" || {
        echo "Expected CRITICAL priority at 95%"; return 1
    }
}

@test "H.6-3: disk at 85% → WPG-STACK-002 WARN" {
    cat > "${MOCK_BIN}/df" << 'MOCK'
#!/usr/bin/env bash
echo "Use%"
echo " 85%"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/df"
    PATH="${MOCK_BIN}:${PATH}"
    _audit_probe_disk_pressure
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-STACK-002" | grep -q "|WARN|" || {
        echo "Expected WARN at 85%"; return 1
    }
}

@test "H.6-3: backup probe emits WPG-BKUP-001 WARN when H.7 not deployed" {
    # Default: no backup dir → H.7 not deployed message
    _audit_probe_backup_currency
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-BKUP-001" || {
        echo "Missing WPG-BKUP-001"; return 1
    }
    # Should not be FAIL in H.6 (H.7 not deployed yet)
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-001" | grep -q "|FAIL|" && {
        echo "Should not be FAIL in H.6 before H.7"; return 1
    } || true
}
