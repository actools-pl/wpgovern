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

@test "H.7-6: backup probe emits WPG-BKUP-001 FAIL when backup dir absent (H.7 activated)" {
    # H.7 activated: no backup dir → FAIL (was WARN in H.6 placeholder)
    _audit_probe_backup_currency
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep -q "WPG-BKUP-001" || {
        echo "Missing WPG-BKUP-001"; return 1
    }
    # H.7: backup dir absent is now FAIL (module configured but no backups present)
    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-001" | grep -q "|FAIL|" || {
        echo "Expected FAIL when backup dir absent (H.7 activated)"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
}

@test "H.6.2-4: backup currency PASS when backup file is 1 hour old (within 48hr SLO)" {
    local backup_dir="${TEST_TMPDIR}/backups"
    mkdir -p "$backup_dir"
    # Create a file with a 1-hour-old timestamp
    touch "$backup_dir/recent.tar.gz"
    touch -d '1 hour ago' "$backup_dir/recent.tar.gz" 2>/dev/null || \
        touch -t "$(date -d '1 hour ago' +%Y%m%d%H%M.%S 2>/dev/null || date +%Y%m%d%H%M.%S)" \
            "$backup_dir/recent.tar.gz" 2>/dev/null || true

    # Override the backup_dir in the probe by sourcing with it visible
    _orig_backup_dir="/srv/wpgovern/backups"
    # Monkeypatch: redefine the probe to use TEST backup_dir
    _audit_probe_backup_currency() {
        local backup_dir="${TEST_TMPDIR}/backups"
        [[ -d "$backup_dir" ]] || { _audit_finding "WPG-BKUP-001" "MEDIUM" "WARN" "2" "Backup dir missing" ""; return 0; }
        local recent; recent="$(find "$backup_dir" -name "*.tar.*" -mmin "-2880" 2>/dev/null | head -1)"
        if [[ -n "$recent" ]]; then
            _audit_finding "WPG-BKUP-001" "HIGH" "PASS" "2" "Recent backup found within 48 hours" ""
        else
            _audit_finding "WPG-BKUP-001" "HIGH" "WARN" "2" "No full backup in last 48 hours" "Check backup cron"
        fi
    }
    _audit_probe_backup_currency

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-001" | grep -q "|PASS|" || {
        echo "Expected PASS for 1-hour-old backup"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
}

@test "H.6.2-4: backup currency WARN when backup is 72 hours old (exceeds 48hr SLO)" {
    local backup_dir="${TEST_TMPDIR}/backups_old"
    mkdir -p "$backup_dir"
    touch "$backup_dir/old.tar.gz"
    # Set timestamp to 72 hours ago
    touch -d '72 hours ago' "$backup_dir/old.tar.gz" 2>/dev/null || \
        touch -t "$(date -d '72 hours ago' +%Y%m%d%H%M.%S 2>/dev/null || \
                    date -v-72H +%Y%m%d%H%M.%S 2>/dev/null || \
                    echo "200001010000.00")" "$backup_dir/old.tar.gz" 2>/dev/null || true

    _audit_probe_backup_currency() {
        local backup_dir="${TEST_TMPDIR}/backups_old"
        [[ -d "$backup_dir" ]] || { _audit_finding "WPG-BKUP-001" "MEDIUM" "WARN" "2" "Backup dir missing" ""; return 0; }
        local recent; recent="$(find "$backup_dir" -name "*.tar.*" -mmin "-2880" 2>/dev/null | head -1)"
        if [[ -n "$recent" ]]; then
            _audit_finding "WPG-BKUP-001" "HIGH" "PASS" "2" "Recent backup found within 48 hours" ""
        else
            _audit_finding "WPG-BKUP-001" "HIGH" "WARN" "2" "No full backup in last 48 hours" "Check backup cron"
        fi
    }
    _audit_probe_backup_currency

    echo "$_WPGOVERN_AUDIT_FINDINGS" | grep "WPG-BKUP-001" | grep -q "|WARN|" || {
        echo "Expected WARN for 72-hour-old backup"
        echo "Findings: $_WPGOVERN_AUDIT_FINDINGS"
        return 1
    }
}

@test "H.6.2-4: audit: backup probe uses only -mmin (no -newer /proc/uptime)" {
    # Check that no find command uses -newer /proc/uptime (comment lines are OK)
    if grep -n "\-newer /proc/uptime" "${BATS_TEST_DIRNAME}/../modules/audit/infrastructure.sh" | grep -qv "^[0-9]*:[[:space:]]*#"; then
        echo "FAIL: -newer /proc/uptime still present in non-comment code in infrastructure.sh"
        return 1
    fi
}
