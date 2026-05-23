#!/usr/bin/env bats
# =============================================================================
# test_h7_restore.bats — Production-path restore integration tests
#
# Lesson 2 fifth refinement (second operational round): tests invoke the real
# wpgovern-restore shim at a test-local path, not phase functions in isolation.
# Same pattern as test_h6_integration.bats (first operational round).
# =============================================================================

REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"
CORE_DIR="${BATS_TEST_DIRNAME}/../core"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    SHIM_PATH="${TEST_TMPDIR}/bin/wpgovern-restore"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" \
             "${TEST_TMPDIR}/backups/binlogs" "${TEST_TMPDIR}/keys" \
             "$MOCK_BIN" "${TEST_TMPDIR}/bin"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_BACKUP_DIR="${TEST_TMPDIR}/backups"
    export WPGOVERN_AGE_PRIVATE_KEY_PATH="${TEST_TMPDIR}/keys/age.key"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/keys/age.pub"
    export WPGOVERN_DB_BACKUP_PASSWORD="test_backup_pw"
    export WPGOVERN_DOMAIN="test.example.com"
}
teardown() { rm -rf "$TEST_TMPDIR"; }

_install_test_shim() {
    cat > "$SHIM_PATH" << SHIM
#!/usr/bin/env bash
export WPGOVERN_INSTALLER_DIR="${REPO_DIR}"
export WPGOVERN_STATE_FILE="${WPGOVERN_STATE_FILE}"
export WPGOVERN_INSTALL_DIR="${WPGOVERN_INSTALL_DIR}"
export WPGOVERN_LOG_DIR="${WPGOVERN_LOG_DIR}"
export WPGOVERN_BACKUP_DIR="${WPGOVERN_BACKUP_DIR}"
export WPGOVERN_AGE_PRIVATE_KEY_PATH="${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
export WPGOVERN_AGE_PUBLIC_KEY_PATH="${WPGOVERN_AGE_PUBLIC_KEY_PATH}"
export WPGOVERN_DB_BACKUP_PASSWORD="${WPGOVERN_DB_BACKUP_PASSWORD}"
exec "${REPO_DIR}/modules/backup/restore_entry.sh" "\$@"
SHIM
    chmod 755 "$SHIM_PATH"
}

@test "H.7-5: restore shim installs at 755 and --version works" {
    _install_test_shim
    local perms; perms="$(stat -c '%a' "$SHIM_PATH")"
    [[ "$perms" == "755" ]] || { echo "Expected 755, got $perms"; return 1; }
    run "$SHIM_PATH" --version
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$output" =~ "wpgovern-restore" && "$output" =~ "1.0" ]] || {
        echo "Missing version output"; return 1
    }
}

@test "H.7-5: --help shows subcommands including ack-key-backup" {
    _install_test_shim
    run "$SHIM_PATH" --help
    [[ "$status" -eq 0 ]]
    echo "$output" | grep -q "ack-key-backup" || { echo "ack-key-backup missing from help"; return 1; }
    echo "$output" | grep -q "restore-test" || { echo "restore-test missing from help"; return 1; }
}

@test "H.7-5: ack-key-backup sets state fact dr.key_backed_up_at" {
    _install_test_shim
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init

    run "$SHIM_PATH" ack-key-backup --location-hint "test vault"
    [[ "$status" -eq 0 ]] || { echo "ack-key-backup failed: $output"; return 1; }

    local ts; ts="$(wpgovern::state::get_fact "dr.key_backed_up_at" 2>/dev/null || echo "")"
    [[ -n "$ts" ]] || { echo "dr.key_backed_up_at not set after ack"; return 1; }
}

@test "H.7-5: install-check phase refuses restore when phases incomplete" {
    _install_test_shim
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    # phases_complete is empty — install not done

    # H.7.1-6 added decryptability check to validate, so we need real age-encrypted files
    # to get past validate (exit 10) and reach install-check (exit 11).
    if ! command -v age >/dev/null 2>&1 || ! command -v age-keygen >/dev/null 2>&1; then
        skip "age tools not available for install-check test"
    fi
    local ts="20260101T120000Z"
    age-keygen -o "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" 2>/dev/null
    chmod 600 "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
    local pub; pub="$(age-keygen -y "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" 2>/dev/null)"
    printf "fake-sql-dump
" | age -r "$pub"         -o "${WPGOVERN_BACKUP_DIR}/full-${ts}.sql.age" 2>/dev/null
    printf "fake-gov-tarball
" | age -r "$pub"         -o "${WPGOVERN_BACKUP_DIR}/governance-${ts}.tar.gz.age" 2>/dev/null
    # Mock docker to say mariadb is running
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
echo "mariadb running"
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    export PATH="${MOCK_BIN}:${PATH}"

    run "$SHIM_PATH" "$ts"
    [[ "$status" -eq 11 ]] || {
        echo "Expected exit 11 (install-check failure), got $status"
        echo "Output: $output"
        return 1
    }
}


@test "H.7-5: validate phase fails with exit 10 when backup file missing" {
    _install_test_shim
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    # Complete install phases so install-check passes
    wpgovern::state::init
    for phase in host stack db wp ceremony audit; do
        wpgovern::state::mark_phase_complete "$phase"
    done

    # No backup files present
    run "$SHIM_PATH" "20260101T120000Z"
    [[ "$status" -eq 10 ]] || {
        echo "Expected exit 10 (validate failure), got $status"
        echo "Output: $output"
        return 1
    }
}

@test "H.7-5: list shows no backups when dir is empty" {
    _install_test_shim
    run "$SHIM_PATH" list
    [[ "$status" -eq 0 ]]
    echo "$output" | grep -q "Available\|none\|No backup" || {
        echo "Expected list output"
        echo "Output: $output"
        return 1
    }
}

@test "H.7-5: exit code semantics — unknown subcommand returns 2" {
    _install_test_shim
    run "$SHIM_PATH"
    [[ "$status" -eq 2 ]] || { echo "Expected 2 for no-args, got $status"; return 1; }
}
