#!/usr/bin/env bats
# test_h7_restore_test.bats — backup integrity verification

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
BACKUP_DIR="${BATS_TEST_DIRNAME}/../modules/backup"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" \
             "${TEST_TMPDIR}/backups" "${TEST_TMPDIR}/keys" "$MOCK_BIN"
    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_BACKUP_DIR="${TEST_TMPDIR}/backups"
    export WPGOVERN_AGE_PRIVATE_KEY_PATH="${TEST_TMPDIR}/keys/age.key"
    export WPGOVERN_AGE_PUBLIC_KEY_PATH="${TEST_TMPDIR}/keys/age.pub"
    export WPGOVERN_DB_BACKUP_PASSWORD="test_backup_pw"
    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
}
teardown() { rm -rf "$TEST_TMPDIR"; }

_require_age() { command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1 || skip "age tools not available"; }

_setup_keys() {
    age-keygen -o "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" 2>/dev/null
    age-keygen -y "${WPGOVERN_AGE_PRIVATE_KEY_PATH}" > "${WPGOVERN_AGE_PUBLIC_KEY_PATH}" 2>/dev/null
    chmod 600 "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
}

_create_fake_backup() {
    local pubkey; pubkey="$(cat "${WPGOVERN_AGE_PUBLIC_KEY_PATH}")"
    { echo "-- MariaDB dump"
      echo "CREATE TABLE wp_options (option_id int);"
      echo "INSERT INTO wp_options VALUES (1);"
    } | age -r "$pubkey" -o "${WPGOVERN_BACKUP_DIR}/full-20260101T120000Z.sql.age"
}

@test "H.7-4: restore_test returns 1 when private key missing" {
    source "${BACKUP_DIR}/restore_test.sh"
    # No private key at path
    run wpgovern::backup::run_restore_test
    [[ "$status" -ne 0 ]] || { echo "Expected non-zero return when key missing"; return 1; }
    local result; result="$(wpgovern::state::get_fact "backup.last_restore_test_result" 2>/dev/null || echo "")"
    echo "$result" | grep -qi "FAIL\|missing" || { echo "Expected FAIL in result"; return 1; }
}

@test "H.7-4: restore_test returns 1 when no backup file exists" {
    _require_age
    _setup_keys
    source "${BACKUP_DIR}/restore_test.sh"
    run wpgovern::backup::run_restore_test
    [[ "$status" -ne 0 ]] || { echo "Expected non-zero when no backup file"; return 1; }
    local result; result="$(wpgovern::state::get_fact "backup.last_restore_test_result" 2>/dev/null || echo "")"
    echo "$result" | grep -qi "FAIL\|no backup" || { echo "Expected FAIL in result"; return 1; }
}

@test "H.7-4: restore_test cleanup: test schema dropped even on failure" {
    _require_age
    _setup_keys
    _create_fake_backup

    local dropped_schemas_file="${TEST_TMPDIR}/dropped_schemas.txt"
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
if echo "\$*" | grep -q "DROP SCHEMA"; then
    echo "\$*" >> "${dropped_schemas_file}"
fi
# Fail the table check to simulate restore failure
if echo "\$*" | grep -q "information_schema"; then
    echo "0"; exit 0
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    source "${BACKUP_DIR}/restore_test.sh"
    wpgovern::backup::run_restore_test || true

    grep -q "DROP SCHEMA" "${dropped_schemas_file}" 2>/dev/null || {
        echo "Test schema was not dropped on failure (cleanup trap failed)"
        return 1
    }
}

@test "H.7-4: xtrace guard prevents private key path/content leakage" {
    _require_age
    _setup_keys
    local SENT="SENTINEL_AGE_KEY_H74_RESTORE_TEST"
    # Write sentinel as fake key content
    printf '%s\n' "AGE-SECRET-KEY-${SENT}" > "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"
    chmod 600 "${WPGOVERN_AGE_PRIVATE_KEY_PATH}"

    local xtrace_out
    xtrace_out="$(bash -x -c "
        export WPGOVERN_AGE_PRIVATE_KEY_PATH='${WPGOVERN_AGE_PRIVATE_KEY_PATH}'
        export WPGOVERN_BACKUP_DIR='${WPGOVERN_BACKUP_DIR}'
        export WPGOVERN_STATE_FILE='${WPGOVERN_STATE_FILE}'
        export WPGOVERN_LOG_DIR='${WPGOVERN_LOG_DIR}'
        export WPGOVERN_INSTALL_DIR='${WPGOVERN_INSTALL_DIR}'
        export WPGOVERN_DB_BACKUP_PASSWORD='test_pw'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        source '${CORE_DIR}/credentials.sh'
        source '${BACKUP_DIR}/restore_test.sh'
        wpgovern::backup::run_restore_test
    " 2>&1 || true)"

    if echo "$xtrace_out" | grep -qF "$SENT"; then
        echo "CREDENTIAL LEAK: age private key sentinel in xtrace output"
        return 1
    fi
}

@test "H.7-4: restore_test records state facts on completion" {
    _require_age
    _setup_keys

    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if echo "$*" | grep -q "information_schema"; then echo "3"; exit 0; fi
if echo "$*" | grep -q "wp_options"; then echo "100"; exit 0; fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"
    _create_fake_backup

    source "${BACKUP_DIR}/restore_test.sh"
    wpgovern::backup::run_restore_test || true

    local ts; ts="$(wpgovern::state::get_fact "backup.last_restore_test_at" 2>/dev/null || echo "")"
    [[ -n "$ts" ]] || { echo "backup.last_restore_test_at not recorded"; return 1; }
    local result; result="$(wpgovern::state::get_fact "backup.last_restore_test_result" 2>/dev/null || echo "")"
    [[ -n "$result" ]] || { echo "backup.last_restore_test_result not recorded"; return 1; }
}
