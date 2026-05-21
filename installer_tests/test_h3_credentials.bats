#!/usr/bin/env bats
# =============================================================================
# test_h3_credentials.bats — credentials.sh behavioral tests
#
# The sentinel-grep test (H.3-8 item 6) is the most critical — verifies
# the credentials-not-in-logs guarantee.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
STACK_DIR="${BATS_TEST_DIRNAME}/../modules/stack"
DB_DIR="${BATS_TEST_DIRNAME}/../modules/db"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_ENV_FILE_PATH="${TEST_TMPDIR}/wpgovern.env"

    # Write a minimal env file credentials.sh can persist back to
    cat > "$WPGOVERN_ENV_FILE_PATH" << ENV
WPGOVERN_OPERATOR_EMAIL=test@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_DOMAIN=test.example.com
ENV

    # Sentinel passwords — distinctive strings for log-scan
    export WPGOVERN_DB_ROOT_PASSWORD="SENTINEL_ROOT_PW_h3creds"
    export WPGOVERN_DB_WP_PASSWORD="SENTINEL_WP_PW_h3creds_xx"
    export WPGOVERN_DB_BACKUP_PASSWORD=""  # blank — will be generated

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init
    wpgovern::state::set_fact "bootstrap.env_file_path" "$WPGOVERN_ENV_FILE_PATH"

    # Source stack credentials.sh to get _wpgovern_credentials_persist helper
    source "${STACK_DIR}/credentials.sh"
    source "${DB_DIR}/credentials.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# ---------------------------------------------------------------------------
# age-keygen availability — skip tests if age is not installed
# ---------------------------------------------------------------------------

_require_age() {
    if ! command -v age-keygen >/dev/null 2>&1; then
        skip "age-keygen not installed — H.3-4 adds it to packages.sh"
    fi
}

@test "H.3-2: age key generated with 600 perms on first run" {
    _require_age

    run wpgovern::db::credentials::generate_age_key
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local key_path="${TEST_TMPDIR}/install/.wpgovern-age.key"
    [[ -f "$key_path" ]] || { echo "age key file not created"; return 1; }

    local perms
    perms="$(stat -c '%a' "$key_path")"
    [[ "$perms" == "600" ]] || { echo "Expected 600, got $perms"; return 1; }
}

@test "H.3-2: existing age key with wrong perms is restored to 600" {
    _require_age

    local key_path="${TEST_TMPDIR}/install/.wpgovern-age.key"
    # Create a key file with wrong perms
    age-keygen -o "$key_path" 2>/dev/null
    chmod 644 "$key_path"

    run wpgovern::db::credentials::generate_age_key
    [[ "$status" -eq 0 ]]

    local perms
    perms="$(stat -c '%a' "$key_path")"
    [[ "$perms" == "600" ]] || { echo "Perms not restored; got $perms"; return 1; }
}

@test "H.3-2: encrypt_state produces decryptable output" {
    _require_age
    if ! command -v age >/dev/null 2>&1; then skip "age not installed"; fi

    # Set non-blank passwords for encryption test
    export WPGOVERN_DB_BACKUP_PASSWORD="SENTINEL_BACKUP_PW_h3creds"

    wpgovern::db::credentials::generate_age_key

    run wpgovern::db::credentials::encrypt_state
    [[ "$status" -eq 0 ]] || { echo "encrypt_state failed: $output"; return 1; }

    local enc_file="${TEST_TMPDIR}/install/.wpgovern-credentials.age"
    local key_path="${TEST_TMPDIR}/install/.wpgovern-age.key"
    [[ -f "$enc_file" ]] || { echo "encrypted file not created"; return 1; }

    # Decrypt and verify content
    local decrypted
    decrypted="$(age -d -i "$key_path" "$enc_file" 2>/dev/null)"
    echo "$decrypted" | grep -q "WPGOVERN_DB_ROOT_PASSWORD=SENTINEL_ROOT_PW_h3creds" || {
        echo "Decrypted content missing expected value"; return 1
    }
}

@test "H.3-2: encrypted file has 600 perms" {
    _require_age
    if ! command -v age >/dev/null 2>&1; then skip "age not installed"; fi

    export WPGOVERN_DB_BACKUP_PASSWORD="backuptest12345678901234567890"
    wpgovern::db::credentials::generate_age_key
    wpgovern::db::credentials::encrypt_state

    local enc_file="${TEST_TMPDIR}/install/.wpgovern-credentials.age"
    local perms
    perms="$(stat -c '%a' "$enc_file")"
    [[ "$perms" == "600" ]] || { echo "Expected 600, got $perms"; return 1; }
}

@test "H.3-2: temp file cleaned up on encryption failure" {
    _require_age

    # Create a key file that will fail recipient extraction
    local key_path="${TEST_TMPDIR}/install/.wpgovern-age.key"
    echo "# no public key here" > "$key_path"
    chmod 600 "$key_path"
    wpgovern::state::set_fact "db.credentials.age_key_path" "$key_path"

    export WPGOVERN_DB_BACKUP_PASSWORD="backuptest12345678901234567890"

    run wpgovern::db::credentials::encrypt_state
    [[ "$status" -ne 0 ]]

    # No orphan .tmp.* files
    local tmp_count
    tmp_count="$(find "${TEST_TMPDIR}/install" -name '*.tmp.*' 2>/dev/null | wc -l)"
    [[ "$tmp_count" -eq 0 ]] || {
        echo "Orphan temp files found: $tmp_count"; return 1
    }
}

@test "H.3-2: NO password value appears in stdout or stderr (sentinel-grep)" {
    _require_age
    if ! command -v age >/dev/null 2>&1; then skip "age not installed"; fi

    export WPGOVERN_DB_BACKUP_PASSWORD="SENTINEL_BACKUP_PW_sentineltest"
    export WPGOVERN_DB_ROOT_PASSWORD="SENTINEL_ROOT_PW_sentineltest"
    export WPGOVERN_DB_WP_PASSWORD="SENTINEL_WP_PW_sentineltest__x"

    run bash -c "
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
        export WPGOVERN_ENV_FILE_PATH='${WPGOVERN_ENV_FILE_PATH}'
        export WPGOVERN_DB_ROOT_PASSWORD='SENTINEL_ROOT_PW_sentineltest'
        export WPGOVERN_DB_WP_PASSWORD='SENTINEL_WP_PW_sentineltest__x'
        export WPGOVERN_DB_BACKUP_PASSWORD='SENTINEL_BACKUP_PW_sentineltest'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        wpgovern::state::init
        wpgovern::state::set_fact 'bootstrap.env_file_path' '${WPGOVERN_ENV_FILE_PATH}'
        source '${STACK_DIR}/credentials.sh'
        source '${DB_DIR}/credentials.sh'
        wpgovern::db::credentials::generate_age_key 2>&1
        wpgovern::db::credentials::encrypt_state 2>&1
    " 2>&1

    for sentinel in "SENTINEL_ROOT_PW_sentineltest" "SENTINEL_WP_PW_sentineltest__x" "SENTINEL_BACKUP_PW_sentineltest"; do
        echo "$output" | grep -q "$sentinel" && {
            echo "CREDENTIAL LEAK: $sentinel found in combined output"; return 1
        }
    done

    # Also check the log file
    for sentinel in "SENTINEL_ROOT_PW_sentineltest" "SENTINEL_WP_PW_sentineltest__x" "SENTINEL_BACKUP_PW_sentineltest"; do
        grep -q "$sentinel" "${TEST_TMPDIR}/logs/wpgovern-installer.log" 2>/dev/null && {
            echo "CREDENTIAL LEAK: $sentinel found in log file"; return 1
        } || true
    done
    return 0
}
