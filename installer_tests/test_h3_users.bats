#!/usr/bin/env bats
# =============================================================================
# test_h3_users.bats — users.sh behavioral tests
#
# Mocked mariadb via witness file captures exact SQL invocations.
# Credentials discipline: sentinel-grep confirms no passwords in output.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
DB_DIR="${BATS_TEST_DIRNAME}/../modules/db"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    WITNESS_FILE="${TEST_TMPDIR}/mariadb_calls.txt"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"
    : > "$WITNESS_FILE"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DB_ROOT_PASSWORD="SENTINEL_ROOT_PW_h3users"
    export WPGOVERN_DB_BACKUP_PASSWORD="SENTINEL_BACKUP_PW_h3users"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init
    source "${DB_DIR}/users.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

_make_user_mock() {
    local wpuser_exists="${1}"    # 1 = exists, "" = missing (no default — caller must be explicit)
    local wpbackup_exists="${2}"  # 1 = exists, "" = missing

    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
# Write all arguments to witness file (redirection removed in caller)
echo "\$@" >> "${WITNESS_FILE}"

if [[ "\$1 \$2" == "compose exec" ]]; then
    shift 2
    # Find SQL in args
    for arg in "\$@"; do
        if [[ "\$arg" == *"User = 'wpuser'"* ]]; then
            echo "${wpuser_exists}"
            exit 0
        fi
        if [[ "\$arg" == *"User = 'wpbackup'"* ]]; then
            echo "${wpbackup_exists}"
            exit 0
        fi
        if [[ "\$arg" == *"CREATE USER 'wpbackup'"* ]]; then
            exit 0
        fi
    done
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
}

@test "H.3-3: application user verification succeeds when user exists" {
    _make_user_mock "1" ""
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::verify_application_user
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local verified_at
    verified_at="$(jq -r '.host_facts["db.users.app_user_verified_at"]' "$WPGOVERN_STATE_FILE")"
    [[ -n "$verified_at" ]] || { echo "app_user_verified_at not set"; return 1; }
}

@test "H.3-3: application user missing fails with mark_phase_failed" {
    _make_user_mock "" ""    # wpuser returns empty (doesn't exist)

    # Write a script file — avoids bats run -c quirks with function exit codes
    local script="${TEST_TMPDIR}/run_verify.sh"
    cat > "$script" << SCRIPT
#!/usr/bin/env bash
set -euo pipefail
export PATH="${MOCK_BIN}:${PATH}"
export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
export WPGOVERN_DB_ROOT_PASSWORD="SENTINEL_ROOT_PW_h3users"
source "${CORE_DIR}/bootstrap.sh"
source "${CORE_DIR}/state.sh"
wpgovern::state::init
source "${DB_DIR}/users.sh"
wpgovern::db::users::verify_application_user
SCRIPT
    chmod +x "$script"

    run bash "$script"
    [[ "$status" -ne 0 ]] || { echo "Expected non-zero; got 0. Output: $output"; return 1; }

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "wpuser missing" ]] || {
        echo "Expected wpuser-missing reason, got: $reason"; return 1
    }
}

@test "H.3-3: backup user creation issues correct SQL (CREATE + GRANT + FLUSH)" {
    # Mock where wpbackup doesn't exist yet
    _make_user_mock "1" ""
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::create_backup_user
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    # Inspect witness file for the SQL content
    local witness_content
    witness_content="$(cat "$WITNESS_FILE")"

    echo "$witness_content" | grep -q "CREATE USER 'wpbackup'" || {
        echo "Missing CREATE USER in SQL. Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "GRANT REPLICATION CLIENT" || {
        echo "Missing GRANT REPLICATION CLIENT. Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "SELECT" || {
        echo "Missing SELECT privilege. Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "LOCK TABLES" || {
        echo "Missing LOCK TABLES privilege. Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "PROCESS" || {
        echo "Missing PROCESS privilege. Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "FLUSH PRIVILEGES" || {
        echo "Missing FLUSH PRIVILEGES. Witness: $witness_content"; return 1
    }
}

@test "H.3-3: backup user already exists is idempotent (no CREATE issued)" {
    _make_user_mock "1" "1"    # wpbackup already exists
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::create_backup_user
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$output" =~ "already exists" ]]

    # CREATE USER must NOT appear in witness (no re-creation attempted)
    grep -q "CREATE USER" "$WITNESS_FILE" && {
        echo "CREATE USER was issued despite user existing"; return 1
    } || true
}

@test "H.3-3: sentinel credentials never appear in users.sh output" {
    _make_user_mock "1" ""
    PATH="${MOCK_BIN}:${PATH}"

    run bash -c "
        export PATH='${MOCK_BIN}:${PATH}'
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
        export WPGOVERN_DB_ROOT_PASSWORD='SENTINEL_ROOT_PW_h3users'
        export WPGOVERN_DB_BACKUP_PASSWORD='SENTINEL_BACKUP_PW_h3users'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        wpgovern::state::init
        source '${DB_DIR}/users.sh'
        wpgovern::db::users::verify_application_user 2>&1
        wpgovern::db::users::create_backup_user 2>&1
    " 2>&1

    for sentinel in "SENTINEL_ROOT_PW_h3users" "SENTINEL_BACKUP_PW_h3users"; do
        echo "$output" | grep -q "$sentinel" && {
            echo "CREDENTIAL LEAK: $sentinel in output"; return 1
        }
    done

    grep -rq "SENTINEL_ROOT_PW_h3users\|SENTINEL_BACKUP_PW_h3users" \
        "${TEST_TMPDIR}/logs/wpgovern-installer.log" 2>/dev/null && {
        echo "CREDENTIAL LEAK found in log file"; return 1
    } || return 0
}
