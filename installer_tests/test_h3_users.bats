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
source "${CORE_DIR}/credentials.sh"
# Don't reinit state — existing state from setup() has phases structure
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

    local witness_content
    witness_content="$(cat "$WITNESS_FILE")"

    echo "$witness_content" | grep -q "CREATE USER 'wpbackup'" || {
        echo "Missing CREATE USER. Witness: $witness_content"; return 1
    }
    # H.3.1-4: split grants — operational on *.*, data on wordpress.*
    echo "$witness_content" | grep -q "GRANT REPLICATION CLIENT, PROCESS" || {
        echo "Missing split GRANT (operational). Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "GRANT SELECT, LOCK TABLES ON" || {
        echo "Missing split GRANT (data). Witness: $witness_content"; return 1
    }
    echo "$witness_content" | grep -q "FLUSH PRIVILEGES" || {
        echo "Missing FLUSH PRIVILEGES. Witness: $witness_content"; return 1
    }
    # H.3.1-4: SELECT/LOCK TABLES must NOT appear on *.* 
    echo "$witness_content" | grep -q "SELECT, LOCK TABLES ON \*\.\*" && {
        echo "SELECT/LOCK TABLES on *.* found — should be scoped to wordpress.*"; return 1
    } || true
}

@test "H.3-3: backup user already exists is idempotent (no CREATE issued)" {
    # Mock: wpbackup exists AND returns correct grants for _wpgovern_db_verify_backup_grants
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
echo "\$@" >> "${WITNESS_FILE}"
if [[ "\$1 \$2" == "compose exec" ]]; then
    for arg in "\$@"; do
        if [[ "\$arg" == *"User = 'wpbackup'"* ]]; then echo "1"; exit 0; fi
        if [[ "\$arg" == *"SHOW GRANTS"* ]]; then
            printf 'GRANT USAGE ON *.* TO \`wpbackup\`@\`%%\`\n'
            printf 'GRANT REPLICATION CLIENT, PROCESS ON *.* TO \`wpbackup\`@\`%%\`\n'
            printf 'GRANT SELECT, LOCK TABLES ON \`wordpress\`.* TO \`wpbackup\`@\`%%\`\n'
            exit 0
        fi
    done
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::create_backup_user
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }
    [[ "$output" =~ "correct grants" ]] || [[ "$output" =~ "already exists" ]]

    # CREATE USER must NOT appear in witness (no re-creation)
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
        source '${CORE_DIR}/credentials.sh'
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

# ---------------------------------------------------------------------------
# H.3.1-3 — Grant verification behavioral tests
# ---------------------------------------------------------------------------

@test "H.3.1-3: existing wpbackup with missing REPLICATION CLIENT fails verification" {
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
if [[ "\$1 \$2" == "compose exec" ]]; then
    for arg in "\$@"; do
        if [[ "\$arg" == *"User = 'wpbackup'"* ]]; then echo "1"; exit 0; fi
        if [[ "\$arg" == *"SHOW GRANTS"* ]]; then
            # Missing REPLICATION CLIENT
            printf 'GRANT SELECT, LOCK TABLES ON \`wordpress\`.* TO \`wpbackup\`@\`%%\`\n'
            exit 0
        fi
    done
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::create_backup_user
    [[ "$status" -ne 0 ]]
    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "incorrect grants" ]] || { echo "Expected incorrect-grants reason, got: $reason"; return 1; }
}

@test "H.3.1-3: existing wpbackup with forbidden SUPER privilege fails verification" {
    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
if [[ "\$1 \$2" == "compose exec" ]]; then
    for arg in "\$@"; do
        if [[ "\$arg" == *"User = 'wpbackup'"* ]]; then echo "1"; exit 0; fi
        if [[ "\$arg" == *"SHOW GRANTS"* ]]; then
            printf 'GRANT REPLICATION CLIENT, PROCESS ON *.* TO \`wpbackup\`@\`%%\`\n'
            printf 'GRANT SELECT, LOCK TABLES ON \`wordpress\`.* TO \`wpbackup\`@\`%%\`\n'
            printf 'GRANT SUPER ON *.* TO \`wpbackup\`@\`%%\`\n'
            exit 0
        fi
    done
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::create_backup_user
    [[ "$status" -ne 0 ]]
    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "incorrect grants" ]] || { echo "Expected incorrect-grants reason, got: $reason"; return 1; }
}

@test "H.3.1-4: backup user SQL uses split grants (operational *.* + data wordpress.*)" {
    # Verify split scope: REPLICATION CLIENT+PROCESS on *.*, SELECT+LOCK TABLES on wordpress.*
    _make_user_mock "1" ""  # wpbackup doesn't exist yet
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::users::create_backup_user
    [[ "$status" -eq 0 ]]

    local witness
    witness="$(cat "$WITNESS_FILE")"

    # Assert split grant structure
    echo "$witness" | grep -q "GRANT REPLICATION CLIENT, PROCESS ON \*\.\*" || {
        echo "Missing operational grant on *.*. Witness: $witness"; return 1
    }
    echo "$witness" | grep -q "GRANT SELECT, LOCK TABLES ON" || {
        echo "Missing data grant. Witness: $witness"; return 1
    }
    # Assert SELECT/LOCK TABLES NOT on *.*
    echo "$witness" | grep -q "SELECT, LOCK TABLES ON \*\.\*" && {
        echo "SELECT/LOCK TABLES incorrectly granted on *.* (should be wordpress.*)"; return 1
    } || true
}
