#!/usr/bin/env bats
# =============================================================================
# test_h3_ci_credentials.bats — CI guard: credentials never logged
#
# H.3-11: the defining test of the credentials-not-in-logs discipline.
# Runs ALL H.3 module functions with sentinel passwords and greps the
# combined stdout+stderr+log for any sentinel value.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
STACK_DIR="${BATS_TEST_DIRNAME}/../modules/stack"
DB_DIR="${BATS_TEST_DIRNAME}/../modules/db"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    # Highly distinctive sentinel values — would be immediately obvious if logged
    export SENTINEL_ROOT="CIGUARD_ROOT_PW_h3sentinel_AAAA"
    export SENTINEL_WP="CIGUARD_WP_PW_h3sentinel_BBBB__"
    export SENTINEL_BACKUP="CIGUARD_BACKUP_PW_h3sentinel_CC"

    cat > "${TEST_TMPDIR}/wpgovern.env" << ENV
WPGOVERN_OPERATOR_EMAIL=ci@example.com
WPGOVERN_INSTALL_DIR=${TEST_TMPDIR}/install
WPGOVERN_DOMAIN=test.example.com
ENV

    # Mock docker for db module calls
    cat > "${MOCK_BIN}/docker" << 'MOCK'
#!/usr/bin/env bash
if [[ "$1 $2" == "compose ps" ]]; then echo '{"State":"running"}'; exit 0; fi
if [[ "$1 $2" == "compose exec" ]]; then
    for arg in "$@"; do
        if [[ "$arg" == *"SELECT 1 FROM mysql.user WHERE User = 'wpuser'"* ]]; then echo "1"; exit 0; fi
        if [[ "$arg" == *"SELECT 1 FROM mysql.user WHERE User = 'wpbackup'"* ]]; then exit 0; fi
        if [[ "$arg" == *"SELECT 1"* ]]; then exit 0; fi
        if [[ "$arg" == *"USE wordpress"* ]]; then exit 0; fi
        if [[ "$arg" == *"CREATE USER"* ]]; then exit 0; fi
    done
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

@test "H.3 CI: no DB password values appear in any output across full db phase" {
    local age_available=false
    command -v age-keygen >/dev/null 2>&1 && command -v age >/dev/null 2>&1 && age_available=true

    # Run all H.3 functions and capture every byte of stdout+stderr
    local combined_output
    combined_output="$(bash -c "
        export PATH='${MOCK_BIN}:${PATH}'
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
        export WPGOVERN_ENV_FILE_PATH='${TEST_TMPDIR}/wpgovern.env'
        export WPGOVERN_DB_ROOT_PASSWORD='${SENTINEL_ROOT}'
        export WPGOVERN_DB_WP_PASSWORD='${SENTINEL_WP}'
        export WPGOVERN_DB_BACKUP_PASSWORD='${SENTINEL_BACKUP}'

        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        wpgovern::state::init
        wpgovern::state::set_fact 'bootstrap.env_file_path' '${TEST_TMPDIR}/wpgovern.env'

        source '${STACK_DIR}/credentials.sh'
        source '${DB_DIR}/wait.sh'
        source '${DB_DIR}/credentials.sh'
        source '${DB_DIR}/users.sh'

        # Run wait
        wpgovern::db::wait_for_ready 2>&1 || true

        # Run credentials (age only if available)
        if command -v age-keygen >/dev/null 2>&1 && command -v age >/dev/null 2>&1; then
            wpgovern::db::credentials::generate_age_key 2>&1 || true
            wpgovern::db::credentials::encrypt_state 2>&1 || true
        fi

        # Run users
        wpgovern::db::users::verify_application_user 2>&1 || true
        wpgovern::db::users::create_backup_user 2>&1 || true
    " 2>&1)"

    # Also capture log file content
    local log_content=""
    [[ -f "${TEST_TMPDIR}/logs/wpgovern-installer.log" ]] && \
        log_content="$(cat "${TEST_TMPDIR}/logs/wpgovern-installer.log")"

    local all_output="${combined_output}${log_content}"

    # Assert: none of the three sentinel values appear anywhere
    local leak_found=false
    for sentinel in "$SENTINEL_ROOT" "$SENTINEL_WP" "$SENTINEL_BACKUP"; do
        if echo "$all_output" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK: sentinel '$sentinel' found in output or log"
            leak_found=true
        fi
    done

    [[ "$leak_found" == "false" ]] || {
        echo "--- LEAKED OUTPUT (first 50 lines) ---"
        echo "$all_output" | head -50
        return 1
    }
}

@test "H.3 CI: wait_for_ready uses >/dev/null 2>&1 on every mariadb call" {
    # Structural check: every docker compose exec block in wait.sh that
    # references the root password must be followed by output suppression.
    # Count exec blocks vs redirection blocks to detect any unguarded invocation.
    local wait_file="${DB_DIR}/wait.sh"
    local exec_count redir_count
    exec_count="$(grep -c 'exec -T mariadb mariadb' "$wait_file" || echo 0)"
    redir_count="$(grep -c '>/dev/null 2>&1' "$wait_file" || echo 0)"
    [[ "$exec_count" -le "$redir_count" ]] || {
        echo "Found $exec_count mariadb exec calls but only $redir_count >/dev/null 2>&1 redirections"
        return 1
    }
}

@test "H.3 CI: users.sh uses >/dev/null 2>&1 on every mariadb call" {
    local users_file="${DB_DIR}/users.sh"
    local exec_count redir_count
    exec_count="$(grep -c 'exec -T mariadb mariadb' "$users_file" || echo 0)"
    # Accept both >/dev/null 2>&1 (full suppression) and 2>/dev/null (stderr-only for captured output)
    redir_count="$(grep -cE '>/dev/null 2>&1|2>/dev/null' "$users_file" || echo 0)"
    [[ "$exec_count" -le "$redir_count" ]] || {
        echo "Found $exec_count mariadb exec calls but only $redir_count output suppressions"
        return 1
    }
}

@test "H.3.1-6: CI sentinel scan — success path (all functions must return 0)" {
    command -v age-keygen >/dev/null 2>&1 && command -v age >/dev/null 2>&1 || {
        skip "age/age-keygen not installed"
    }

    # H.3.1.1: write to runner script — `run | tee` pipe breaks $status capture in bats
    local runner_script="${TEST_TMPDIR}/runner_success.sh"
    cat > "$runner_script" << SCRIPT
#!/usr/bin/env bash
set -euo pipefail
export PATH='${MOCK_BIN}:${PATH}'
export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
export WPGOVERN_ENV_FILE_PATH='${TEST_TMPDIR}/wpgovern.env'
export WPGOVERN_DB_ROOT_PASSWORD='${SENTINEL_ROOT}'
export WPGOVERN_DB_WP_PASSWORD='${SENTINEL_WP}'
export WPGOVERN_DB_BACKUP_PASSWORD='${SENTINEL_BACKUP}'

source '${CORE_DIR}/bootstrap.sh'
source '${CORE_DIR}/state.sh'
source '${CORE_DIR}/credentials.sh'
wpgovern::state::init
wpgovern::state::set_fact 'bootstrap.env_file_path' '${TEST_TMPDIR}/wpgovern.env'

source '${DB_DIR}/wait.sh'
wpgovern::db::wait_for_ready

source '${STACK_DIR}/credentials.sh'
source '${DB_DIR}/credentials.sh'
wpgovern::db::credentials::ensure_backup_password
wpgovern::db::credentials::generate_age_key
wpgovern::db::credentials::encrypt_state

source '${DB_DIR}/users.sh'
wpgovern::db::users::verify_application_user
wpgovern::db::users::create_backup_user
SCRIPT
    chmod +x "$runner_script"

    run bash "$runner_script" 2>&1
    echo "$output" > "${TEST_TMPDIR}/combined_output.txt"

    [[ "$status" -eq 0 ]] || {
        echo "One or more db phase functions returned non-zero (H.3.1-6 success-path violation)"
        echo "Exit status: $status"
        echo "Output: $output"
        return 1
    }

    # Sentinel scan: use $output from run (captures both stdout and stderr of runner script)
    # Also check the log file the runner wrote to
    local log_content=""
    [[ -f "${TEST_TMPDIR}/logs/wpgovern-installer.log" ]] && \
        log_content="$(cat "${TEST_TMPDIR}/logs/wpgovern-installer.log")"
    local combined="${output}"$'\n'"${log_content}"

    for sentinel in "$SENTINEL_ROOT" "$SENTINEL_WP" "$SENTINEL_BACKUP"; do
        if echo "$combined" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK on SUCCESS path: '$sentinel' found"
            echo "--- in output ---"
            echo "$output" | grep -F "$sentinel" | head -3
            echo "--- in log ---"
            echo "$log_content" | grep -F "$sentinel" | head -3
            return 1
        fi
    done
}

@test "H.3.1-6: CI sentinel scan — failure path (encrypt fails, no credential leak)" {
    command -v age-keygen >/dev/null 2>&1 || skip "age-keygen not installed"

    local sent_r="FAILPATH_ROOT_SENTINEL_H316"
    local sent_w="FAILPATH_WP_SENTINEL_H316__"
    local sent_b="FAILPATH_BKP_SENTINEL_H316_"

    # H.3.1.1: runner script — state setup + corrupt key + encrypt all inside the subprocess
    local runner_fail="${TEST_TMPDIR}/runner_fail.sh"
    cat > "$runner_fail" << SCRIPT
#!/usr/bin/env bash
set -euo pipefail
export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
export WPGOVERN_DB_ROOT_PASSWORD='${sent_r}'
export WPGOVERN_DB_WP_PASSWORD='${sent_w}'
export WPGOVERN_DB_BACKUP_PASSWORD='${sent_b}'
mkdir -p '${TEST_TMPDIR}/install' '${TEST_TMPDIR}/logs'
source '${CORE_DIR}/bootstrap.sh'
source '${CORE_DIR}/state.sh'
source '${CORE_DIR}/credentials.sh'
wpgovern::state::init
# Create corrupt key without using 'local' at top level
_corrupt_key_path='${TEST_TMPDIR}/install/.wpgovern-age.key'
echo '# corrupt key' > "\$_corrupt_key_path"
chmod 600 "\$_corrupt_key_path"
wpgovern::state::set_fact 'db.credentials.age_key_path' "\$_corrupt_key_path"
source '${DB_DIR}/credentials.sh'
wpgovern::db::credentials::encrypt_state
SCRIPT
    chmod +x "$runner_fail"

    run bash "$runner_fail" 2>&1

    [[ "$status" -ne 0 ]] || { echo "Expected failure, got 0"; return 1; }

    for sentinel in "$sent_r" "$sent_w" "$sent_b"; do
        if echo "$output" | grep -qF "$sentinel"; then
            echo "CREDENTIAL LEAK on FAILURE path: '$sentinel' found"
            return 1
        fi
    done
}
