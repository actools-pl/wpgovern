#!/usr/bin/env bats
# =============================================================================
# test_h3_wait.bats — wait_for_ready behavioral tests
#
# All docker compose calls are mocked via PATH manipulation.
# Credentials discipline verified by sentinel-grep.
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
DB_DIR="${BATS_TEST_DIRNAME}/../modules/db"
REPO_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DB_ROOT_PASSWORD="SENTINEL_ROOT_PW_h3wait"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    wpgovern::state::init
    source "${DB_DIR}/wait.sh"
}

teardown() {
    rm -rf "$TEST_TMPDIR"
}

# Build mock docker-compose with configurable behavior
_make_docker_mock() {
    local ps_state="${1:-running}"      # container state
    local connect_exit="${2:-0}"        # exit code for SELECT 1
    local db_exists_exit="${3:-0}"      # exit code for USE wordpress
    local connect_delay="${4:-0}"       # seconds before connect succeeds
    local call_count_file="${TEST_TMPDIR}/connect_calls"
    echo "0" > "$call_count_file"

    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash

if [[ "\$1 \$2" == "compose ps" ]]; then
    echo '{"State":"${ps_state}"}'
    exit 0
fi

if [[ "\$1 \$2" == "compose exec" ]]; then
    shift 2  # remove "compose exec"
    # Find the -e argument to distinguish SELECT 1 from USE wordpress
    for arg in "\$@"; do
        if [[ "\$arg" == *"SELECT 1"* ]]; then
            count=\$(cat "${call_count_file}")
            count=\$((count + 1))
            echo "\$count" > "${call_count_file}"
            # delay: first N calls fail (simulate slow start)
            if [[ ${connect_delay} -gt 0 && \$count -le ${connect_delay} ]]; then
                exit 1
            fi
            exit ${connect_exit}
        fi
        if [[ "\$arg" == *"USE wordpress"* ]]; then
            exit ${db_exists_exit}
        fi
        if [[ "\$arg" == *"SELECT 1 FROM mysql"* ]]; then
            exit 0
        fi
    done
    exit 0
fi

exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
}

@test "H.3-1: container not running fails with clear reason in state" {
    _make_docker_mock "stopped" 0 0
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::wait_for_ready
    [[ "$status" -ne 0 ]]

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "container not running" ]] || {
        echo "Expected container-not-running reason, got: $reason"; return 1
    }
}

@test "H.3-1: timeout fails with timeout reason in state" {
    _make_docker_mock "running" 1 0  # connect always fails
    PATH="${MOCK_BIN}:${PATH}"

    # Override timeout to 1s so test finishes quickly
    run bash -c "
        export PATH='${MOCK_BIN}:${PATH}'
        export WPGOVERN_INSTALL_DIR='${TEST_TMPDIR}/install'
        export WPGOVERN_LOG_DIR='${TEST_TMPDIR}/logs'
        export WPGOVERN_STATE_FILE='${TEST_TMPDIR}/install/.state.json'
        export WPGOVERN_DB_ROOT_PASSWORD='SENTINEL_ROOT_PW_h3wait'
        source '${CORE_DIR}/bootstrap.sh'
        source '${CORE_DIR}/state.sh'
        wpgovern::state::init
        source '${DB_DIR}/wait.sh'
        # Patch timeout to 1 for test speed
        wpgovern::db::wait_for_ready_fast() {
            local timeout=1; local elapsed=0; local interval=1
            local container_state
            container_state=\"\$(docker compose ps mariadb --format json 2>/dev/null | jq -r '.State // empty' || true)\"
            [[ \"\$container_state\" == 'running' ]] || { wpgovern::state::mark_phase_failed 'db' 'wait_for_ready: container not running'; return 1; }
            while [[ \$elapsed -lt \$timeout ]]; do
                if docker compose exec -T mariadb mariadb -uroot -p\"\${WPGOVERN_DB_ROOT_PASSWORD}\" -e \"SELECT 1\" >/dev/null 2>&1; then break; fi
                sleep \$interval; elapsed=\$((elapsed + interval))
            done
            if [[ \$elapsed -ge \$timeout ]]; then
                wpgovern::state::mark_phase_failed 'db' \"wait_for_ready: timeout after \${timeout}s\"
                return 1
            fi
        }
        wpgovern::db::wait_for_ready_fast
    "
    [[ "$status" -ne 0 ]]

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "timeout" ]] || { echo "Expected timeout reason, got: $reason"; return 1; }
}

@test "H.3-1: wordpress database missing fails clearly" {
    _make_docker_mock "running" 0 1  # connect succeeds, USE wordpress fails
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::wait_for_ready
    [[ "$status" -ne 0 ]]

    local reason
    reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "wordpress database missing" ]] || {
        echo "Expected db-missing reason, got: $reason"; return 1
    }
}

@test "H.3-1: ready DB completes with elapsed_seconds recorded in state" {
    _make_docker_mock "running" 0 0  # all succeeds immediately
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::db::wait_for_ready
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    local elapsed
    elapsed="$(jq -r '."host_facts"["db.wait_for_ready.elapsed_seconds"]' "$WPGOVERN_STATE_FILE")"
    [[ -n "$elapsed" ]] || { echo "elapsed_seconds not recorded"; return 1; }
}

@test "H.3-1: sentinel password never appears in wait_for_ready output" {
    _make_docker_mock "running" 0 0
    PATH="${MOCK_BIN}:${PATH}"

    # Capture all output
    run wpgovern::db::wait_for_ready
    # The sentinel password must never appear in logs or output
    echo "$output" | grep -q "SENTINEL_ROOT_PW_h3wait" && {
        echo "CREDENTIAL LEAK: password found in output"; return 1
    }
    # Also check the log file
    grep -q "SENTINEL_ROOT_PW_h3wait" "${TEST_TMPDIR}/logs/wpgovern-installer.log" && {
        echo "CREDENTIAL LEAK: password found in log file"; return 1
    } || true
    return 0
}
