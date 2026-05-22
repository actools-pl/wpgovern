#!/usr/bin/env bats
# =============================================================================
# test_h4_provision.bats — WordPress provision via wp-cli tests
# =============================================================================

CORE_DIR="${BATS_TEST_DIRNAME}/../core"
WP_DIR="${BATS_TEST_DIRNAME}/../modules/wp"

setup() {
    TEST_TMPDIR="$(mktemp -d)"
    MOCK_BIN="${TEST_TMPDIR}/mock_bin"
    WITNESS_FILE="${TEST_TMPDIR}/wp_calls.txt"
    mkdir -p "${TEST_TMPDIR}/install" "${TEST_TMPDIR}/logs" "$MOCK_BIN"
    : > "$WITNESS_FILE"

    export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
    export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
    export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
    export WPGOVERN_DOMAIN="test.example.com"
    export WPGOVERN_WP_ADMIN_USER="admin"
    export WPGOVERN_WP_ADMIN_PASSWORD="SENTINEL_ADMIN_PW_h4prov"
    export WPGOVERN_WP_ADMIN_EMAIL="admin@example.com"
    export WPGOVERN_WP_SITE_TITLE="Test Site"

    source "${CORE_DIR}/bootstrap.sh"
    source "${CORE_DIR}/state.sh"
    source "${CORE_DIR}/credentials.sh"
    wpgovern::state::init
    source "${WP_DIR}/provision.sh"
}

teardown() { rm -rf "$TEST_TMPDIR"; }

_make_wpcli_mock() {
    local is_installed_exit="${1:-1}"   # 1=not installed, 0=installed
    local install_exit="${2:-0}"

    cat > "${MOCK_BIN}/docker" << MOCK
#!/usr/bin/env bash
echo "\$@" >> "${WITNESS_FILE}"
if [[ "\$1" == "compose" ]]; then
    shift
    # --profile cli run --rm cli wp core is-installed
    if [[ "\$@" == *"core is-installed"* ]]; then exit ${is_installed_exit}; fi
    # wp core install
    if [[ "\$@" == *"core install"* ]]; then exit ${install_exit}; fi
fi
exit 0
MOCK
    chmod +x "${MOCK_BIN}/docker"
}

@test "H.4-2: WordPress not installed → wp core install invoked" {
    _make_wpcli_mock 1 0  # not installed, install succeeds
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::wp::provision
    [[ "$status" -eq 0 ]] || { echo "FAILED: $output"; return 1; }

    grep -q "core install" "$WITNESS_FILE" || {
        echo "wp core install was not invoked"; return 1
    }
}

@test "H.4-2: WordPress already installed → idempotent skip (no core install)" {
    _make_wpcli_mock 0 0  # already installed
    PATH="${MOCK_BIN}:${PATH}"

    run wpgovern::wp::provision
    [[ "$status" -eq 0 ]]
    [[ "$output" =~ "already installed" ]]

    grep -q "core install" "$WITNESS_FILE" && {
        echo "core install was called despite WP being installed"; return 1
    } || true
}

@test "H.4-2: missing required env var fails with clear reason" {
    _make_wpcli_mock 1 0
    PATH="${MOCK_BIN}:${PATH}"
    unset WPGOVERN_WP_ADMIN_PASSWORD

    run wpgovern::wp::provision
    [[ "$status" -ne 0 ]]
    local reason; reason="$(jq -r '.phases_failed[0].reason' "$WPGOVERN_STATE_FILE")"
    [[ "$reason" =~ "provision" ]] || { echo "Expected provision reason, got: $reason"; return 1; }
}

@test "H.4-2: wp core install includes --skip-email flag" {
    _make_wpcli_mock 1 0
    PATH="${MOCK_BIN}:${PATH}"

    wpgovern::wp::provision

    grep -q "skip-email" "$WITNESS_FILE" || {
        echo "--skip-email not found in wp-cli invocation"; return 1
    }
}

@test "H.4-2: sentinel admin password never appears in output or log" {
    _make_wpcli_mock 1 0

    local runner="${TEST_TMPDIR}/prov_runner.sh"
    cat > "$runner" << SCRIPT
#!/usr/bin/env bash
export PATH="${MOCK_BIN}:/usr/bin:/bin"
export WPGOVERN_INSTALL_DIR="${TEST_TMPDIR}/install"
export WPGOVERN_LOG_DIR="${TEST_TMPDIR}/logs"
export WPGOVERN_STATE_FILE="${TEST_TMPDIR}/install/.state.json"
export WPGOVERN_DOMAIN="test.example.com"
export WPGOVERN_WP_ADMIN_USER="admin"
export WPGOVERN_WP_ADMIN_PASSWORD="SENTINEL_ADMIN_PW_h4prov"
export WPGOVERN_WP_ADMIN_EMAIL="admin@example.com"
source "${CORE_DIR}/bootstrap.sh"
source "${CORE_DIR}/state.sh"
source "${CORE_DIR}/credentials.sh"
wpgovern::state::init
source "${WP_DIR}/provision.sh"
wpgovern::wp::provision
SCRIPT
    chmod +x "$runner"
    run bash "$runner" 2>&1

    local sentinel="SENTINEL_ADMIN_PW_h4prov"
    if echo "$output" | grep -qF "$sentinel"; then
        echo "CREDENTIAL LEAK: admin password found in output"; return 1
    fi
    if grep -qF "$sentinel" "${TEST_TMPDIR}/logs/wpgovern-installer.log" 2>/dev/null; then
        echo "CREDENTIAL LEAK: admin password found in log file"; return 1
    fi
}
